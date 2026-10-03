"""Post-apply target health verification.

A successful `terraform apply` proves the API accepted the change, not that the
workload is healthy. After execute, `verify()` observes what the change touched
for a bounded time and returns structured evidence. Anything not observed
healthy inside the window (unhealthy, unreachable, still pending) fails
verification, so the run is recorded FAILED and blocks the target like any
failed apply.

Two kinds of item are observed, both opt-in through a target's `verify` table:

* `nomad = true`: every `nomad_job` the applied plan created, updated or
  deleted. Service and system jobs must reach a successful deployment (or,
  without one, enough running allocations of the current version). Periodic
  jobs must be registered with launches enabled; `periodic = "launch"` also
  forces one launch and requires it to complete. Other batch and
  parameterized jobs must be registered. Deleted jobs must be gone or stopped.
* `[[...verify.check]]`: argv commands run in the target directory with the
  apply env, retried until they exit 0 or the window closes.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any, Callable

EVIDENCE_VERSION = 1
DETAIL_MAX = 500
HTTP_TIMEOUT = 10

HEALTHY, UNHEALTHY, PENDING, TIMEOUT = "healthy", "unhealthy", "pending", "timeout"


class NomadError(Exception):
    """The Nomad API could not answer (unreachable, denied, malformed)."""


def _clip(text: str) -> str:
    text = (text or "").strip()
    return text if len(text) <= DETAIL_MAX else "..." + text[-(DETAIL_MAX - 3):]


def nomad_api(addr: str, token: str = "", *, deadline: float | None = None,
              clock: Callable[[], float] = time.monotonic) -> Callable[..., Any]:
    """`api(method, path, params)` -> decoded JSON, or None for a 404."""
    base = addr if "://" in addr else f"http://{addr}"
    base = base.rstrip("/")

    def call(method: str, path: str, params: dict | None = None) -> Any:
        query = {k: v for k, v in (params or {}).items() if v}
        url = base + path + (f"?{urllib.parse.urlencode(query)}" if query else "")
        req = urllib.request.Request(url, method=method, data=b"{}" if method != "GET" else None)
        if token:
            req.add_header("X-Nomad-Token", token)
        try:
            remaining = HTTP_TIMEOUT if deadline is None else min(HTTP_TIMEOUT, deadline - clock())
            if remaining <= 0:
                raise NomadError("verification deadline reached")
            with urllib.request.urlopen(req, timeout=remaining) as resp:
                body = resp.read()
        except urllib.error.HTTPError as e:
            e.close()
            if e.code == 404:
                return None
            raise NomadError(f"HTTP {e.code} from {method} {path}") from None
        except (urllib.error.URLError, OSError) as e:
            raise NomadError(f"{method} {path}: {getattr(e, 'reason', e)}") from None
        try:
            return json.loads(body or b"null")
        except ValueError:
            raise NomadError(f"{method} {path}: response is not JSON") from None

    return call


def nomad_jobs(plan: dict | None) -> list[dict]:
    """The Nomad jobs an applied plan created, updated or deleted."""
    jobs = []
    for rc in (plan or {}).get("resource_changes") or []:
        if rc.get("type") != "nomad_job" or rc.get("mode", "managed") != "managed":
            continue
        change = rc.get("change") or {}
        actions = change.get("actions") or []
        if not actions or set(actions) <= {"no-op", "read"}:
            continue
        removed = actions == ["delete"]
        values = (change.get("before") if removed else change.get("after")) or {}
        jobs.append({
            "address": rc.get("address", ""),
            "id": values.get("name") if isinstance(values.get("name"), str) else None,
            "namespace": values.get("namespace") or "default",
            "region": values.get("region") or "",
            "removed": removed,
        })
    return jobs


class _Item:
    state = PENDING
    detail = ""
    polls = 0

    def evidence(self) -> dict:
        raise NotImplementedError


class NomadJob(_Item):
    def __init__(self, job: dict, periodic: str) -> None:
        self.job = job
        self.periodic = periodic
        self.policy = "removed" if job["removed"] else ""
        self.baseline: set[str] | None = None
        self.child = ""
        self.observed: dict[str, Any] = {}

    def _params(self, **extra: str) -> dict:
        return {"namespace": self.job["namespace"], "region": self.job["region"], **extra}

    def _path(self, *parts: str) -> str:
        return "/v1/" + "/".join(urllib.parse.quote(p, safe="") for p in parts)

    def step(self, api: Callable[..., Any]) -> tuple[str, str]:
        jid = self.job["id"]
        if not jid:
            return UNHEALTHY, "job ID is unknown in the applied plan; cannot observe it"
        live = api("GET", self._path("job", jid), self._params())
        if self.job["removed"]:
            if live is None or live.get("Stop"):
                return HEALTHY, "removed" if live is None else "stopped"
            return PENDING, "still registered and not stopped"
        if live is None:
            return PENDING, "not registered"
        if live.get("Stop"):
            return UNHEALTHY, "job is stopped"
        jtype = live.get("Type") or ""
        periodic = live.get("Periodic") or None
        self.observed.update(type=jtype, version=live.get("Version"), status=live.get("Status"))
        if live.get("ParameterizedJob"):
            self.policy = "parameterized"
            return HEALTHY, "registered (parameterized)"
        if periodic:
            self.policy = f"periodic-{self.periodic}"
            if not periodic.get("Enabled", True):
                return UNHEALTHY, "periodic launches are disabled"
            if self.periodic != "launch":
                return HEALTHY, f"registered, periodic launches enabled ({periodic.get('Spec', '')})"
            return self._launch(api, jid)
        if jtype == "batch":
            self.policy = "batch"
            return HEALTHY, "registered (batch)"
        self.policy = jtype or "service"
        return self._service(api, jid, live)

    def _children(self, api: Callable[..., Any], jid: str) -> list[dict]:
        rows = api("GET", "/v1/jobs", self._params(prefix=f"{jid}/periodic-")) or []
        return [r for r in rows if r.get("ParentID") == jid]

    def _launch(self, api: Callable[..., Any], jid: str) -> tuple[str, str]:
        if self.baseline is None:
            baseline = {r.get("ID", "") for r in self._children(api, jid)}
            api("POST", self._path("job", jid, "periodic", "force"), self._params())
            self.baseline = baseline
            return PENDING, "forced launch requested"
        if not self.child:
            new = [r for r in self._children(api, jid) if r.get("ID") not in self.baseline]
            if not new:
                return PENDING, "waiting for the forced launch to create a child job"
            self.child = max(new, key=lambda r: r.get("SubmitTime") or 0)["ID"]
            self.observed["launched"] = self.child
        child = api("GET", self._path("job", self.child), self._params())
        if child is None:
            return UNHEALTHY, f"launched job {self.child} disappeared"
        if child.get("Status") != "dead":
            return PENDING, f"launched job {self.child} is {child.get('Status')}"
        allocs = api("GET", self._path("job", self.child, "allocations"), self._params()) or []
        statuses = Counter(a.get("ClientStatus", "") for a in allocs)
        self.observed["launch_allocations"] = dict(statuses)
        if allocs and set(statuses) == {"complete"}:
            return HEALTHY, f"launched job {self.child} completed ({len(allocs)} allocation(s))"
        return UNHEALTHY, f"launched job {self.child} finished without completing: {dict(statuses) or 'no allocations'}"

    def _service(self, api: Callable[..., Any], jid: str, live: dict) -> tuple[str, str]:
        version = live.get("Version")
        dep = api("GET", self._path("job", jid, "deployment"), self._params())
        if dep and dep.get("JobVersion") == version:
            status = dep.get("Status")
            self.observed["deployment"] = {"id": str(dep.get("ID", ""))[:8], "status": status}
            if status == "successful":
                return HEALTHY, f"deployment {str(dep.get('ID', ''))[:8]} successful"
            if status in ("failed", "cancelled"):
                return UNHEALTHY, f"deployment {status}: {dep.get('StatusDescription', '')}"
            return PENDING, f"deployment {status}: {dep.get('StatusDescription', '')}"
        allocs = api("GET", self._path("job", jid, "allocations"), self._params()) or []
        current = [a for a in allocs if a.get("JobVersion") == version and a.get("DesiredStatus") == "run"]
        running = [a for a in current if a.get("ClientStatus") == "running"
                   and (a.get("DeploymentStatus") or {}).get("Healthy") is not False]
        failed = [a for a in current if a.get("ClientStatus") in ("failed", "lost")]
        groups = live.get("TaskGroups") or []
        coverage = {}
        for group in groups:
            name = group.get("Name", "")
            have = sum(a.get("TaskGroup") == name for a in running)
            want = int(group.get("Count") or 0)
            coverage[name] = {"running": have, "wanted": want}
        if live.get("Type") == "system":
            # System placement is determined by the scheduler rather than Count.
            summary = api("GET", self._path("job", jid, "summary"), self._params()) or {}
            reported = summary.get("Summary") or {}
            for name, group in coverage.items():
                row = reported.get(name)
                if row is None or row.get("Queued", 0) or row.get("Starting", 0):
                    return PENDING, f"system placement for {name} is not complete"
                group["wanted"] = max(1, int(row.get("Running") or 0))
        self.observed["allocations"] = {"groups": coverage, "failed": len(failed)}
        detail = "; ".join(f"{name}: {g['running']}/{g['wanted']} allocation(s) running"
                           for name, g in coverage.items())
        complete = bool(coverage) and all(g["running"] >= g["wanted"] for g in coverage.values())
        return (HEALTHY if complete else PENDING), detail

    def evidence(self) -> dict:
        return {"kind": "nomad_job", "id": self.job["id"], "namespace": self.job["namespace"],
                "address": self.job["address"], "policy": self.policy or "unobserved",
                "state": self.state, "detail": _clip(self.detail), "polls": self.polls,
                "observed": self.observed}


class Check(_Item):
    def __init__(self, check: Any, cwd: Path, env: dict[str, str]) -> None:
        self.check = check
        self.cwd = cwd
        self.env = env
        self.exit: int | None = None

    def step(self, remaining: float) -> tuple[str, str]:
        limit = min(float(self.check.timeout or remaining), remaining)
        if limit <= 0:
            return PENDING, "verification deadline reached"
        env = {**os.environ, **self.env}
        try:
            proc = subprocess.Popen(self.check.run, cwd=self.cwd, env=env, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                    errors="replace", start_new_session=True)
        except OSError as e:
            self.exit = 127
            return UNHEALTHY, f"could not run: {e.strerror or e}"
        try:
            out, _ = proc.communicate(timeout=limit)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            out, _ = proc.communicate()
            self.exit = 124
            return PENDING, f"{_clip(out)}\ncheck timed out after {limit:.0f}s".strip()
        self.exit = proc.returncode
        return (HEALTHY if proc.returncode == 0 else PENDING), _clip(out)

    def evidence(self) -> dict:
        return {"kind": "check", "name": self.check.name, "state": self.state,
                "detail": self.detail, "attempts": self.polls, "exit": self.exit}


def verify(policy: Any, *, plan: dict | None, cwd: Path, env: dict[str, str],
           api: Callable[..., Any] | None = None,
           clock: Callable[[], float] = time.monotonic,
           sleep: Callable[[float], None] = time.sleep) -> tuple[bool, str, dict]:
    """Observe until every item is healthy, one is unhealthy, or the window closes.

    Returns (ok, one-line reason, evidence). Never raises for target trouble:
    an unreachable API is an item that stays pending until the deadline.
    """
    start = clock()
    deadline = start + policy.timeout
    items: list[_Item] = []
    if policy.nomad:
        if plan is None:
            missing = NomadJob({"address": "", "id": None, "namespace": "", "region": "", "removed": False},
                               policy.periodic)
            missing.state, missing.detail = UNHEALTHY, "no applied plan to derive Nomad jobs from"
            items.append(missing)
        else:
            items += [NomadJob(j, policy.periodic) for j in nomad_jobs(plan)]
        addr = policy.nomad_addr or env.get("NOMAD_ADDR", "")
        if api is None and addr:
            api = nomad_api(addr, env.get("NOMAD_TOKEN", ""), deadline=deadline, clock=clock)
    items += [Check(c, cwd, env) for c in policy.checks]

    while True:
        for item in items:
            if item.state != PENDING:
                continue
            if clock() >= deadline:
                break
            item.polls += 1
            try:
                if isinstance(item, NomadJob):
                    if api is None:
                        item.state, item.detail = UNHEALTHY, "no Nomad address (set verify.nomad_addr or NOMAD_ADDR)"
                        continue
                    item.state, item.detail = item.step(api)
                else:
                    item.state, item.detail = item.step(deadline - clock())
            except NomadError as e:
                item.state, item.detail = PENDING, f"Nomad API unavailable: {e}"
            except Exception as e:  # noqa: BLE001 -- a verifier bug must fail the run, not crash it
                item.state, item.detail = UNHEALTHY, f"verification error: {type(e).__name__}: {e}"
            if clock() >= deadline and item.state == HEALTHY:
                item.state, item.detail = PENDING, "observation arrived after verification deadline"
        failed = any(i.state == UNHEALTHY for i in items)
        if failed or all(i.state != PENDING for i in items) or clock() >= deadline:
            break
        sleep(max(0.0, min(policy.interval, deadline - clock())))
    for item in items:
        if item.state == PENDING:
            # Stopped early by another item's failure, or out of time.
            item.state = "not_observed" if failed else TIMEOUT

    healthy = all(i.state == HEALTHY for i in items)
    verdict = "nothing_to_observe" if not items else HEALTHY if healthy else UNHEALTHY
    evidence = {
        "version": EVIDENCE_VERSION,
        "verdict": verdict,
        "elapsed_sec": round(clock() - start, 3),
        "timeout_sec": policy.timeout,
        "items": [i.evidence() for i in items],
    }
    if verdict != UNHEALTHY:
        return True, "", evidence
    bad = [i.evidence() for i in items if i.state != HEALTHY]
    first = next((b for b in bad if b["state"] == UNHEALTHY), bad[0])
    label = first.get("id") or first.get("name") or first.get("address") or "item"
    reason = (f"post-apply health verification failed: {len(bad)} of {len(items)} item(s) not healthy; "
              f"`{label}` {first['state']}: {first['detail'].splitlines()[-1] if first['detail'] else ''}")
    return False, reason.rstrip(": "), evidence
