"""Post-apply target health verification.

A successful `terraform apply` proves the API accepted the change, not that the
workload is healthy. After execute, `verify()` observes what the change touched
for a bounded time and returns structured evidence. Anything not observed
healthy inside the window (unhealthy, unreachable, still pending) fails
verification, so the run is recorded FAILED and blocks the target like any
failed apply.

Three kinds of item are observed, all opt-in through a target's `verify` table:

* `nomad = true`: every `nomad_job` the applied plan created, updated or
  deleted. Service and system jobs must reach a successful deployment (or,
  without one, enough running allocations of the current version). Periodic
  jobs must be registered with launches enabled; `periodic = "launch"` also
  forces one launch and requires it to complete. Other batch and
  parameterized jobs must be registered. Deleted jobs must be gone or stopped.
* `consul = true`: for every `nomad_job` the applied plan created or updated,
  each Consul service the live job declares must list at least the expected
  number of passing instances registered by allocations of the applied job
  version. Registrations from older allocations never count (see
  `ConsulServices`). Removed jobs, batch-type jobs and jobs without Consul
  services are recorded as `skipped` items.
* `[[...verify.check]]`: argv commands run in the target directory with the
  apply env, retried until they exit 0 or the window closes.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

EVIDENCE_VERSION = 1
DETAIL_MAX = 500
HTTP_TIMEOUT = 10

HEALTHY, UNHEALTHY, PENDING, TIMEOUT = "healthy", "unhealthy", "pending", "timeout"
SKIPPED = "skipped"  # nothing to require for this item (explicit no-op); never a failure
DONE = (HEALTHY, SKIPPED)


class ApiError(Exception):
    """An HTTP JSON API could not answer (unreachable, denied, malformed)."""


class NomadError(ApiError):
    """The Nomad API could not answer (unreachable, denied, malformed)."""


class ConsulError(ApiError):
    """The Consul API could not answer (unreachable, denied, malformed)."""


def _clip(text: str) -> str:
    text = (text or "").strip()
    return text if len(text) <= DETAIL_MAX else "..." + text[-(DETAIL_MAX - 3):]


def _json_api(addr: str, header: str, token: str, error: type[ApiError], *,
              deadline: float | None, clock: Callable[[], float], scheme: str = "http") -> Callable[..., Any]:
    base = addr if "://" in addr else f"{scheme}://{addr}"
    base = base.rstrip("/")

    def call(method: str, path: str, params: dict | None = None) -> Any:
        query = {k: v for k, v in (params or {}).items() if v}
        url = base + path + (f"?{urllib.parse.urlencode(query)}" if query else "")
        req = urllib.request.Request(url, method=method, data=b"{}" if method != "GET" else None)
        if token:
            req.add_header(header, token)
        try:
            remaining = HTTP_TIMEOUT if deadline is None else min(HTTP_TIMEOUT, deadline - clock())
            if remaining <= 0:
                raise error("verification deadline reached")
            with urllib.request.urlopen(req, timeout=remaining) as resp:
                body = resp.read()
        except urllib.error.HTTPError as e:
            e.close()
            if e.code == 404:
                return None
            raise error(f"HTTP {e.code} from {method} {path}") from None
        except (urllib.error.URLError, OSError) as e:
            raise error(f"{method} {path}: {getattr(e, 'reason', e)}") from None
        try:
            return json.loads(body or b"null")
        except ValueError:
            raise error(f"{method} {path}: response is not JSON") from None

    return call


def nomad_api(addr: str, token: str = "", *, deadline: float | None = None,
              clock: Callable[[], float] = time.monotonic) -> Callable[..., Any]:
    """`api(method, path, params)` -> decoded JSON, or None for a 404."""
    return _json_api(addr, "X-Nomad-Token", token, NomadError, deadline=deadline, clock=clock)


def consul_api(addr: str, token: str = "", *, ssl: bool = False, deadline: float | None = None,
               clock: Callable[[], float] = time.monotonic) -> Callable[..., Any]:
    """Like `nomad_api`, sending the token as X-Consul-Token. `ssl` picks https
    for a scheme-less address (CONSUL_HTTP_SSL)."""
    return _json_api(addr, "X-Consul-Token", token, ConsulError, deadline=deadline, clock=clock,
                     scheme="https" if ssl else "http")


_IMAGE = re.compile(r'\bimage\s*=\s*"([^"\\\n]*)"')


def jobspec_images(jobspec: object) -> list[str]:
    """Literal container images in a planned jobspec (HCL text or JSON).

    Only plain literals are returned: anything interpolated (`${...}`) is
    resolved by Nomad or HCL2 variables and cannot be compared here. Whole-line
    `#` and `//` comments are ignored. Returns [] when nothing is known."""
    if not isinstance(jobspec, str) or not jobspec.strip():
        return []
    found: list[str] = []
    try:
        doc = json.loads(jobspec)
    except ValueError:
        doc = None
    if isinstance(doc, (dict, list)):
        def walk(node: object) -> None:
            if isinstance(node, dict):
                for key, value in node.items():
                    if key.lower() == "image" and isinstance(value, str):
                        found.append(value)
                    else:
                        walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)
        walk(doc)
    else:
        text = re.sub(r"/\*.*?\*/", "", jobspec, flags=re.DOTALL)
        lines = [ln for ln in text.splitlines() if not ln.lstrip().startswith(("#", "//"))]
        found = _IMAGE.findall("\n".join(lines))
    return sorted({img for img in found if img and "${" not in img})


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
            "images": [] if removed else jobspec_images(values.get("jobspec")),
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
        return {"kind": "nomad_job", "id": self.job["id"], "namespace": self.job["namespace"], "region": self.job.get("region", ""),
                "address": self.job["address"], "policy": self.policy or "unobserved",
                "state": self.state, "detail": _clip(self.detail), "polls": self.polls,
                "observed": self.observed}


# Nomad registers each Consul service instance with an ID that embeds the
# allocation: `_nomad-task-<alloc-uuid>-<task>-<service>-<port>` (task services)
# or `_nomad-task-<alloc-uuid>-group-<group>-<service>-<port>` (group services).
_NOMAD_SERVICE_ID = re.compile(r"^_nomad-task-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})-")
NON_SERVICE_TYPES = ("batch", "sysbatch")


def service_alloc(service_id: object) -> str:
    """The allocation ID Nomad embedded in a Consul service ID, or ""."""
    m = _NOMAD_SERVICE_ID.match(service_id) if isinstance(service_id, str) else None
    return m.group(1) if m else ""


def _service_name(name: str, job: str, group: str, task: str = "") -> str:
    if not name:
        name = f"{job}-{group}-{task}" if task else f"{job}-{group}"
    subs = {"JOB": job, "NOMAD_JOB_NAME": job, "TASKGROUP": group, "NOMAD_GROUP_NAME": group}
    if task:
        subs.update(BASE=f"{job}-{group}-{task}", TASK=task, NOMAD_TASK_NAME=task)
    for var, value in subs.items():
        name = name.replace("${" + var + "}", value)
    return name


def declared_services(job_id: str, live: dict) -> dict[str, dict[str, int]]:
    """{service name: {group: registrations per allocation}} for Consul services.

    Read from the live job definition (Nomad's parse of the applied jobspec).
    Services with `provider = "nomad"` are Nomad-native and not in Consul."""
    out: dict[str, dict[str, int]] = {}

    def add(svc: dict, group: str, task: str = "") -> None:
        if (svc.get("Provider") or "consul") != "consul":
            return
        name = _service_name(svc.get("Name") or "", job_id, group, task)
        out.setdefault(name, {}).setdefault(group, 0)
        out[name][group] += 1

    for group in live.get("TaskGroups") or []:
        gname = group.get("Name") or ""
        for svc in group.get("Services") or []:
            add(svc, gname)
        for task in group.get("Tasks") or []:
            for svc in task.get("Services") or []:
                add(svc, gname, task.get("Name") or "")
    return out


def live_images(live: dict) -> set[str]:
    return {str((t.get("Config") or {}).get("image")) for g in live.get("TaskGroups") or []
            for t in g.get("Tasks") or [] if (t.get("Config") or {}).get("image")}


class ConsulServices(_Item):
    """Consul service health for one changed Nomad job, bound to its applied version.

    A passing count alone can be met by allocations of the previous version
    while the changed deployment fails, so a registration counts only when the
    allocation ID Nomad embedded in its service ID is a running allocation of
    the job version observed on the first poll after apply. Further:

    * the job version must not change during the window (auto-revert or a
      concurrent submission means the applied version is no longer live);
    * literal images in the planned jobspec must all appear in the live job;
    * a failed or cancelled deployment of that version fails at once.

    Expected instances per service are the group `count` times the service's
    registrations per allocation (system jobs: the running allocations of the
    version, at least one). During a rolling update old and new allocations
    overlap; old ones are reported as `stale` and never counted, so the item
    is healthy only once enough new allocations pass.
    """

    def __init__(self, job: dict) -> None:
        self.job = job
        self.policy = "consul"
        self.version: Any = None
        self.observed: dict[str, Any] = {}

    def _params(self, **extra: str) -> dict:
        return {"namespace": self.job["namespace"], "region": self.job["region"], **extra}

    def _path(self, *parts: str) -> str:
        return "/v1/" + "/".join(urllib.parse.quote(p, safe="") for p in parts)

    def step(self, nomad: Callable[..., Any], consul: Callable[..., Any]) -> tuple[str, str]:
        jid = self.job["id"]
        if not jid:
            return UNHEALTHY, "job ID is unknown in the applied plan; cannot observe its services"
        if self.job["removed"]:
            return SKIPPED, "removed by the plan; no services required"
        live = nomad("GET", self._path("job", jid), self._params())
        if live is None:
            return PENDING, "not registered"
        if live.get("Stop"):
            return UNHEALTHY, "job is stopped"
        jtype = live.get("Type") or "service"
        if jtype in NON_SERVICE_TYPES or live.get("Periodic") or live.get("ParameterizedJob"):
            return SKIPPED, f"{jtype} job; Consul services are not required to stay registered"
        version = live.get("Version")
        if self.version is None:
            self.version = version
            self.observed["job_version"] = version
        elif version != self.version:
            return UNHEALTHY, (f"job version changed from {self.version} to {version} during verification "
                               "(auto-revert or another submission); the applied version is no longer live")
        planned = set(self.job.get("images") or [])
        if planned:
            missing = sorted(planned - live_images(live))
            self.observed["image_check"] = "mismatch" if missing else "matched"
            if missing:
                return UNHEALTHY, f"live job version {version} does not run the applied image(s) {', '.join(missing)}"
        else:
            self.observed["image_check"] = "unavailable"
        services = declared_services(jid, live)
        if not services:
            return SKIPPED, "job declares no Consul services"
        unresolved = sorted(n for n in services if "${" in n)
        if unresolved:
            return UNHEALTHY, f"cannot resolve Consul service name(s) {', '.join(unresolved)}"
        dep = nomad("GET", self._path("job", jid, "deployment"), self._params())
        if dep and dep.get("JobVersion") == version and dep.get("Status") in ("failed", "cancelled"):
            return UNHEALTHY, f"deployment of version {version} {dep.get('Status')}"
        allocs = nomad("GET", self._path("job", jid, "allocations"), self._params()) or []
        new = {a["ID"]: a.get("TaskGroup") for a in allocs if a.get("ID") and a.get("JobVersion") == version
               and a.get("DesiredStatus") == "run" and a.get("ClientStatus") == "running"}
        others = {a["ID"] for a in allocs if a.get("ID") and a["ID"] not in new}
        wanted: dict[str, int] = {}
        for group in live.get("TaskGroups") or []:
            name = group.get("Name") or ""
            if jtype == "system":
                wanted[name] = max(1, sum(g == name for g in new.values()))
            else:
                wanted[name] = int(group.get("Count") or 0)
        rows: dict[str, dict[str, int]] = {}
        for name, groups in sorted(services.items()):
            entries = consul("GET", self._path("health", "service", name)) or []
            row = {"expected": sum(wanted.get(g, 0) * n for g, n in groups.items()),
                   "passing": 0, "failing": 0, "stale": 0, "other": 0}
            for entry in entries if isinstance(entries, list) else []:
                alloc = service_alloc((entry.get("Service") or {}).get("ID"))
                passing = all(c.get("Status") == "passing" for c in entry.get("Checks") or [])
                if alloc in new and new[alloc] in groups:
                    row["passing" if passing else "failing"] += 1
                elif alloc in others:
                    row["stale"] += 1
                else:
                    row["other"] += 1
            rows[name] = row
        self.observed.update(services=rows, new_allocations=len(new))
        parts = []
        for name, r in rows.items():
            notes = [f"{r['failing']} not passing"] if r["failing"] else []
            if not r["passing"] and not r["failing"]:
                notes.append("no registration from the new allocations")
            if r["stale"]:
                notes.append(f"{r['stale']} from older allocations ignored")
            parts.append(f"{name}: {r['passing']}/{r['expected']} passing on version {version}"
                         + (f" ({'; '.join(notes)})" if notes else ""))
        complete = all(r["passing"] >= r["expected"] for r in rows.values())
        return (HEALTHY if complete else PENDING), "; ".join(parts)

    def evidence(self) -> dict:
        return {"kind": "consul_service", "id": self.job["id"], "namespace": self.job["namespace"],
                "region": self.job.get("region", ""), "address": self.job["address"], "policy": self.policy,
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
           consul: Callable[..., Any] | None = None,
           clock: Callable[[], float] = time.monotonic,
           sleep: Callable[[float], None] = time.sleep) -> tuple[bool, str, dict]:
    """Observe until every item is healthy, one is unhealthy, or the window closes.

    Returns (ok, one-line reason, evidence). Never raises for target trouble:
    an unreachable API is an item that stays pending until the deadline.
    `api` and `consul` replace the Nomad and Consul HTTP clients (tests).
    """
    start = clock()
    deadline = start + policy.timeout
    items: list[_Item] = []
    use_consul = policy.consul
    if policy.nomad or use_consul:
        jobs: list[dict] = []
        if plan is None:
            missing = NomadJob({"address": "", "id": None, "namespace": "", "region": "", "removed": False},
                               policy.periodic)
            missing.state, missing.detail = UNHEALTHY, "no applied plan to derive Nomad jobs from"
            items.append(missing)
        else:
            jobs = nomad_jobs(plan)
        if policy.nomad:
            items += [NomadJob(j, policy.periodic) for j in jobs]
        if use_consul:
            items += [ConsulServices(j) for j in jobs]
        addr = policy.nomad_addr or env.get("NOMAD_ADDR", "")
        if api is None and addr:
            api = nomad_api(addr, env.get("NOMAD_TOKEN", ""), deadline=deadline, clock=clock)
        caddr = policy.consul_addr or env.get("CONSUL_HTTP_ADDR", "")
        if use_consul and consul is None and caddr:
            ssl = env.get("CONSUL_HTTP_SSL", "").strip().lower() in ("1", "true", "yes")
            consul = consul_api(caddr, env.get("CONSUL_HTTP_TOKEN", ""), ssl=ssl, deadline=deadline, clock=clock)
    items += [Check(c, cwd, env) for c in policy.checks]

    while True:
        for item in items:
            if item.state != PENDING:
                continue
            if clock() >= deadline:
                break
            item.polls += 1
            try:
                if isinstance(item, (NomadJob, ConsulServices)) and api is None:
                    item.state, item.detail = UNHEALTHY, "no Nomad address (set verify.nomad_addr or NOMAD_ADDR)"
                    continue
                if isinstance(item, ConsulServices):
                    if consul is None:
                        item.state, item.detail = UNHEALTHY, "no Consul address (set verify.consul_addr or CONSUL_HTTP_ADDR)"
                        continue
                    item.state, item.detail = item.step(api, consul)
                elif isinstance(item, NomadJob):
                    item.state, item.detail = item.step(api)
                else:
                    item.state, item.detail = item.step(deadline - clock())
            except NomadError as e:
                item.state, item.detail = PENDING, f"Nomad API unavailable: {e}"
            except ConsulError as e:
                item.state, item.detail = PENDING, f"Consul API unavailable: {e}"
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

    healthy = all(i.state in DONE for i in items)
    # Skipped items are explicit no-ops: recorded, never failing, never proof of health.
    observed = [i for i in items if i.state != SKIPPED]
    verdict = "nothing_to_observe" if not observed else HEALTHY if healthy else UNHEALTHY
    evidence = {
        "version": EVIDENCE_VERSION,
        "verdict": verdict,
        "elapsed_sec": round(clock() - start, 3),
        "timeout_sec": policy.timeout,
        "items": [i.evidence() for i in items],
    }
    if verdict != UNHEALTHY:
        return True, "", evidence
    bad = [i.evidence() for i in items if i.state not in DONE]
    first = next((b for b in bad if b["state"] == UNHEALTHY), bad[0])
    label = first.get("id") or first.get("name") or first.get("address") or "item"
    what = " Consul services" if first.get("kind") == "consul_service" else ""
    reason = (f"post-apply health verification failed: {len(bad)} of {len(items)} item(s) not healthy; "
              f"`{label}`{what} {first['state']}: {first['detail'].splitlines()[-1] if first['detail'] else ''}")
    return False, reason.rstrip(": "), evidence
