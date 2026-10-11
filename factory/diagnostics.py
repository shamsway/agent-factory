"""Bounded read-only runtime evidence. Payloads are untrusted, never instructions.

Collectors share a deadline and byte budget. Only allowlisted state fields enter
the bundle; job specs, plans, variables and host configuration are never copied.
Unknown token shapes remain a sanitizer limitation (SHA-238).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from factory import artifacts


@dataclass
class Policy:
    timeout: int = 20
    call_timeout: int = 3
    max_bytes: int = 256 * 1024
    response_bytes: int = 64 * 1024
    lookback: int = 3600
    logs: bool = False
    nomad_addr: str = ""
    consul_addr: str = ""
    services: list[str] = field(default_factory=list)
    probes: list[str] = field(default_factory=list)
    error_logs: list[str] = field(default_factory=list)


def policy(raw: object) -> Policy | None:
    from factory.config import ConfigError
    if raw is None:
        return None
    if not isinstance(raw, dict) or set(raw) - set(Policy.__dataclass_fields__):
        raise ConfigError("diagnostics: invalid table or unknown keys")
    p = Policy(**raw)
    if type(p.logs) is not bool:
        raise ConfigError("diagnostics.logs: expected boolean")
    for key, maximum in (("timeout", 120), ("call_timeout", 10), ("max_bytes", 1024 * 1024),
                         ("response_bytes", 256 * 1024), ("lookback", 3600)):
        value = getattr(p, key)
        if type(value) is not int or not (8192 if key == "max_bytes" else 1) <= value <= maximum:
            raise ConfigError(f"diagnostics.{key}: out of bounds")
    for key in ("nomad_addr", "consul_addr"):
        value = getattr(p, key)
        if not isinstance(value, str):
            raise ConfigError(f"diagnostics.{key}: expected URL string")
        if value:
            endpoint(value)
    for key in ("services", "probes", "error_logs"):
        values = getattr(p, key)
        if not isinstance(values, list) or len(values) > 8 or not all(isinstance(v, str) and v for v in values):
            raise ConfigError(f"diagnostics.{key}: expected up to eight strings")
    for url in p.probes:
        endpoint(url)
    for path in p.error_logs:
        if not re.fullmatch(r"[A-Za-z0-9_/-]+\.log", path) or path.startswith("/") or ".." in path or "secrets" in path.lower().split("/"):
            raise ConfigError("diagnostics.error_logs: require allowlisted relative .log paths")
    return p


def endpoint(url: str) -> str:
    # Never embed credentials in URLs/references or forward them on redirects.
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password or u.query or u.fragment:
        from factory.config import ConfigError
        raise ConfigError("diagnostics: require credential-free HTTP(S) URL without query/fragment")
    return url.rstrip("/")


class Unavailable(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Unavailable("redirect_refused")


class HTTP:
    """GET only. No arbitrary request method, command, or filesystem access."""
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.opener = urllib.request.build_opener(NoRedirect())

    def get(self, url: str, headers: dict, deadline: float, limit: int) -> bytes:
        remaining = deadline - self.clock()
        if remaining <= 0:
            raise Unavailable("budget_expired")
        # A socket timeout does not bound getaddrinfo. An isolated reader can
        # be killed even when DNS or TLS is stuck. Credentials travel through
        # stdin, never argv; raw bounded output remains in memory only.
        env = {key: value for key, value in os.environ.items() if key in
               ("PATH", "SSL_CERT_FILE", "SSL_CERT_DIR", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
                "http_proxy", "https_proxy", "no_proxy")}
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
        try:
            result = subprocess.run([sys.executable, "-P", "-c",
                "from factory.diagnostics import http_worker; http_worker()"],
                input=json.dumps({"url": url, "headers": headers, "deadline": deadline, "limit": limit}).encode(),
                capture_output=True, env=env, timeout=remaining)
        except subprocess.TimeoutExpired:
            raise Unavailable("budget_expired") from None
        if result.returncode:
            reason = result.stderr.decode(errors="replace").strip()
            safe = {"permission_denied", "absent_or_expired", "expired", "transport_unavailable", "budget_expired",
                    "redirect_refused", "response_too_large"}
            raise Unavailable(reason if reason in safe or re.fullmatch(r"HTTP\d{3}", reason) else "transport_unavailable")
        if self.clock() > deadline or len(result.stdout) > limit:
            raise Unavailable("budget_expired")
        return result.stdout

    def _read(self, url: str, headers: dict, deadline: float, limit: int) -> bytes:
        try:
            remaining = deadline - self.clock()
            if remaining <= 0:
                raise Unavailable("budget_expired")
            req = urllib.request.Request(url, headers=headers, method="GET")
            with self.opener.open(req, timeout=remaining) as response:
                chunks, size = [], 0
                while size <= limit:
                    if self.clock() >= deadline:
                        raise Unavailable("budget_expired")
                    if response.isclosed():
                        break
                    response.fp.raw._sock.settimeout(max(0.001, deadline - self.clock()))
                    # read1 performs at most one underlying read, allowing a
                    # deadline check between chunks even on trickle responses.
                    part = response.read1(min(4096, limit + 1 - size))
                    if not part:
                        break
                    chunks.append(part)
                    size += len(part)
                if self.clock() > deadline:
                    raise Unavailable("budget_expired")
                if size > limit:
                    raise Unavailable("response_too_large")
                return b"".join(chunks)
        except urllib.error.HTTPError as exc:
            exc.close()
            raise Unavailable({403: "permission_denied", 401: "permission_denied",
                               404: "absent_or_expired", 410: "expired"}.get(exc.code, f"HTTP{exc.code}")) from None
        except (OSError, urllib.error.URLError):
            raise Unavailable("transport_unavailable") from None


def http_worker():
    """Private fixed GET reader; no filesystem persistence or other commands."""
    try:
        request = json.loads(sys.stdin.buffer.read())
        value = HTTP()._read(request["url"], request["headers"], request["deadline"], request["limit"])
    except Unavailable as exc:
        sys.stderr.write(str(exc))
        raise SystemExit(1)
    except Exception:
        sys.stderr.write("transport_unavailable")
        raise SystemExit(1)
    sys.stdout.buffer.write(value)


def seconds(value) -> float | None:
    try:
        if isinstance(value, str):
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.timestamp() if parsed.tzinfo else None
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return value / 1e9 if value > 1e12 else float(value)
    except (ValueError, OverflowError):
        pass
    return None


def utc(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def pick(row: dict, names: str) -> dict:
    return {k: row[k] for k in names.split() if k in row}


def public_tree(value, secrets):
    """Defense for plugin/local evidence: never retain secret-shaped fields."""
    if isinstance(value, dict):
        return {artifacts.sanitize(str(key), secrets):
                artifacts.REDACTED if artifacts.SECRET_NAME_RE.search(str(key)) or str(key).lower() in
                ("env", "environment", "variables", "config", "host_config", "plan", "terraform_state", "terraform_plan")
                else public_tree(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [public_tree(item, secrets) for item in value]
    return artifacts.sanitize_tree(value, secrets)


class Context:
    def __init__(self, run, p: Policy, env: dict, transport=None, clock=time.monotonic, wall=time.time):
        self.run, self.p, self.env, self.clock, self.wall = run, p, env, clock, wall
        self.transport = transport or HTTP(clock)
        self.started = clock()
        self.deadline = self.started + p.timeout
        self.secrets = artifacts.secret_values(env, os.environ)
        self.rows = []
        self.used = 0
        self.downloaded = 0
        self.dropped = 0
        now = wall()
        self.window_known = seconds(run.started_at) is not None and seconds(run.completed_at) is not None
        # Old incidents must not silently widen to unlimited historical data.
        self.end = min(seconds(run.completed_at) or now, now)
        self.start = max(seconds(run.started_at) or self.end, self.end - p.lookback)
        self.jobs = []
        for item in (run.verification or {}).get("items", []):
            if item.get("kind") == "nomad_job" and item.get("id"):
                self.jobs.append({"id": item["id"], "namespace": item.get("namespace") or "default",
                                  "region": item.get("region") or "", "version": (item.get("observed") or {}).get("version")})
        self.jobs = self.jobs[:8]
        if not self.jobs:
            self.jobs = [{**job, "version": None} for job in (getattr(run, "diagnostic_jobs", None) or [])[:8]]

    def add(self, source, status, data=None, *, lineage=None):
        row = public_tree({"source": source, "status": status, "observed_at": utc(self.wall()),
                           "lineage": lineage, "data": data}, self.secrets)
        raw = json.dumps(row).encode()
        if self.used + len(raw) > self.p.max_bytes - 4096:
            self.dropped += 1
            return
        self.used += len(raw)
        self.rows.append(row)

    def get(self, base, path, params=None, *, token="", header="X-Nomad-Token", text=False):
        url = endpoint(base) + path
        if params:
            url += "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v != "" and v is not None})
        remaining = self.p.max_bytes - self.downloaded
        if self.clock() >= self.deadline or remaining <= 0:
            raise Unavailable("budget_expired")
        limit = min(self.p.response_bytes, remaining)
        # Reserve the full response allowance before I/O. A rejected oversized
        # or interrupted response still consumed bytes; failures cannot reset
        # the shared download budget.
        self.downloaded += limit
        data = self.transport.get(url, {header: token} if token else {},
                                  min(self.deadline, self.clock() + self.p.call_timeout), limit)
        self.downloaded += len(data) - limit
        if len(data) > limit or self.clock() > self.deadline:
            raise Unavailable("budget_expired")
        if text:
            return data.decode("utf-8", errors="replace")
        try:
            return json.loads(data)
        except (ValueError, UnicodeError):
            raise Unavailable("invalid_response") from None

    def observe(self, source, action, *, lineage=None):
        try:
            value = action()
            self.add(source, "observed", value, lineage=lineage)
            return value
        except Unavailable as exc:
            self.add(source, str(exc), lineage=lineage)
        except Exception as exc:
            # Messages can contain raw payloads or private URLs; type only.
            self.add(source, type(exc).__name__, lineage=lineage)
        return None


def local(ctx: Context):
    run = ctx.run
    if not ctx.p.logs:
        items = [pick(item, "kind id namespace region policy state observed")
                 for item in (run.verification or {}).get("items", [])]
        ctx.add("deploy_run", "observed", {"status": run.status.value, "verification": {"items": items},
                                            "free_text": "disabled"})
        return
    ctx.add("deploy_run", "observed", {"status": run.status.value, "error": run.error,
                                        "output_tail": run.output[-4000:], "verification": run.verification})


def nomad(ctx: Context):
    base = ctx.p.nomad_addr or ctx.env.get("NOMAD_ADDR", "")
    if not base or not ctx.jobs:
        ctx.add("nomad", "not_configured" if not base else "lineage_unavailable")
        return
    if not ctx.window_known:
        ctx.add("nomad", "window_unavailable")
        return
    token = ctx.env.get("FACTORY_DIAGNOSTIC_NOMAD_TOKEN", "")
    for job in ctx.jobs:
        jid = urllib.parse.quote(job["id"], safe="")
        params = {"namespace": job["namespace"], "region": job["region"]}
        def read(path, extra=None, text=False):
            return ctx.get(base, path, {**params, **(extra or {})}, token=token, text=text)
        ctx.observe(f"nomad/job/{jid}/current", lambda: pick(read(f"/v1/job/{jid}"), "ID Namespace Version Status Type Stop"),
                    lineage={**job, "relation": "current_state_only"})
        lineage = {**job, "relation": "recorded_health_version"}
        def evals():
            rows = read(f"/v1/job/{jid}/evaluations")
            return [pick(r, "ID JobID Namespace JobModifyIndex Status StatusDescription TriggeredBy PreviousEval NextEval BlockedEval DeploymentID CreateTime ModifyTime FailedTGAllocs")
                    for r in rows if r.get("JobID") == job["id"] and r.get("Namespace", "default") == job["namespace"]
                    and seconds(r.get("ModifyTime")) is not None and ctx.start <= seconds(r["ModifyTime"]) <= ctx.end][:50]
        # Evaluation API has no JobVersion; time/JobID is weaker correlation.
        ctx.observe(f"nomad/job/{jid}/evaluations", evals,
                    lineage={**lineage, "relation": "job_time_window_not_version_proof"})
        if type(job["version"]) is not int:
            ctx.add(f"nomad/job/{jid}", "version_unavailable", lineage=job)
            continue
        ctx.observe(f"nomad/job/{jid}/deployments", lambda: [pick(r, "ID JobID Namespace JobVersion Status StatusDescription CreateIndex ModifyIndex")
                    for r in read(f"/v1/job/{jid}/deployments") if r.get("JobVersion") == job["version"]
                    and r.get("JobID") == job["id"] and r.get("Namespace", "default") == job["namespace"]][:50], lineage=lineage)
        rows = ctx.observe(f"nomad/job/{jid}/allocations", lambda: [pick(r, "ID JobID Namespace JobVersion EvalID DeploymentID PreviousAllocation NextAllocation NodeID TaskGroup ClientStatus DesiredStatus CreateTime ModifyTime")
                    for r in read(f"/v1/job/{jid}/allocations", {"all": "true"})
                    if r.get("JobVersion") == job["version"] and r.get("JobID") == job["id"]
                    and r.get("Namespace", "default") == job["namespace"]
                    and seconds(r.get("CreateTime")) is not None and seconds(r["CreateTime"]) <= ctx.end
                    and seconds(r.get("ModifyTime")) is not None and seconds(r["ModifyTime"]) >= ctx.start][:50], lineage=lineage) or []
        for row in rows[:8]:
            aid = urllib.parse.quote(row["ID"], safe="")
            alloc_lineage = {**lineage, **pick(row, "EvalID DeploymentID PreviousAllocation NextAllocation"), "allocation": row["ID"]}
            def allocation():
                value = read(f"/v1/allocation/{aid}")
                if value.get("JobID") != job["id"] or value.get("Job", {}).get("Version") != job["version"] or value.get("Namespace", "default") != job["namespace"]:
                    raise Unavailable("lineage_mismatch")
                tasks = {}
                for name, task in list((value.get("TaskStates") or {}).items())[:8]:
                    tasks[name] = pick(task, "State Failed StartedAt FinishedAt")
                    fields = "Type Time ExitCode Signal FailsTask" + (" DisplayMessage Message RestartReason" if ctx.p.logs else "")
                    events = []
                    for event in task.get("Events", []):
                        if seconds(event.get("Time")) is None or not ctx.start <= seconds(event["Time"]) <= ctx.end:
                            continue
                        projected = pick(event, fields)
                        # Nomad 2.x records this explicit driver signal in Details.
                        # Never retain the arbitrary Details map or infer from 137.
                        oom = (event.get("Details") or {}).get("oom_killed")
                        if oom in ("true", "false"):
                            projected["OOMKilled"] = oom == "true"
                        events.append(projected)
                    tasks[name]["Events"] = events[-50:]
                return {**pick(value, "ID JobID Namespace EvalID DeploymentID PreviousAllocation NextAllocation ClientStatus DesiredStatus"), "tasks": tasks}
            details = ctx.observe(f"nomad/allocation/{aid}", allocation, lineage=alloc_lineage)
            if not ctx.p.logs:
                ctx.add(f"nomad/allocation/{aid}/logs", "disabled", lineage=alloc_lineage)
                continue
            for task in (details or {}).get("tasks", {}):
                # Nomad task logs lack reliable timestamps. Treat the bounded
                # tail as context, not proof it belongs to the failure window.
                for stream in ("stdout", "stderr"):
                    ctx.observe(f"nomad/allocation/{aid}/{task}/{stream}",
                                lambda t=task, s=stream: {"text": read(f"/v1/client/fs/logs/{aid}",
                                    {"task": t, "type": s, "follow": "false", "plain": "true", "origin": "end", "offset": min(8192, ctx.p.response_bytes)}, text=True),
                                    "time_coverage": "untimestamped_bounded_tail"}, lineage=alloc_lineage)
            if details:
                for path in ctx.p.error_logs:
                    def error_log(path=path):
                        stat = read(f"/v1/client/fs/stat/{aid}", {"path": path})
                        size = stat.get("Size")
                        if type(size) is not int or size < 0 or stat.get("IsDir"):
                            raise Unavailable("invalid_log_stat")
                        count = min(8192, ctx.p.response_bytes)
                        return {"text": read(f"/v1/client/fs/readat/{aid}", {"path": path, "offset": max(0, size - count), "limit": count}, text=True),
                                "time_coverage": "untimestamped_bounded_tail"}
                    ctx.observe(f"nomad/allocation/{aid}/error-log/{path}", error_log, lineage=alloc_lineage)


def consul(ctx: Context):
    if not ctx.p.consul_addr or not ctx.p.services:
        ctx.add("consul", "not_configured")
        return
    for service in ctx.p.services:
        path = "/v1/health/checks/" + urllib.parse.quote(service, safe="")
        fields = "Node CheckID Name Status ServiceID ServiceName" + (" Output" if ctx.p.logs else "")
        ctx.observe("consul/health/" + service, lambda p=path: [pick(r, fields)
            for r in ctx.get(ctx.p.consul_addr, p, token=ctx.env.get("CONSUL_HTTP_TOKEN", ""), header="X-Consul-Token")][:50],
            lineage={"relation": "current_state_only"})


def probes(ctx: Context):
    for index, url in enumerate(ctx.p.probes):
        # No response body retained: dependency probes may return secrets.
        ctx.observe(f"probe/{index}", lambda u=url: {"reachable": isinstance(ctx.get(u, "", text=True), str)},
                    lineage={"relation": "current_state_only", "allowlist_index": index})


COLLECTORS = (local, nomad, consul, probes)


def verify_nomad_token(cfg, token: str) -> str:
    """Check attached ACL policies without printing tokens, rules or errors."""
    if token == cfg.apply_env.get("NOMAD_TOKEN"):
        return "invalid"
    base = next((t.diagnostics.get("nomad_addr") or (t.verify.nomad_addr if t.verify else "")
                 for t in cfg.targets.values() if t.diagnostics is not None), "") or cfg.apply_env.get("NOMAD_ADDR", "")
    if not base:
        return "unavailable"
    try:
        deadline = time.monotonic() + 10
        reader = HTTP()
        def get(path):
            return json.loads(reader.get(endpoint(base) + path, {"X-Nomad-Token": token}, deadline, 65536))
        identity = get("/v1/acl/token/self")
        if identity.get("Type") != "client" or identity.get("Roles"):
            return "invalid"
        names = identity.get("Policies") or []
        if not names or len(names) > 8:
            return "invalid"
        allowed = {"list-jobs", "read-job", "read-logs", "read-scaling", "list-scaling-policies",
                   "read-scaling-policy"}
        if any(t.diagnostics and t.diagnostics.get("logs") is True and t.diagnostics.get("error_logs")
               for t in cfg.targets.values()):
            allowed.add("read-fs")
        for name in names:
            rules = get("/v1/acl/policy/" + urllib.parse.quote(name, safe="")).get("Rules", "")
            # Conservative: reject unknown capabilities and non-read policies.
            # Rules only used in memory, never emitted or persisted.
            # Refuse comments/escapes rather than risk stripping a grant while
            # scanning HCL. Operator can use a simple explicit read-only policy.
            if any(part in rules for part in ("#", "//", "/*", "\\")):
                return "unavailable"
            # Read-only variables still expose stored secrets. Never accept
            # variable access, even when an explicit path only grants read/list.
            if re.search(r"\bvariables\s*\{", rules):
                return "invalid"
            if len(re.findall(r"\bpolicy\s*=", rules)) != len(re.findall(r'\bpolicy\s*=\s*"[^"]+"', rules)):
                return "unavailable"
            if len(re.findall(r"\bcapabilities\s*=", rules)) != len(re.findall(r"\bcapabilities\s*=\s*\[[^]]*\]", rules)):
                return "unavailable"
            if not rules or any(v not in ("read", "deny") for v in re.findall(r'policy\s*=\s*"([^"]+)"', rules)):
                return "invalid"
            for group in re.findall(r"capabilities\s*=\s*\[([^]]*)\]", rules):
                if set(re.findall(r'"([^"]+)"', group)) - allowed:
                    return "invalid"
            if not re.search(r'policy\s*=\s*"read"|capabilities\s*=', rules):
                return "invalid"
        get("/v1/jobs")
        return "valid"
    except Exception:
        return "unavailable"


def collect(run, p: Policy, env: dict, *, collectors=None, transport=None, clock=time.monotonic, wall=time.time) -> dict:
    ctx = Context(run, p, env, transport, clock, wall)
    for collector in collectors if collectors is not None else COLLECTORS:
        if ctx.clock() >= ctx.deadline:
            ctx.add(collector.__name__, "budget_expired")
            continue
        try:
            collector(ctx)
        except Exception as exc:
            ctx.add(collector.__name__, type(exc).__name__)
    return artifacts.sanitize_tree({"version": 1, "run_id": run.run_id, "target": run.target, "commit": run.commit,
        "collected_at": utc(ctx.wall()), "window": {"start": utc(ctx.start), "end": utc(ctx.end), "known": ctx.window_known},
        "elapsed_sec": round(ctx.clock() - ctx.started, 3), "limits": {"total_sec": p.timeout, "per_call_sec": p.call_timeout,
        "response_bytes": p.response_bytes, "bundle_bytes": p.max_bytes, "lookback_sec": p.lookback,
        "jobs": 8, "state_rows": 50, "allocations_with_logs": 8, "tasks_per_allocation": 8, "task_events": 50, "log_tail_bytes": 8192},
        "observations": ctx.rows, "dropped_observations": ctx.dropped,
        "logs_enabled": p.logs, "nomad_identity": "diagnostic_token" if env.get("FACTORY_DIAGNOSTIC_NOMAD_TOKEN") else "anonymous",
        "limitations": ["Recorded health version is an observation, not an atomic commit-to-Nomad proof.",
                         "Evaluations correlate by job and time, not job version; logs may be untimestamped or expired.",
                         "Unknown secret formats remain a sanitizer limitation (SHA-238)."]}, ctx.secrets)


def main(argv: list[str]) -> int:
    import fcntl
    from factory import config, deploy
    parser = argparse.ArgumentParser(prog="factory diagnostics")
    parser.add_argument("--target", default="default")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args(argv)
    cfg = config.load()
    target = cfg.targets.get(args.target)
    if not target or target.diagnostics is None:
        parser.error("target diagnostics are not configured")
    locks = cfg.factory / "locks"
    locks.mkdir(parents=True, exist_ok=True)
    fd = os.open(locks / "apply.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            parser.error("apply pass is busy; retry diagnostics later")
        run = next((r for r in deploy.get_target_state(args.target, cfg.factory / "events.jsonl").runs if r.run_id == args.run_id), None)
        if not run or not run.is_terminal():
            parser.error("terminal run not found")
        env = {**os.environ, **cfg.apply_env}
        bundle = collect(run, policy(target.diagnostics), env)
        if not artifacts.read_manifest(artifacts.artifact_dir(cfg.factory, run.target, run.run_id)):
            artifacts.write_run_artifacts(cfg.factory, run, secrets=artifacts.secret_values(env, os.environ))
        artifacts.write_diagnostics(cfg.factory, run, bundle)
    print(json.dumps({"run_id": run.run_id, "target": run.target, "observations": len(bundle["observations"]),
                      "artifact": "diagnostics.json", "dropped_observations": bundle["dropped_observations"]}))
    return 0
