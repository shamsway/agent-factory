"""Trusted, bounded SHA-201 evidence broker. No model/network/publication calls.

This module is not a sandbox. Only its immutable projection may cross the future
investigator boundary; the legacy worker must never receive the store or bundle.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time
import urllib.parse

from . import artifacts, incidents

POLICY_VERSION = 1
MAX_FILE = 1024 * 1024
MAX_JOURNAL = 64 * MAX_FILE
MAX_ROWS = 256
MAX_PROJECTION = 128 * 1024
MAX_AGE = 3600
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
HEX = re.compile(r"[0-9a-f]{40}")
STATUSES = frozenset({"observed", "disabled", "not_configured", "lineage_unavailable",
    "version_unavailable", "window_unavailable", "permission_denied", "absent_or_expired",
    "expired", "budget_expired", "transport_unavailable", "response_too_large"})
JOB_STATES = frozenset({"pending", "running", "dead"})
ALLOC_STATES = frozenset({"pending", "running", "complete", "failed", "lost", "unknown"})
EVAL_STATES = frozenset({"pending", "complete", "failed", "blocked", "canceled"})
DEPLOY_STATES = frozenset({"running", "paused", "successful", "failed", "cancelled", "blocked"})
EVENT_TYPES = frozenset({"Received", "Task Setup", "Driver", "Started", "Terminated", "Restarting",
    "Not Restarting", "Killing", "Killed", "Sibling Task Failed", "Failed Validation"})


class EvidenceRefused(ValueError):
    """Fixed reason codes only: exceptions must not contain private payloads."""


def require(condition, reason="invalid_evidence"):
    if not condition:
        raise EvidenceRefused(reason)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def encoded(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def timestamp(value) -> float:
    require(isinstance(value, str) and len(value) <= 40)
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        require(dt.tzinfo is not None)
        return dt.timestamp()
    except (ValueError, OverflowError):
        raise EvidenceRefused("invalid_timestamp") from None


def utc(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def number(value) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 10**12


def alias(kind: str, value: str) -> str:
    require(isinstance(value, str) and 0 < len(value) <= 256)
    return kind + "-" + digest(value.encode())[:24]


@contextmanager
def directory(root: Path):
    """Anchor every ancestor without following symlinks, then use openat only."""
    path = Path(root).absolute()
    require(".." not in path.parts, "unsafe_path")
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        yield fd
    except OSError:
        raise EvidenceRefused("unsafe_or_missing_file") from None
    finally:
        os.close(fd)


@contextmanager
def file_at(root_fd: int, parts: tuple[str, ...]):
    fd = os.dup(root_fd)
    opened = None
    try:
        for part in parts[:-1]:
            require(part not in ("", ".", "..") and "/" not in part, "unsafe_path")
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        require(parts[-1] not in ("", ".", "..") and "/" not in parts[-1], "unsafe_path")
        opened = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        require(stat.S_ISREG(os.fstat(opened).st_mode), "unsafe_file_type")
        with os.fdopen(opened, "rb") as handle:
            opened = None
            yield handle
    except OSError:
        raise EvidenceRefused("unsafe_or_missing_file") from None
    finally:
        if opened is not None:
            os.close(opened)
        os.close(fd)


def unique_pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def read_json(fd, parts):
    with file_at(fd, parts) as handle:
        require(os.fstat(handle.fileno()).st_size <= MAX_FILE, "file_budget_exhausted")
        raw = handle.read(MAX_FILE + 1)
    require(len(raw) <= MAX_FILE, "file_budget_exhausted")
    try:
        obj = json.loads(raw, object_pairs_hook=unique_pairs)
    except (ValueError, UnicodeError, RecursionError):
        raise EvidenceRefused("invalid_json") from None
    require(isinstance(obj, dict))
    return obj, raw


def durable_run(fd, run_id, target, deadline):
    """Read committed modern rows under the journal lock; bounded gzip segments."""
    names = [n for n in os.listdir(fd) if re.fullmatch(r"events\.jsonl\.[1-9][0-9]*\.gz", n)]
    require(len(names) <= 8, "journal_budget_exhausted")
    names.sort(key=lambda n: int(n.split(".")[-2]), reverse=True)
    latest, used = None, 0
    with file_at(fd, ("events.jsonl",)) as live:
        try:
            fcntl.flock(live, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            raise EvidenceRefused("journal_busy") from None
        def scan(handle):
            nonlocal latest, used
            while True:
                require(time.monotonic() < deadline, "reader_timeout")
                line = handle.readline(MAX_FILE + 1)
                if not line:
                    break
                used += len(line)
                require(used <= MAX_JOURNAL and len(line) <= MAX_FILE, "journal_budget_exhausted")
                if not line.endswith(b"\n"):
                    continue
                try:
                    row = json.loads(line)
                except (ValueError, UnicodeError, RecursionError):
                    continue
                if isinstance(row, dict) and row.get("event") in ("deploy_acknowledged", "deploy_superseded"):
                    if row.get("target") == target and (row.get("run_id") == run_id or latest and row.get("ticket") == latest.get("ticket")):
                        raise EvidenceRefused("run_already_resolved")
                if isinstance(row, dict) and row.get("event") == "deploy_run" and row.get("run_id") == run_id:
                    require(row.get("target") == target, "run_identity_mismatch")
                    # Apply emits complete modern rows. Never use compatibility
                    # notifications or reconstruct a partial modern identity.
                    latest = row
        try:
            for name in names:
                with file_at(fd, (name,)) as archived:
                    with gzip.GzipFile(fileobj=archived) as handle:
                        scan(handle)
            scan(live)
        except (OSError, EOFError):
            raise EvidenceRefused("journal_unavailable") from None
    require(latest is not None, "run_unavailable")
    return latest


@dataclass(frozen=True)
class Projection:
    """Immutable trusted bytes; model JSON is not a Projection or authority."""
    payload: bytes
    repository: str = ""  # trusted routing metadata; never supplied by the model
    issue: int | None = None
    deliverable: bool = False

    @property
    def sha256(self):
        return digest(self.payload)

    def data(self):
        return json.loads(self.payload)


def jobs_for(run):
    jobs = []
    for item in (run.get("verification") or {}).get("items", []):
        if item.get("kind") == "nomad_job" and item.get("id"):
            jobs.append((item["id"], item.get("namespace") or "default", item.get("region") or "",
                         (item.get("observed") or {}).get("version")))
    if not jobs:
        jobs = [(j["id"], j.get("namespace") or "default", j.get("region") or "", None)
                for j in run.get("diagnostic_jobs") or []]
    require(len(jobs) <= 8)
    for jid, ns, region, version in jobs:
        require(all(isinstance(v, str) and len(v) <= 256 for v in (jid, ns, region)))
        require(bool(jid) and bool(ns) and (version is None or type(version) is int and 0 <= version <= 2**63 - 1))
    return jobs


def project(bundle, run, now):
    require(bundle.get("version") == 1 and bundle.get("logs_enabled") is False, "logs_not_allowed")
    window = bundle.get("window") or {}
    require(window.get("known") is True, "window_unavailable")
    start, end = timestamp(window.get("start")), timestamp(window.get("end"))
    completed, began = timestamp(run.get("completed_at")), timestamp(run.get("started_at"))
    collected = timestamp(bundle.get("collected_at"))
    require(began <= start <= end <= completed and end == completed and end - start <= MAX_AGE)
    require(end <= collected <= now and now - end <= MAX_AGE, "stale_evidence")
    require(type(bundle.get("dropped_observations")) is int and bundle["dropped_observations"] == 0, "partial_evidence")
    jobs = jobs_for(run)
    observations = bundle.get("observations")
    require(isinstance(observations, list) and len(observations) <= 1024, "row_budget_exhausted")
    rows = []
    allocation_ids = set()
    def add(kind, status, observed, fields):
        require(len(rows) < MAX_ROWS, "row_budget_exhausted")
        rows.append({"ref": f"e{len(rows) + 1:04d}", "kind": kind, "status": status,
                     "observed_at": utc(observed), **fields})
    for row in observations:
        require(isinstance(row, dict))
        status = row.get("status")
        if status not in STATUSES:
            status = "unavailable"
        observed = timestamp(row.get("observed_at"))
        require(end <= observed <= collected, "invalid_observation_time")
        source, lineage, data = row.get("source"), row.get("lineage") or {}, row.get("data")
        require(isinstance(lineage, dict))
        matched = next((j for j in jobs if lineage.get("id") == j[0] and lineage.get("namespace") == j[1]
                        and (lineage.get("region") or "") == j[2] and lineage.get("version") == j[3]), None)
        if not matched:
            continue  # Includes all free text, local logs, dependency payloads.
        jid, ns, region, version = matched
        require(type(lineage.get("version")) is int if type(version) is int else lineage.get("version") is None)
        scope = {"job": alias("job", jid), "namespace": alias("namespace", ns), "version": version}
        prefix = "nomad/job/" + urllib.parse.quote(jid, safe="")
        if source == prefix + "/current":
            if status == "observed":
                require(isinstance(data, dict) and data.get("ID") == jid and data.get("Namespace", "default") == ns)
                require(type(data.get("Version")) is int and data["Version"] >= 0)
                require(data.get("Status") in JOB_STATES)
                add("current_job", status, observed, {**scope, "current_version": data["Version"], "state": data["Status"], "relation": "current_state_only"})
            else:
                add("current_job", status, observed, scope)
        elif source == prefix + "/evaluations":
            if status != "observed":
                add("evaluation", status, observed, scope)
                continue
            require(isinstance(data, list) and len(data) <= 50)
            for value in data:
                require(value.get("JobID") == jid and value.get("Namespace", "default") == ns)
                require(UUID.fullmatch(value.get("ID", "")) and value.get("Status") in EVAL_STATES)
                modified = value.get("ModifyTime")
                require(type(modified) is int and start <= modified / 1e9 <= end)
                metrics = {"nodes_available": 0, "constraints_filtered": 0, "resources_exhausted": 0,
                           "cpu_exhausted": 0, "memory_exhausted": 0, "disk_exhausted": 0}
                failed = value.get("FailedTGAllocs") or {}
                require(isinstance(failed, dict) and len(failed) <= 50)
                for metric in failed.values():
                    require(isinstance(metric, dict))
                    # Nomad exposes NodesAvailable by datacenter, not a scalar.
                    # Retain only its total; arbitrary datacenter names stay private.
                    available = metric.get("NodesAvailable") or {}
                    require(isinstance(available, dict) and len(available) <= 128)
                    for count in available.values():
                        require(number(count))
                        metrics["nodes_available"] += count
                    if "NodesExhausted" in metric:
                        require(number(metric["NodesExhausted"]))
                        metrics["resources_exhausted"] += metric["NodesExhausted"]
                    dimensions = metric.get("DimensionExhausted") or {}
                    require(isinstance(dimensions, dict) and len(dimensions) <= 128)
                    for dimension in ("cpu", "memory", "disk"):
                        if dimension in dimensions:
                            require(number(dimensions[dimension]))
                            metrics[dimension + "_exhausted"] += dimensions[dimension]
                    filters = metric.get("ConstraintFiltered") or {}
                    require(isinstance(filters, dict) and len(filters) <= 128)
                    for count in filters.values():
                        require(number(count))
                        metrics["constraints_filtered"] += count
                add("evaluation", status, observed, {**scope, "evaluation": alias("evaluation", value["ID"]),
                    "state": value["Status"], "event_time": utc(modified / 1e9), "relation": "job_time_window_not_version_proof", **metrics})
        elif source == prefix + "/allocations" or source == prefix + "/deployments":
            kind = "allocation" if source.endswith("/allocations") else "deployment"
            if status != "observed":
                add(kind, status, observed, scope)
                continue
            require(type(version) is int, "version_unavailable")
            require(isinstance(data, list) and len(data) <= 50)
            for value in data:
                require(value.get("JobID") == jid and value.get("Namespace", "default") == ns and value.get("JobVersion") == version)
                require(UUID.fullmatch(value.get("ID", "")) and type(value.get("JobVersion")) is int)
                if kind == "allocation":
                    created, modified = value.get("CreateTime"), value.get("ModifyTime")
                    require(type(created) is int and type(modified) is int
                            and created / 1e9 <= end and modified / 1e9 >= start, "allocation_window_mismatch")
                    allocation_ids.add((value["ID"], jid, ns, version))
                state = value.get("ClientStatus") if kind == "allocation" else value.get("Status")
                require(state in (ALLOC_STATES if kind == "allocation" else DEPLOY_STATES))
                add(kind, status, observed, {**scope, kind: alias(kind, value["ID"]), "state": state, "relation": "recorded_health_version"})
        elif isinstance(source, str) and source.startswith("nomad/allocation/") and source.count("/") == 2:
            aid = source.rsplit("/", 1)[1]
            require(UUID.fullmatch(aid) and lineage.get("allocation") == aid and type(version) is int
                    and (aid, jid, ns, version) in allocation_ids, "allocation_lineage_mismatch")
            if status != "observed":
                add("task", status, observed, scope)
                continue
            require(isinstance(data, dict) and data.get("ID") == aid and data.get("JobID") == jid and data.get("Namespace", "default") == ns)
            tasks = data.get("tasks") or {}
            require(isinstance(tasks, dict) and len(tasks) <= 8)
            for name, task in tasks.items():
                require(isinstance(task, dict) and task.get("State") in {"pending", "running", "dead"})
                events = task.get("Events") or []
                require(isinstance(events, list) and len(events) <= 50)
                for event in events:
                    et = event.get("Time")
                    require(type(et) is int and start <= et / 1e9 <= end)
                    event_type = event.get("Type")
                    if event_type not in EVENT_TYPES:
                        event_type = "Other"
                    fields = {**scope, "allocation": alias("allocation", aid), "task": alias("task", name),
                        "state": task["State"], "event_type": event_type, "event_time": utc(et / 1e9), "relation": "recorded_health_version"}
                    if "OOMKilled" in event:
                        require(type(event["OOMKilled"]) is bool)
                        fields["oom_killed"] = event["OOMKilled"]
                    for key in ("ExitCode", "Signal"):
                        if key in event:
                            require(type(event[key]) is int and 0 <= event[key] <= 65535)
                            fields[key] = event[key]
                    add("task_event", status, observed, fields)
    return {"window": {"start": utc(start), "end": utc(end)}, "rows": rows}


def read_evidence(factory: Path, incident_id: str, run_id: str, *, now=None) -> Projection:
    """Resolve local incident -> committed failed run -> manifest -> bundle.

    Missing, contradictory, stale or oversized evidence fails closed. No file
    creation, locks beyond nonblocking shared journal read, or network access.
    """
    require(isinstance(incident_id, str) and isinstance(run_id, str)
            and incidents.ID_RE.fullmatch(incident_id) and artifacts.RUN_ID_RE.fullmatch(run_id), "invalid_reference")
    now = time.time() if now is None else now
    require(number(now))
    try:
        with directory(factory) as fd:
            incident, _ = read_json(fd, ("incidents", incident_id + ".json"))
            require(incident.get("version") == 1 and incident.get("id") == incident_id)
            target, ticket, repo = incident.get("target"), incident.get("original_ticket"), incident.get("repo")
            require(isinstance(target, str) and artifacts.TARGET_RE.fullmatch(target))
            require(type(ticket) is int and ticket > 0 and isinstance(repo, str)
                    and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo))
            require(incident_id == incidents.identity(repo, target, ticket), "incident_identity_mismatch")
            refs = [r for r in incident.get("runs", []) if r.get("run_id") == run_id]
            require(len(refs) == 1, "incident_run_mismatch")
            ref = refs[0]
            require(ref.get("artifact_ref") == f"artifacts/{target}/{run_id}/manifest.json")
            run = durable_run(fd, run_id, target, time.monotonic() + 5)
            require(run.get("status") == "failed", "not_a_failed_run")
            require(type(run.get("ticket")) is int and run["ticket"] > 0)
            require(HEX.fullmatch(run.get("commit", "")) and ref.get("commit") == run["commit"] and ref.get("ticket") == run.get("ticket"))
            parts = ("artifacts", target, run_id)
            manifest, manifest_raw = read_json(fd, parts + ("manifest.json",))
            for key in ("run_id", "target", "commit", "ticket", "status"):
                require(manifest.get(key) == run.get(key), "manifest_identity_mismatch")
            require(manifest.get("version") == artifacts.MANIFEST_VERSION)
            files = manifest.get("files")
            require(isinstance(files, list) and len(files) <= 16)
            entries = [e for e in files if isinstance(e, dict) and e.get("name") == "diagnostics.json"]
            require(len(entries) == 1, "diagnostics_not_authenticated")
            entry = entries[0]
            require(entry.get("kind") == "diagnostics" and type(entry.get("bytes")) is int)
            bundle, raw = read_json(fd, parts + ("diagnostics.json",))
            require(len(raw) == entry["bytes"] and digest(raw) == entry.get("sha256"), "diagnostics_hash_mismatch")
            for key in ("run_id", "target", "commit"):
                require(bundle.get(key) == run.get(key), "bundle_identity_mismatch")
            projected = project(bundle, run, now)
            result = {"policy_version": POLICY_VERSION, "incident": incident_id, "commit": run["commit"],
                "run": alias("run", run_id), "target": alias("target", target), "ticket": run["ticket"],
                "provenance": {"manifest_sha256": digest(manifest_raw), "bundle_sha256": digest(raw)}, **projected}
            payload = encoded(result)
            require(len(payload) <= MAX_PROJECTION, "projection_budget_exhausted")
            issue = incident.get("issue")
            require(issue is None or type(issue) is int and issue > 0, "invalid_publication_destination")
            return Projection(payload, repo, issue, incident.get("status") == "delivered"
                              and incident.get("uncertain") is False)
    except EvidenceRefused:
        raise
    except Exception:
        raise EvidenceRefused("invalid_evidence") from None
