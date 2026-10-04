"""Fail-closed deployment-incident routing fence; not a worker sandbox.

The legacy worker and its free-form publisher must not handle deployment roots.
A label change, forced ticket, or stale frontier body cannot bypass this fence.
"""
from __future__ import annotations

import os
import re
import stat
import time

from . import config, incidents
from .investigation_evidence import directory, read_incident, EvidenceRefused


def inventory(factory):
    """Read-only bounded identity scan. Incident records are not pruned.

    No fixed record-count cap: stream directory entries under the time budget,
    retaining only issue numbers. Refuse incomplete/unsafe identity lookup.
    """
    store = factory / "incidents"
    count, issues = 0, set()
    try:
        try:
            metadata = store.lstat()
        except FileNotFoundError:
            return {"status": "observed", "count": 0, "issues": issues}
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError()
        deadline = time.monotonic() + 2
        with directory(store) as fd, os.scandir(fd) as entries:
            for entry in entries:
                if time.monotonic() >= deadline:
                    return {"status": "unavailable", "reason": "scan_timeout", "count": count, "issues": set()}
                if not entry.name.endswith(".json"):
                    continue
                incident_id = entry.name[:-5]
                if not incidents.ID_RE.fullmatch(incident_id):
                    raise ValueError()
                row = read_incident(factory, incident_id)
                count += 1
                if row.get("issue") is not None:
                    if type(row["issue"]) is not int or row["issue"] <= 0:
                        raise ValueError()
                    issues.add(row["issue"])
        return {"status": "observed", "count": count, "issues": issues}
    except (EvidenceRefused, OSError, ValueError):
        return {"status": "unavailable", "reason": "identity_scan_unavailable", "count": count, "issues": set()}


def blocked(factory, issue):
    if not isinstance(issue, dict) or type(issue.get("number")) is not int:
        return "incident_routing_unavailable"
    body = issue.get("body") or ""
    if not isinstance(body, str) or "<!-- factory-incident:" in body:
        return "deployment_incident_requires_isolated_route"
    rows = inventory(factory)
    if rows["status"] != "observed":
        return "incident_routing_unavailable"
    return "deployment_incident_requires_isolated_route" if issue["number"] in rows["issues"] else None


def note_availability(cfg, available, record):
    """One durable audit attempt per repository-wide availability transition.

    Persist before the journal attempt. A failed/interrupted attempt is visible
    as audit=uncertain and never repeated blindly. No private path/error text.
    """
    import fcntl
    from .investigation_evidence import read_json
    factory = cfg.factory.resolve()
    root = factory / "routing-handoffs"
    if available and not root.exists():
        return False
    with directory(factory) as parent:
        try:
            os.mkdir("routing-handoffs", mode=0o700, dir_fd=parent)
        except FileExistsError:
            pass
    with directory(root) as fd:
        lock = os.open("routing-state.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=fd)
        try:
            if not stat.S_ISREG(os.fstat(lock).st_mode):
                raise ValueError("unsafe routing lock")
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            path = root / "routing-state.json"
            if path.exists() or path.is_symlink():
                state, _ = read_json(fd, (path.name,))
                if state.get("repo") != cfg.repo or type(state.get("active")) is not bool:
                    raise ValueError("invalid routing state")
            else:
                state = {"active": False}
            active = not available
            if state["active"] == active:
                return False
            state = {"version": 1, "repo": cfg.repo, "active": active, "at": incidents.now(), "audit": "uncertain"}
            incidents.write(path, state)
            record("incident-routing-unavailable" if active else "incident-routing-recovered",
                   reason="incident_routing_unavailable" if active else "identity_scan_available")
            state["audit"] = "recorded"
            incidents.write(path, state)
            return True
        finally:
            os.close(lock)


def snapshot(factory):
    """Metadata only; observation never writes receipts, journal or provider data."""
    from .investigation_evidence import read_json
    rows = inventory(factory)
    result = {"status": rows["status"], "incident_count": rows["count"],
              "reason": rows.get("reason"), "retention": "not_pruned", "last_transition": None,
              "handoffs": [], "receipt_status": "observed"}
    root = factory / "routing-handoffs"
    try:
        try:
            root.lstat()
        except FileNotFoundError:
            return result
        deadline = time.monotonic() + 2
        with directory(root) as fd, os.scandir(fd) as entries:
            for entry in entries:
                if time.monotonic() > deadline:
                    raise ValueError()
                if entry.name == "routing-state.json":
                    state, _ = read_json(fd, (entry.name,))
                    if type(state.get("active")) is not bool or state.get("audit") not in {"recorded", "uncertain"}:
                        raise ValueError()
                    from .investigation_evidence import timestamp, utc
                    result["last_transition"] = {"active": state["active"], "at": utc(timestamp(state.get("at"))), "audit": state["audit"]}
                elif re.fullmatch(r"[1-9][0-9]*\.json", entry.name):
                    state, _ = read_json(fd, (entry.name,))
                    if state.get("comment") not in {"pending", "uncertain", "confirmed", "failed"}:
                        raise ValueError()
                    issue = state.get("issue")
                    error = state.get("last_error")
                    if type(issue) is not int or str(issue) + ".json" != entry.name or type(state.get("done")) is not bool:
                        raise ValueError()
                    if error is not None and (not isinstance(error, str) or not re.fullmatch(r"HTTP4[0-9]{2}", error)):
                        raise ValueError()
                    result["handoffs"].append({"issue": issue, "comment": state["comment"], "done": state["done"], "last_error": error})
        result["handoffs"].sort(key=lambda r: r["issue"])
    except Exception:
        result["receipt_status"] = "unavailable"
        result["handoffs"] = []
        result["last_transition"] = None
    return result


HANDOFF_BODY = (
    "Deployment incident investigation is paused until the isolated investigator "
    "is installed and accepted. This issue is handed to a human. "
    "No diagnosis, repair, merge or deployment is authorized; private evidence "
    "and legacy worker findings are not published."
)


def handoff(cfg, number, *, remote=None):
    """Durable, serialized fixed handoff. Unknown comment creation never repeats.

    Reconcile by REST marker listing after a lost response. A missing marker
    after uncertainty is not proof that GitHub did not accept the comment.
    Label edits are idempotent and retryable even if comment delivery is uncertain.
    """
    import fcntl
    from .investigation_evidence import read_json
    if type(number) is not int or number <= 0 or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", cfg.repo):
        raise ValueError("invalid routing issue")
    factory = cfg.factory.resolve()
    root = factory / "routing-handoffs"
    with directory(factory) as parent:
        try:
            os.mkdir("routing-handoffs", mode=0o700, dir_fd=parent)
        except FileExistsError:
            pass
    with directory(root) as fd:
        lock = os.open(f"{number}.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=fd)
        try:
            if not stat.S_ISREG(os.fstat(lock).st_mode):
                raise ValueError("unsafe routing lock")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return False
            path = root / f"{number}.json"
            if path.exists() or path.is_symlink():
                state, _ = read_json(fd, (path.name,))
                if (state.get("version") != 1 or state.get("issue") != number or state.get("repo") != cfg.repo
                        or state.get("comment") not in {"pending", "uncertain", "confirmed", "failed"}
                        or type(state.get("done")) is not bool):
                    raise ValueError("invalid routing handoff")
            else:
                state = {"version": 1, "issue": number, "repo": cfg.repo, "comment": "pending", "done": False}
            if state.get("done") is True:
                return False
            remote = remote or incidents.GitHub(cfg)
            endpoint = f"repos/{cfg.repo}/issues/{number}"
            marker = f"<!-- factory-routing-handoff: {number} -->"
            found = False
            for page in range(1, 11):
                rows = remote.api(endpoint + f"/comments?per_page=100&page={page}")
                if not isinstance(rows, list):
                    raise ValueError("invalid routing response")
                if any(marker in (r.get("body") or "") for r in rows):
                    found = True
                    break
                if len(rows) < 100:
                    break
            else:
                raise ValueError("routing comment lookup incomplete")
            if found:
                state["comment"] = "confirmed"
                incidents.write(path, state)
            elif state["comment"] == "pending":
                state["comment"] = "uncertain"
                incidents.write(path, state)  # durable intent before any POST
                try:
                    remote.api(endpoint + "/comments", {"body": marker + "\n" + HANDOFF_BODY}, "POST")
                except incidents.RequestRefused as exc:
                    state["comment"] = "failed"
                    state["last_error"] = f"HTTP{exc.status}"
                    incidents.write(path, state)
                except Exception:
                    pass  # unknown outcome: never repeat POST, still hand to human
                else:
                    state["comment"] = "confirmed"
                    incidents.write(path, state)
            issue = remote.api(endpoint)
            labels = [l["name"] for l in issue.get("labels", [])
                      if l.get("name") not in {config.LABEL_AGENT, config.LABEL_INVESTIGATE}]
            labels = sorted(set(labels) | {config.LABEL_HUMAN})
            remote.api(endpoint, {"labels": labels}, "PATCH")
            state["done"] = True
            incidents.write(path, state)
            return True
        finally:
            os.close(lock)
