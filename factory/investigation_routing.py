"""Fail-closed deployment-incident routing fence; not a worker sandbox.

The legacy worker and its free-form publisher must not handle deployment roots.
A label change, forced ticket, or stale frontier body cannot bypass this fence.
"""
from __future__ import annotations

import os
import re
import stat
import time

from . import incidents
from .investigation_evidence import directory, read_incident, EvidenceRefused


def blocked(factory, issue, *, legacy_investigation=False):
    if not isinstance(issue, dict) or type(issue.get("number")) is not int:
        return "incident_routing_unavailable"
    body = issue.get("body") or ""
    if not isinstance(body, str) or "<!-- factory-incident:" in body:
        return "deployment_incident_requires_isolated_route"
    store = factory / "incidents"
    try:
        metadata = store.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        return "incident_routing_unavailable"
    if not stat.S_ISDIR(metadata.st_mode):
        return "incident_routing_unavailable"
    try:
        deadline = time.monotonic() + 2
        with directory(store) as fd:
            names = os.listdir(fd)
        ids = [name[:-5] for name in names if name.endswith(".json")]
        if len(ids) > 256:
            return "incident_routing_unavailable"
        for incident_id in ids:
            if time.monotonic() >= deadline or not incidents.ID_RE.fullmatch(incident_id):
                return "incident_routing_unavailable"
            row = read_incident(factory, incident_id)
            if row.get("issue") == issue["number"]:
                return "deployment_incident_requires_isolated_route"
    except (EvidenceRefused, OSError):
        return "incident_routing_unavailable"
    return None


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
    Label edits are idempotent and retryable after the comment is confirmed.
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
        lock = os.open(f"{number}.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        try:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return False
            path = root / f"{number}.json"
            if path.exists() or path.is_symlink():
                state, _ = read_json(fd, (path.name,))
                if (state.get("version") != 1 or state.get("issue") != number or state.get("repo") != cfg.repo
                        or state.get("comment") not in {"pending", "uncertain", "confirmed"}
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
                except Exception:
                    pass  # unknown outcome: never repeat POST, still hand to human
                else:
                    state["comment"] = "confirmed"
                    incidents.write(path, state)
            issue = remote.api(endpoint)
            labels = [l["name"] for l in issue.get("labels", [])
                      if l.get("name") not in {"ready-for-agent", "ready-for-investigation"}]
            labels = sorted(set(labels) | {"ready-for-human"})
            remote.api(endpoint, {"labels": labels}, "PATCH")
            state["done"] = True
            incidents.write(path, state)
            return True
        finally:
            os.close(lock)
