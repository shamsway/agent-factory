"""Fail-closed deployment-incident routing fence; not a worker sandbox.

The legacy worker and its free-form publisher must not handle deployment roots.
A label change, forced ticket, or stale frontier body cannot bypass this fence.
"""
from __future__ import annotations

import os
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
    # Infrastructure repositories may still have unrelated software tickets,
    # but no legacy investigation may start while they own a private store.
    store = factory / "incidents"
    try:
        metadata = store.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        return "incident_routing_unavailable"
    if not stat.S_ISDIR(metadata.st_mode):
        return "incident_routing_unavailable"
    if legacy_investigation:
        return "deployment_incident_requires_isolated_route"
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
