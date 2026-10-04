"""SHA-201 public rendering boundary, independent of investigation logic.

No unrestricted model prose or raw source values are interpolated. A caller in
trusted broker code supplies Projection; model input can supply only the result.
This module performs no GitHub calls. Wiring publication and isolation is a later
review gate; rendering is not itself evidence of a sandboxed investigation.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re

from . import incidents

from .investigation_evidence import (Projection, EvidenceRefused, require, encoded, timestamp, utc,
                                     MAX_PROJECTION, MAX_ROWS, read_evidence, read_incident)

MAX_RESULT = 8192
MAX_PUBLIC = 16384
FINDINGS = {
    "PLACEMENT_CONSTRAINTS": "A recorded evaluation reports filtered placement constraints.",
    "RESOURCE_CPU": "A recorded evaluation reports CPU capacity exhaustion.",
    "RESOURCE_MEMORY": "A recorded evaluation reports memory capacity exhaustion.",
    "RESOURCE_DISK": "A recorded evaluation reports disk capacity exhaustion.",
    "OOM_EVENT": "A recorded allocation task has an explicit OOM event.",
}
ACTIONS = {
    "REVIEW_CONSTRAINTS": ("PLACEMENT_CONSTRAINTS", "Review placement constraints in a gated repository change; verify intended nodes and placement before seeking approval."),
    "REVIEW_CPU": ("RESOURCE_CPU", "Review CPU capacity and reservations in a gated repository change; verify placement and resource headroom before seeking approval."),
    "REVIEW_MEMORY": ("RESOURCE_MEMORY", "Review memory capacity and reservations in a gated repository change; verify placement and resource headroom before seeking approval."),
    "REVIEW_DISK": ("RESOURCE_DISK", "Review disk capacity and reservations in a gated repository change; verify placement and storage headroom before seeking approval."),
    "REVIEW_OOM": ("OOM_EVENT", "Review memory limits and usage in a gated repository change; verify task stability and headroom before seeking approval."),
}
REASONS = {
    "MODEL_FAILED": "The model request failed or returned an invalid answer; human investigation is needed.",
    "INSUFFICIENT": "Evidence is insufficient for a supported proposal.",
    "UNSUPPORTED": "This failure class needs human investigation.",
    "CONTRADICTORY": "Evidence is contradictory and needs human reconciliation.",
    "STALE": "Evidence is stale; a reviewed fresh observation is needed.",
    "BUDGET": "The investigation budget is exhausted; a human must decide the next step.",
}


def supports(code, row):
    if row.get("status") != "observed":
        return False
    if code == "OOM_EVENT":
        return (row.get("kind") == "task_event" and row.get("event_type") == "Terminated" and row.get("oom_killed") is True
                and row.get("relation") == "recorded_health_version")
    if row.get("kind") != "evaluation" or row.get("state") not in ("blocked", "failed"):
        return False
    field = {"PLACEMENT_CONSTRAINTS": "constraints_filtered", "RESOURCE_CPU": "cpu_exhausted",
             "RESOURCE_MEMORY": "memory_exhausted", "RESOURCE_DISK": "disk_exhausted"}.get(code)
    return field is not None and type(row.get(field)) in (int, float) and row[field] > 0


def _render(projection: Projection, raw_result: bytes) -> str:
    """Validate model enums/references against trusted evidence, then render.

    Unknown fields are refused, not ignored. Revisions/hashes prevent stale or
    substituted results. Even escalations cannot carry raw text to GitHub.
    """
    require(type(projection) is Projection and type(raw_result) is bytes, "invalid_result")
    require(len(raw_result) <= MAX_RESULT, "result_budget_exhausted")
    try:
        # Reject duplicate keys, rather than silently accepting the last value.
        def pairs(items):
            result = {}
            for key, value in items:
                require(key not in result, "duplicate_result_key")
                result[key] = value
            return result
        result = json.loads(raw_result, object_pairs_hook=pairs)
    except (ValueError, UnicodeError, RecursionError):
        raise EvidenceRefused("invalid_result") from None
    require(isinstance(result, dict), "invalid_result")
    require(result.get("projection_sha256") == projection.sha256, "stale_result")
    require(len(projection.payload) <= MAX_PROJECTION, "invalid_projection")
    data = projection.data()
    require(encoded(data) == projection.payload, "invalid_projection")
    require(isinstance(data.get("rows"), list) and len(data["rows"]) <= MAX_ROWS, "invalid_projection")
    for index, row in enumerate(data["rows"], 1):
        require(isinstance(row, dict) and row.get("ref") == f"e{index:04d}", "invalid_projection")
        require(timestamp(row.get("observed_at")) >= 0, "invalid_projection")
        if "relation" in row:
            require(row["relation"] in {"current_state_only", "recorded_health_version",
                    "job_time_window_not_version_proof"}, "invalid_projection")
    require(data.get("policy_version") == 1 and re.fullmatch(r"[0-9a-f]{40}", data.get("commit", "")), "invalid_projection")
    rows = {row["ref"]: row for row in data["rows"]}
    require(len(rows) == len(data["rows"]), "invalid_projection")
    lines = ["## Deployment investigation", "", f"Revision: `{data['commit']}`.",
             f"Evidence projection: `{projection.sha256}`; policy version 1.", ""]
    if result.get("outcome") == "escalate":
        require(set(result) == {"projection_sha256", "outcome", "reason"}, "invalid_result")
        require(result.get("reason") in REASONS, "invalid_result")
        lines += [REASONS[result["reason"]], "No repair is proposed or authorized."]
    else:
        require(set(result) == {"projection_sha256", "outcome", "findings", "action"}
                and result.get("outcome") == "proposal", "invalid_result")
        findings = result.get("findings")
        require(isinstance(findings, list) and 1 <= len(findings) <= 8, "invalid_result")
        codes, used = set(), set()
        for finding in findings:
            require(isinstance(finding, dict) and set(finding) == {"code", "refs"}, "invalid_result")
            code, refs = finding.get("code"), finding.get("refs")
            require(isinstance(code, str) and code in FINDINGS and code not in codes, "invalid_result")
            require(isinstance(refs, list) and 1 <= len(refs) <= 8 and all(isinstance(r, str) for r in refs), "invalid_result")
            require(len(set(refs)) == len(refs) and all(r in rows and supports(code, rows[r]) for r in refs), "unsupported_finding")
            codes.add(code)
            used.update(refs)
            lines.append("- " + FINDINGS[code] + " Evidence: " + ", ".join(f"`{r}`" for r in refs) + ".")
        action = result.get("action")
        require(isinstance(action, str) and action in ACTIONS and ACTIONS[action][0] in codes, "unsupported_proposal")
        lines += ["", "### Evidence references"]
        for ref in sorted(used):
            row = rows[ref]
            # Only broker-normalized timestamps, fixed relation and hashed aliases.
            lines.append(f"- `{ref}` observed {utc(timestamp(row['observed_at']))}; relation: `{row['relation']}`.")
        lines += ["", "### Scoped review proposal", ACTIONS[action][1], "",
            "Evaluation evidence is matched by job and time, not proof of an exact deployed revision.",
            "Observed symptoms do not exclude other causes; configuration and dependency causes remain unconfirmed.",
            "Affected source files and concrete edits require a separately validated repository scope before a fix PR.",
            "Validation: normal repository gates, reviewed plan and post-apply health checks.",
            "Risks: incorrect scope or inadequate capacity; resolve missing evidence before changes.",
            "Rollback: preserve the last approved deployment specification and use the existing recovery procedure.",
            "No merge, apply, restart or production write is authorized by these findings."]
    body = "\n".join(lines) + "\n"
    require(len(body.encode()) <= MAX_PUBLIC, "publication_budget_exhausted")
    return body


def render(projection: Projection, raw_result: bytes) -> str:
    try:
        return _render(projection, raw_result)
    except EvidenceRefused:
        raise
    except Exception:
        raise EvidenceRefused("invalid_result") from None


def render_for_incident(factory, incident_id: str, run_id: str, raw_result: bytes, *, now=None) -> str:
    """Preferred trusted entrypoint: reload original evidence at publication time.

    The worker never provides the projection, paths, repo or GitHub destination.
    Callers resolve incident/run from trusted routing, not unrestricted model JSON.
    A changed, stale or resolved input invalidates the prior model result.
    """
    projection = read_evidence(factory, incident_id, run_id, now=now)
    return render(projection, raw_result)


@dataclass(frozen=True)
class Publication:
    repository: str
    issue: int
    idempotency_key: str
    body: str


def prepare_for_incident(factory, repository: str, incident_id: str, run_id: str,
                         raw_result: bytes, *, now=None) -> Publication:
    """Produce a fixed-destination envelope for a future trusted outbox sender.

    Does not post. Destination comes from the local incident, compared to the
    configured repository. No worker-supplied endpoint, credential or body field.
    The sender must deduplicate this key, persist delivery and use its own role.
    """
    projection = read_evidence(factory, incident_id, run_id, now=now)
    require(projection.repository == repository and projection.issue is not None and projection.deliverable,
            "publication_destination_unavailable")
    body = render(projection, raw_result)
    key = "investigation-" + projection.sha256
    return Publication(repository, projection.issue, key, body)


# Codes originate in the trusted reader. Never interpolate an exception message
# or accept unrestricted model prose as a refusal code.
REFUSALS = frozenset({
    "invalid_evidence", "invalid_reference", "unsafe_path", "unsafe_or_missing_file",
    "unsafe_file_type", "duplicate_json_key", "invalid_json", "invalid_timestamp",
    "file_budget_exhausted", "journal_budget_exhausted", "reader_timeout",
    "journal_busy", "journal_unavailable", "run_unavailable", "run_already_resolved",
    "run_identity_mismatch", "not_a_failed_run", "incident_identity_mismatch",
    "incident_run_mismatch", "manifest_identity_mismatch", "diagnostics_not_authenticated",
    "diagnostics_hash_mismatch", "bundle_identity_mismatch", "logs_not_allowed",
    "window_unavailable", "stale_evidence", "partial_evidence", "invalid_observation_time",
    "version_unavailable", "allocation_window_mismatch", "allocation_lineage_mismatch",
    "row_budget_exhausted", "projection_budget_exhausted", "invalid_publication_destination",
})


def render_refusal(incident_id: str, refusal_code: str) -> str:
    """Render human escalation without reading refused evidence or a projection."""
    require(isinstance(incident_id, str) and incidents.ID_RE.fullmatch(incident_id), "invalid_reference")
    require(isinstance(refusal_code, str) and refusal_code in REFUSALS, "invalid_refusal_code")
    return ("## Deployment investigation escalated\n\n"
            f"Incident: `{incident_id}`.\n"
            f"Evidence reader refused the input (`{refusal_code}`).\n"
            "A human must inspect the private incident and reconcile or refresh evidence.\n"
            "No diagnosis or repair is proposed or authorized. Raw evidence is not published.\n")


def prepare_refusal(factory, repository: str, incident_id: str, refusal_code: str) -> Publication:
    """Route escalation using only validated incident metadata, never the bundle.

    If routing itself is unavailable, refuse posting; the future outbox must
    retain a local operator-visible failure. No worker-selected destination.
    """
    body = render_refusal(incident_id, refusal_code)
    incident = read_incident(factory, incident_id)
    issue = incident.get("issue")
    require(incident.get("repo") == repository and type(issue) is int and issue > 0
            and incident.get("status") == "delivered" and incident.get("uncertain") is False,
            "publication_destination_unavailable")
    return Publication(repository, issue, f"investigation-refused-{incident_id}-{refusal_code}", body)
