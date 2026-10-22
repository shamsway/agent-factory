"""Operator-only investigation run for one real deployment incident.

The supported production entry to `investigation_model.investigate`. Evidence
comes only from `investigation_evidence.read_evidence`; budgets, receipts and the
per-run lock are the model broker's own. The default is a local preview with no
provider call. A live call needs explicit flags and the existing host switches.
This command never publishes: the operator-confirmed export/broker or publish
path stays separate. Journal rows carry identities, hashes, codes and counts only.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import time

from . import config, incidents, lifecycle
from . import investigation_evidence as evidence
from . import investigation_model as model

EVENT = "investigation-run"
MAX_INCIDENTS = 4096
SHA = re.compile(r"[0-9a-f]{64}")

# Fixed refusal codes this command may print or journal. Anything else is withheld.
REFUSALS = frozenset({
    "operator_context_required", "identity_required", "invalid_identity", "incident_not_found",
    "incident_run_ambiguous", "incident_store_unavailable", "repository_mismatch",
    "lineage_unavailable", "configuration_invalid", "model_export_disabled",
    "model_credential_invalid", "provider_spend_cap_ack_required",
    "projection_confirmation_required", "projection_changed", "request_budget",
    "investigation_busy", "state_identity_changed", "retry_flag_required",
    "invalid_state", "unsafe_state", "state_budget", "model_state_unavailable",
    # Fixed evidence-reader codes (investigation_evidence.EvidenceRefused).
    "invalid_reference", "invalid_evidence", "incident_identity_mismatch", "incident_run_mismatch",
    "run_unavailable", "run_identity_mismatch", "run_already_resolved", "not_a_failed_run",
    "manifest_identity_mismatch", "diagnostics_not_authenticated", "diagnostics_hash_mismatch",
    "bundle_identity_mismatch", "logs_not_allowed", "window_unavailable", "stale_evidence",
    "partial_evidence", "row_budget_exhausted", "projection_budget_exhausted",
    "invalid_observation_time", "version_unavailable", "allocation_window_mismatch",
    "allocation_lineage_mismatch", "invalid_timestamp", "invalid_json", "duplicate_json_key",
    "unsafe_path", "unsafe_or_missing_file", "unsafe_file_type", "file_budget_exhausted",
    "journal_busy", "journal_unavailable", "journal_budget_exhausted", "reader_timeout",
    "invalid_publication_destination",
})


class RunRefused(ValueError):
    """Fixed codes only; never evidence, provider, configuration or credential text."""


def operator_context():
    """Mirror the dispatcher boundary: worker and reviewer children inherit lifecycle context.

    This is a routing fence, not OS isolation (see docs/deployment-investigation.md).
    """
    if os.environ.get(lifecycle.CONTEXT_ENV):
        raise RunRefused("operator_context_required")


def resolve(cfg, incident_id=None, run_id=None):
    """Return (incident, run) from local incident records only; no journal or network."""
    if incident_id is None and run_id is None:
        raise RunRefused("identity_required")
    if incident_id is not None and not (isinstance(incident_id, str) and incidents.ID_RE.fullmatch(incident_id)):
        raise RunRefused("invalid_identity")
    if run_id is not None and not (isinstance(run_id, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", run_id)):
        raise RunRefused("invalid_identity")
    if incident_id is not None:
        row = evidence.read_incident(cfg.factory, incident_id)
        if row["repo"] != cfg.repo:
            raise RunRefused("repository_mismatch")
        runs = [r.get("run_id") for r in row.get("runs") or [] if isinstance(r, dict)]
        if run_id is None:
            if not runs:
                raise RunRefused("incident_run_ambiguous")
            run_id = runs[-1]  # The newest correlated run; older ones are usually resolved.
        return incident_id, run_id
    matches = []
    deadline = time.monotonic() + 2
    try:
        with evidence.directory(cfg.factory / "incidents") as fd, os.scandir(fd) as entries:
            for count, entry in enumerate(entries):
                if count >= MAX_INCIDENTS or time.monotonic() > deadline:
                    raise RunRefused("incident_store_unavailable")
                name = entry.name
                if not (name.endswith(".json") and incidents.ID_RE.fullmatch(name[:-5])):
                    continue
                try:
                    row = evidence.read_incident(cfg.factory, name[:-5])
                except evidence.EvidenceRefused:
                    continue  # Unreadable records are reported by `factory incidents`.
                if row["repo"] == cfg.repo and any(isinstance(r, dict) and r.get("run_id") == run_id
                                                   for r in row.get("runs") or []):
                    matches.append(row["id"])
    except evidence.EvidenceRefused:
        raise RunRefused("incident_store_unavailable") from None
    if not matches:
        raise RunRefused("incident_not_found")
    if len(matches) > 1:
        raise RunRefused("incident_run_ambiguous")
    return matches[0], run_id


def assess(state, p, projection, reserved):
    """Classify an existing receipt without changing it."""
    if state is None:
        return "new"
    if (state.get("projection_sha256") != projection.sha256 or state.get("policy_sha256") != model.policy_digest(p)
            or state.get("repository") != projection.repository):
        return "state_identity_changed"
    if state["state"] in {"complete", "failed"}:
        return "cached"
    if state["state"] == "uncertain":
        return "uncertain"
    needed = reserved + p["max_output_tokens"]
    if (state["request_count"] >= min(state["max_requests"], p["max_requests"])
            or state["reserved_input_tokens"] + state["reserved_output_tokens"] + needed
            > min(state["token_budget"], p["token_budget"])
            or state["reserved_seconds"] + p["timeout"] > state["time_budget_sec"]):
        return "budget_exhausted"
    return state["state"]  # "retryable" or "ready" (after an audited operator reset)


def receipt(cfg, incident_id, run_id):
    """Read the model receipt under the broker's own per-run lock."""
    with model._store(cfg.factory, incident_id, run_id) as (fd, name):
        return model._read(fd, name)


def summary(state):
    if state is None:
        return None
    return {"state": state["state"], "code": state["code"], "request_count": state["request_count"],
            "max_requests": state["max_requests"],
            "reserved_tokens": state["reserved_input_tokens"] + state["reserved_output_tokens"],
            "token_budget": state["token_budget"], "reserved_seconds": state["reserved_seconds"],
            "time_budget_sec": state["time_budget_sec"]}


def result_metadata(state):
    """Closed, publisher-validated enums only; never provider text."""
    result = state.get("result") if state and state.get("state") == "complete" else None
    if not isinstance(result, dict):
        return None
    meta = {"outcome": result.get("outcome"), "result_sha256": evidence.digest(evidence.encoded(result))}
    if result.get("outcome") == "proposal":
        meta.update(findings=[f.get("code") for f in result.get("findings", [])], action=result.get("action"))
    else:
        meta["reason"] = result.get("reason")
    return meta


def next_steps(incident_id, run_id, status, projection_sha256=None):
    base = f"--incident {incident_id} --run {run_id}"
    live = f"factory investigation-run {base} --live --confirm-provider-spend-cap --projection-sha256 {projection_sha256}"
    if status == "preview":
        return [live]
    if status in {"complete", "failed"}:
        # Publication is a separate operator-confirmed step; this command never sends.
        return [f"factory investigation-publish {base} --preview",
                f"factory investigation-export {base} --staging-dir STAGING_DIR"]
    if status == "uncertain":
        return [f"factory investigation-reset {base} --reason operator_review --acknowledge-uncertain-spend --dry-run"]
    if status == "retryable":
        return [live + " --retry"]
    return []


def audit(cfg, row):
    """Append one safe metadata row; failure is reported, never fatal to a recorded receipt."""
    try:
        if not cfg.factory.is_dir():
            return "skipped"
        lifecycle.append(cfg.factory / "events.jsonl",
                         {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": EVENT, **row})
        return "recorded"
    except Exception:  # noqa: BLE001 - journal failure must not hide the outcome
        return "failed"


def investigation_run(cfg, incident_id=None, run_id=None, *, live=False, confirm_spend_cap=False,
                      projection_sha256=None, retry=False, client=None, now=None):
    """Preview (default) or explicitly run one bounded model request; never publish.

    Every outcome after the operator-context check is journaled with safe metadata.
    Refusals raise RunRefused/ModelRefused/EvidenceRefused with fixed codes.
    """
    operator_context()
    mode = "live" if live else "preview"
    try:
        incident_id, run_id = resolve(cfg, incident_id, run_id)
        result = _run(cfg, incident_id, run_id, live=live, confirm_spend_cap=confirm_spend_cap,
                      projection_sha256=projection_sha256, retry=retry, client=client, now=now)
    except (RunRefused, model.ModelRefused, evidence.EvidenceRefused) as error:
        code = str(error) if str(error) in REFUSALS else "investigation_run_unavailable"
        audit(cfg, {**safe_identity(incident_id, run_id), "mode": mode, "ok": False, "code": code,
                    "provider_called": False})
        raise
    result["audit"] = audit(cfg, audit_row(result))
    return result


def safe_identity(incident_id, run_id):
    """Only syntactically valid identities enter the journal."""
    return {"incident": incident_id if isinstance(incident_id, str) and incidents.ID_RE.fullmatch(incident_id) else None,
            "run_id": run_id if isinstance(run_id, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", run_id) else None}


def _run(cfg, incident_id, run_id, *, live, confirm_spend_cap, projection_sha256, retry, client, now):
    identity = {"incident": incident_id, "run_id": run_id, "mode": "live" if live else "preview"}
    try:
        p = model.policy(cfg.investigation)
    except config.ConfigError:
        raise RunRefused("configuration_invalid") from None
    if live and not confirm_spend_cap:
        raise RunRefused("provider_spend_cap_ack_required")
    projection = evidence.read_evidence(cfg.factory, incident_id, run_id, now=now)
    if projection.repository != cfg.repo:
        raise RunRefused("repository_mismatch")
    data = projection.data()
    if not data.get("rows"):
        raise RunRefused("lineage_unavailable")  # No observation bound to recorded job lineage.
    content, reserved, payload = model.request(p, projection)
    state = receipt(cfg, incident_id, run_id)
    status = assess(state, p, projection, reserved)
    base = {**identity, "projection_sha256": projection.sha256,
            "manifest_sha256": data["provenance"]["manifest_sha256"],
            "bundle_sha256": data["provenance"]["bundle_sha256"], "rows": len(data["rows"]),
            "public_write": False}
    if not live:
        blocked = None
        if not p["enabled"] or not p["allow_export"]:
            blocked = "model_export_disabled"
        elif model.credential_status(cfg) not in {"configured", "configured_shared"}:
            blocked = "model_credential_invalid"
        elif status in {"state_identity_changed", "budget_exhausted"}:
            blocked = "state_identity_changed" if status == "state_identity_changed" else "request_budget"
        would_call = blocked is None and status in {"new", "retryable", "ready"}
        return {**base, "ok": True, "provider_called": False, "receipt": status,
                "would_call": would_call, "blocked": blocked, "existing": summary(state),
                "result": result_metadata(state),
                "request": {"model": p["model"], "input_bytes": len(content.encode()),
                            "reserved_input_tokens": reserved, "max_output_tokens": p["max_output_tokens"],
                            "token_budget": p["token_budget"], "timeout": p["timeout"],
                            "max_requests": p["max_requests"],
                            "request_sha256": evidence.digest(evidence.encoded(payload))},
                "next": next_steps(incident_id, run_id, "retryable" if status == "retryable" else "preview",
                                   projection.sha256) if would_call
                        else next_steps(incident_id, run_id, state["state"] if state else "", projection.sha256)}
    if not p["enabled"] or not p["allow_export"]:
        raise RunRefused("model_export_disabled")
    if model.credential_status(cfg) not in {"configured", "configured_shared"}:
        raise RunRefused("model_credential_invalid")
    if not isinstance(projection_sha256, str) or not SHA.fullmatch(projection_sha256):
        raise RunRefused("projection_confirmation_required")
    if projection_sha256 != projection.sha256:
        raise RunRefused("projection_changed")
    if status == "state_identity_changed":
        raise RunRefused("state_identity_changed")
    if status == "budget_exhausted":
        raise RunRefused("request_budget")
    if status == "retryable" and not retry:
        raise RunRefused("retry_flag_required")
    calls = []
    if status in {"new", "retryable", "ready"}:
        def counted(policy, request_payload):
            calls.append(True)
            return (client or model.http_call)(policy, request_payload)
        try:
            state = model.investigate(cfg, incident_id, run_id, client=counted, now=now,
                                      expected_projection=projection_sha256)
        except model.ModelRefused as error:
            # A refusal after the provider was called cannot arise in investigate(); keep it honest anyway.
            raise RunRefused(str(error) if str(error) in REFUSALS else "model_state_unavailable") from None
    outcome = "called" if calls else ("uncertain" if state["state"] == "uncertain" else "cached")
    usage = state.get("usage") if state["state"] == "complete" else None
    return {**base, "ok": state["state"] == "complete", "provider_called": bool(calls), "outcome": outcome,
            "state": state["state"], "code": state["code"], "receipt": summary(state),
            "validation_reason": state["attempts"][-1].get("validation_reason", "validation_unavailable"),
            "usage": usage, "result": result_metadata(state),
            "next": next_steps(incident_id, run_id, state["state"], projection.sha256)}


def audit_row(result):
    """Project a command result onto journal-safe metadata only."""
    keys = ("incident", "run_id", "mode", "ok", "code", "outcome", "state", "provider_called",
            "projection_sha256", "manifest_sha256", "bundle_sha256", "rows", "receipt", "would_call",
            "blocked", "validation_reason", "usage")
    row = {k: result[k] for k in keys if k in result}
    if isinstance(result.get("receipt"), dict):
        row["budget"] = row.pop("receipt")
    elif "receipt" in row:
        row["receipt_status"] = row.pop("receipt")
    if isinstance(result.get("existing"), dict):
        row["budget"] = result["existing"]
    if isinstance(result.get("result"), dict):
        row["result_outcome"] = result["result"].get("outcome")
        row["result_sha256"] = result["result"].get("result_sha256")
    return row


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="factory investigation-run",
        description="Operator-only: preview or run one bounded model investigation for a "
                    "deployment incident. Never publishes.")
    parser.add_argument("--incident", help="local incident ID (incident-...)")
    parser.add_argument("--run", help="deployment run ID; defaults to the incident's newest run")
    parser.add_argument("--live", action="store_true", help="send one provider request (default: preview)")
    parser.add_argument("--confirm-provider-spend-cap", action="store_true",
                        help="attest that a provider-side spend cap is configured for the model key")
    parser.add_argument("--projection-sha256", help="projection hash printed by the preview you reviewed")
    parser.add_argument("--retry", action="store_true",
                        help="permit the next attempt for a definite retryable receipt (never an unknown outcome)")
    args = parser.parse_args(argv)
    try:
        operator_context()
        cfg = config.load()
        result = investigation_run(cfg, args.incident, args.run, live=args.live,
                                   confirm_spend_cap=args.confirm_provider_spend_cap,
                                   projection_sha256=args.projection_sha256, retry=args.retry)
        exit_code = 0 if result["ok"] else 1
    except (RunRefused, model.ModelRefused, evidence.EvidenceRefused, config.ConfigError) as error:
        code = "configuration_invalid" if isinstance(error, config.ConfigError) else str(error)
        result = {"ok": False, "code": code if code in REFUSALS else "investigation_run_unavailable"}
        exit_code = 1
    except Exception:  # noqa: BLE001 - withhold raw evidence, provider and state errors
        result, exit_code = {"ok": False, "code": "investigation_run_unavailable"}, 1
    print(json.dumps(result))
    return exit_code
