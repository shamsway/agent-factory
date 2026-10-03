"""Read-only deployment history. Raw journal output is never part of this API."""
from __future__ import annotations

import logging
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

from factory import artifacts, deploy, dispatch

HISTORY_LIMIT = 200


def safe_project(factory: Path, rows: list[dict], secrets: list[str] | None = None) -> dict | None:
    """Keep optional history failures from breaking the rest of the dashboard."""
    try:
        return project(factory, rows, secrets)
    except Exception:
        logging.getLogger(__name__).warning("Deployment history unavailable", exc_info=True)
        return None


def project(factory: Path, rows: list[dict], secrets: list[str] | None = None) -> dict:
    states = deploy.replay_rows(rows)
    transitions: dict[str, list[dict]] = {}
    dispositions = {}
    for row in rows:
        rid = row.get("run_id")
        if not rid:
            continue
        if row.get("event") == "deploy_run":
            transitions.setdefault(rid, []).append({
                "at": row.get("at") or row.get("started_at"),
                "status": row.get("status"), "phase": row.get("phase") or "executing",
            })
        if row.get("event") in ("deploy_acknowledged", "deploy_superseded"):
            dispositions[rid] = row["event"].removeprefix("deploy_")
    runs, targets = [], []
    for target, state in sorted(states.items()):
        safe_target = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
        owned = dispatch.lock_held(factory / "locks" / f"target-{safe_target}.lock")
        targets.append({"target": target, "last_succeeded_commit": state.latest_succeeded_commit,
                        "unresolved_failures": len(state.unacknowledged_failed_tickets),
                        "unfinished": len(state.interrupted_runs), "runner_lock_held": owned})
        for run in state.runs:
            status = run.status.value
            if status == "running":
                status = (run.phase or "executing") if owned else "interrupted"
            status = dispositions.get(run.run_id, status)
            if run.run_id in state.acknowledged_failures and status == "failed":
                status = "acknowledged"
            queue_sec = None
            try:
                if run.queued_at:
                    queue_sec = max(0, (datetime.fromisoformat(run.started_at.replace("Z", "+00:00"))
                                       - datetime.fromisoformat(run.queued_at.replace("Z", "+00:00"))).total_seconds())
            except (AttributeError, ValueError, TypeError):
                pass
            runs.append({
                "run_id": run.run_id, "target": target, "ticket": run.ticket, "pr": run.pr,
                "commit": run.commit, "attempt": run.attempt, "status": status,
                "outcome": run.status.value, "started_at": run.started_at,
                "completed_at": run.completed_at, "execution_sec": run.duration_sec, "queue_sec": queue_sec,
                "verification": run.verification,
                "unresolved": run.ticket in state.unacknowledged_failed_tickets
                              and state.runs_by_ticket[run.ticket][-1].run_id == run.run_id,
                "timeline": transitions.get(run.run_id, []), "artifacts": [],
                "result": None, "publication": {},
            })
    counts = Counter(r["outcome"] for r in runs)
    durations = [r["execution_sec"] for r in runs if r["execution_sec"] is not None]
    queue_times = [r["queue_sec"] for r in runs if r["queue_sec"] is not None]
    denominator = counts["succeeded"] + counts["failed"]
    open_runs = [r for r in runs if r["unresolved"] or r["status"] in
                 ("pending", "executing", "verifying", "interrupted")]
    closed = [r for r in runs if r not in open_runs]
    closed.sort(key=lambda r: r["completed_at"] or r["started_at"] or "", reverse=True)
    visible = open_runs + closed[:HISTORY_LIMIT]
    for run in visible:
        try:
            d = artifacts.artifact_dir(factory, run["target"], run["run_id"])
            manifest = artifacts.read_manifest(d) or {}
            for entry in manifest.get("files", []):
                name = entry.get("name", "")
                if name not in ("summary.json", "apply.log"):
                    continue
                run["artifacts"].append({"name": name, "url": "/api/artifacts/" + "/".join(
                    quote(p, safe="") for p in (run["target"], run["run_id"], name))})
                if name == "summary.json":
                    found = artifacts.lookup(factory, run["target"], run["run_id"], name)
                    if found:
                        import json
                        run["result"] = json.loads(found[0])
            run["publication"] = manifest.get("publications", {})
        except (OSError, ValueError, KeyError, TypeError):
            run["result"] = None
    return artifacts.sanitize_tree({"runs": visible, "targets": targets, "metrics": {
        "recorded_attempts": len(runs), "pending": counts["pending"],
        "successes": counts["succeeded"], "failures": counts["failed"],
        "success_denominator": denominator,
        "success_rate": counts["succeeded"] / denominator if denominator else None,
        "mean_execution_sec": sum(durations) / len(durations) if durations else None,
        "duration_denominator": len(durations),
        "mean_queue_sec": sum(queue_times) / len(queue_times) if queue_times else None,
        "queue_denominator": len(queue_times),
        "queue_scope": "PR merge to attempt start; excludes rows without merge timestamps",
    }, "history": {"total": len(runs), "shown": len(visible),
                    "truncated": len(visible) < len(runs),
                    "scope": "Recorded deployment attempts, including closed tickets"}}, secrets)
