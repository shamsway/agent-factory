"""Read-only deployment history. Raw journal output is never part of this API."""
from __future__ import annotations

import fcntl
import gzip
import json
import logging
import os
import re
import threading
from collections import Counter
from datetime import datetime
from pathlib import Path
from urllib.parse import urlencode

from factory import artifacts, deploy, dispatch, lifecycle

HISTORY_LIMIT = 200


# Deployment history spans the whole journal, so it can't come from the
# dashboard's bounded tail window: on a long-lived host every deploy ages out
# of it. These byte markers pre-filter lines before JSON parsing; anything
# project() or deploy.replay_rows() reads carries one of them.
_DEPLOY_MARKERS = (b'"deploy_', b'"applied"', b'"apply-escalate"', b'"run_id"')
_journal_lock = threading.Lock()
_journal_cache: dict[str, dict] = {}


def _deploy_rows(lines) -> list[dict]:
    rows = []
    for line in lines:
        if not line.endswith(b"\n") or not any(marker in line for marker in _DEPLOY_MARKERS):
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict) and (row.get("event") in deploy.REPLAY_EVENTS or row.get("run_id")
                                      or str(row.get("event", "")).startswith("deploy_")):
            rows.append(row)
    return rows


def journal_rows(path: Path) -> list[dict]:
    """Every deployment-related row in the journal (gzip segments and live file),
    oldest first. Segments and the live prefix already read are cached, so a
    refresh parses only appended bytes; rotation or truncation re-reads all."""
    key = str(path)
    with _journal_lock, Path(path).open("rb") as handle:
        fcntl.flock(handle, fcntl.LOCK_SH)
        stat = os.fstat(handle.fileno())
        segments = tuple((n, lifecycle._segment(path, n).stat().st_size) for n in lifecycle._segments(path))
        cache = _journal_cache.get(key)
        if (cache is None or cache["inode"] != stat.st_ino or cache["segments"] != segments
                or stat.st_size < cache["offset"]):
            archived: list[dict] = []
            for n, _size in segments:
                with gzip.open(lifecycle._segment(path, n), "rb") as segment:
                    archived += _deploy_rows(segment)
            cache = {"inode": stat.st_ino, "segments": segments, "offset": 0, "archived": archived, "live": []}
        handle.seek(cache["offset"])
        data = handle.read(max(0, stat.st_size - cache["offset"]))
        end = data.rfind(b"\n") + 1  # a torn final line waits for the next refresh
        cache["live"] += _deploy_rows(data[:end].splitlines(keepends=True))
        cache["offset"] += end
        _journal_cache[key] = cache
        return cache["archived"] + cache["live"]


def safe_project_journal(factory: Path, secrets: list[str] | None = None) -> dict | None:
    """Project the full journal's deployment history; failures never break the dashboard."""
    try:
        return project(factory, journal_rows(factory / "events.jsonl"), secrets)
    except FileNotFoundError:
        return project(factory, [], secrets)
    except Exception:
        logging.getLogger(__name__).warning("Deployment history unavailable", exc_info=True)
        return None


def safe_project(factory: Path, rows: list[dict], secrets: list[str] | None = None) -> dict | None:
    """Keep optional history failures from breaking the rest of the dashboard."""
    try:
        return project(factory, rows, secrets)
    except Exception:
        logging.getLogger(__name__).warning("Deployment history unavailable", exc_info=True)
        return None


def _observations(rows: list[dict]) -> dict:
    """Post-run observations for one run; the latest per kind decides attention."""
    items = [{key: row.get(key) for key in ("at", "kind", "state", "detail", "url", "attention", "final")}
             for row in rows]
    return {"observations": items, "needs_attention": deploy.observation_attention(rows)}


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
    observed = deploy.observations_by_run(rows)
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
                    queue_sec = max(0, (datetime.fromisoformat(run.started_at)
                                       - datetime.fromisoformat(run.queued_at)).total_seconds())
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
                **_observations(observed.get(run.run_id, [])),
            })
    counts = Counter(r["outcome"] for r in runs)
    durations = [r["execution_sec"] for r in runs if r["execution_sec"] is not None]
    queue_times = [r["queue_sec"] for r in runs if r["queue_sec"] is not None]
    denominator = counts["succeeded"] + counts["failed"]
    open_runs = [r for r in runs if r["unresolved"] or r["needs_attention"] or r["status"] in
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
                # The workspace adds the repository scope and fetches with the access key.
                run["artifacts"].append({"name": name, "url": "/api/artifacts?" + urlencode(
                    {"target": run["target"], "run": run["run_id"], "name": name})})
                if name == "summary.json":
                    found = artifacts.lookup(factory, run["target"], run["run_id"], name)
                    if found:
                        import json
                        run["result"] = json.loads(found[0])
            run["publication"] = manifest.get("publications", {})
        except (OSError, ValueError, KeyError, TypeError):
            run["result"] = None
    return artifacts.sanitize_tree({"runs": visible, "targets": targets,
                                    "attention": sum(r["needs_attention"] for r in runs), "metrics": {
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
