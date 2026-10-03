"""Conservative private-plan retention, serialized by the caller's apply lock."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from factory import artifacts, config, deploy, lifecycle

KEEP_RUNS = 10


def prune(factory: Path, *, keep: int = KEEP_RUNS, dry_run: bool = False) -> dict:
    """Keep recent terminal runs per target and every unresolved/unknown run.

    Caller must hold apply.lock. Never follow private-store symlinks. A corrupt
    or unreadable journal fails before deletion; rows absent from retained
    history are unknown and therefore retained.
    """
    if keep < 1:
        raise ValueError("private retention must keep at least one run")
    root = factory / "private"
    result = {
        "keep_per_target": keep,
        "dry_run": dry_run,
        "removed": [],
        "retained": [],
        "errors": [],
    }
    if not root.exists():
        return result
    if root.is_symlink() or not root.is_dir():
        raise ValueError("private store must be a real directory")
    rows = lifecycle.read_events(factory / "events.jsonl")
    for row in rows:
        if row.get("event") == "deploy_run":
            # Replay tolerates malformed rows for observation; pruning must not
            # mistake a malformed newer record for a resolved old one.
            deploy.DeployRun.from_dict(
                {k: v for k, v in row.items() if k not in ("event", "at")}
            )
    states = deploy.replay_rows(rows)
    protected, eligible, owners = set(), set(), {}
    for target, state in states.items():
        terminal = [r for r in state.runs if r.is_terminal()]
        protected.update(r.run_id for r in terminal[-keep:])
        for run in state.runs:
            owners.setdefault(run.run_id, set()).add(target)
            if not run.is_terminal() or (
                run.status == deploy.DeployStatus.FAILED
                and run.run_id not in state.acknowledged_failures
            ):
                protected.add(run.run_id)
            else:
                eligible.add(run.run_id)
    for entry in sorted(root.iterdir()):
        rid = entry.name
        allowed = (
            artifacts.RUN_ID_RE.fullmatch(rid)
            and entry.is_dir()
            and not entry.is_symlink()
            and rid in eligible
            and rid not in protected
            and len(owners.get(rid, ())) == 1
        )
        if not allowed:
            result["retained"].append(rid)
            continue
        if not dry_run:
            # fd-based rmtree refuses substituted symlink directories and does
            # not follow nested symlinks. Refuse deletion on unsafe platforms.
            if not shutil.rmtree.avoids_symlink_attacks:
                raise RuntimeError("safe private-store deletion unavailable")
            try:
                shutil.rmtree(entry)
            except OSError:
                result["errors"].append(rid)
                continue
        result["removed"].append(rid)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="factory prune-private")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--keep", type=int, default=KEEP_RUNS)
    args = parser.parse_args(argv)
    cfg = config.load()
    acquired, handle = deploy.acquire_apply_lock(cfg.factory)
    if not acquired:
        print(json.dumps({"ok": False, "error": "apply lock busy"}))
        return 1
    try:
        result = prune(cfg.factory, keep=args.keep, dry_run=args.dry_run)
        print(json.dumps({"ok": not result["errors"], **result}))
        return bool(result["errors"])
    finally:
        deploy.release_lock(handle)
