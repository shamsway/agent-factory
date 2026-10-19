"""Retention for finished tickets' worktrees (`factory prune-worktrees`).

`dispatch.cleanup_after_merge` removes a ticket's worktree when the merge stage lands
its PR. Every other ending leaves `.factory/wt-<n>` behind: a PR a human merged or
closed, an escalated ticket closed by hand, a merge whose handoff retention was
incomplete. This sweep removes those once nothing can be lost:

- finished: no open PR on `agent/<n>`, no held ticket lock, and the issue is closed,
  or open but unassigned, outside every active lane and with a merged or closed PR;
- clean: no uncommitted or untracked change outside the ignored scratch
  (`.factory/`, `.factory-prompt.md`); a dirty worktree is always kept;
- nothing local only: the worktree's head is in the merged or closed PR's head,
  `origin/agent/<n>` or `origin/<main>`, or on the local `agent/<n>` branch, which
  is then kept;
- evidence first: an accepted handoff is retained under `.factory/results/` (the
  dispatcher's `retain_handoff`) and removal waits for a cleanup-safe answer; an
  unaccepted handoff that `factory score` still has to read keeps the worktree.
  Transcripts (`.factory/transcripts/<n>`) and logs already live outside it.

The local `agent/<n>` branch is deleted (compare-and-swap on its tip) only when its tip
is pushed, as `cleanup_after_merge` deletes it after a merge; otherwise it stays.
Removals are journaled as `worktree-removed`, stale worktrees kept for safety as
`worktree-kept` (at most once a day per ticket and reason): metadata only.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import subprocess
from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from pathlib import Path

from factory import config, dispatch, gitguard, lifecycle

AUTO_LIMIT = 5  # finished candidates read from GitHub per dispatcher pass
SCAN_CAP = 200  # finished candidates one explicit run reads from GitHub
DOCTOR_CAP = 50  # ... and one `factory doctor`
LIST_CAP = 1000  # open issues/PRs prefetched to skip in-flight tickets cheaply
SIZE_ENTRY_CAP = 20_000  # directory entries walked to size one worktree
KEPT_JOURNAL_INTERVAL = timedelta(hours=24)
ACTIVE_LANES = frozenset({
    config.LABEL_VIABILITY, config.LABEL_REVIEW, config.LABEL_TRIAGE, config.LABEL_INFO,
    config.LABEL_AGENT, config.LABEL_INVESTIGATE, config.LABEL_HUMAN, config.LABEL_APPROVED,
    config.LABEL_WONTFIX,
})
SCRATCH = (":(exclude).factory-prompt.md", ":(exclude).factory")
_WT = re.compile(r"wt-([1-9][0-9]{0,18})\Z")
_SHA = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
_GH_ERRORS = (subprocess.CalledProcessError, ValueError, KeyError, TypeError, OSError)


def _git(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    # No optional locks: a dry run's `git status` must not refresh any index either.
    env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0"}
    return dispatch.run(["git", *args], cwd=cwd or dispatch.ROOT, check=False, env=env)


def _oid(ref: str, cwd: Path | None = None) -> str | None:
    out = _git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}", cwd=cwd).stdout.strip()
    return out if _SHA.fullmatch(out) else None


def _contains(commit: str, ref: str | None) -> bool:
    return bool(ref) and _git("merge-base", "--is-ancestor", commit, ref).returncode == 0


def worktrees(factory: Path) -> list[tuple[int, Path]]:
    """Ticket worktrees `wt-<n>` under `factory`, by ticket number."""
    try:
        with os.scandir(factory) as entries:
            found = [(int(m[1]), Path(e.path)) for e in entries if (m := _WT.fullmatch(e.name))]
    except OSError:
        return []
    return sorted(found)


def size(path: Path, cap: int = SIZE_ENTRY_CAP) -> tuple[int, bool]:
    """(bytes, truncated): apparent size of `path`, never following symlinks, at most `cap` entries."""
    total, seen = 0, 0
    for dirpath, dirnames, filenames in os.walk(path):
        for name in dirnames + filenames:
            seen += 1
            if seen > cap:
                return total, True
            try:
                total += os.lstat(os.path.join(dirpath, name)).st_size
            except OSError:
                pass
    return total, False


def human_size(value: int | None, truncated: bool = False) -> str:
    if value is None:
        return "-"
    amount, unit = float(value), "B"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB":
            break
        amount /= 1024
    text = f"{int(amount)} B" if unit == "B" else f"{amount:.1f} {unit}"
    return (">=" if truncated else "") + text


def _local(n: int, wt: Path) -> dict:
    """The worktree's own state, read through gitguard's pinned paths."""
    if wt.is_symlink() or not wt.is_dir():
        return {"error": "unsafe", "detail": "not a real directory; inspect by hand"}
    if gitguard.admin_dir(dispatch.ROOT, wt) is None:
        return {"error": "unregistered", "detail": "not a registered git worktree; inspect by hand"}
    head = _oid("HEAD", cwd=wt)
    if head is None:
        return {"error": "unreadable", "detail": "worktree head is unreadable"}
    status = _git("status", "--porcelain", "--untracked-files=all", "--", ".", *SCRATCH, cwd=wt)
    if status.returncode != 0:
        return {"error": "unreadable", "detail": "worktree status is unreadable"}
    return {"head": head, "changes": sum(1 for line in status.stdout.splitlines() if line.strip())}


def _scored(rows: list[dict]) -> set:
    return {(r.get("ticket"), r.get("attempt"), r.get("transcript")) for r in rows if r.get("event") == "score"}


def unscored_attempts(rows: list[dict], n: int, root: Path) -> int:
    """Attempts `factory score` would still score by reading this ticket's handoff."""
    if not any(r.get("event") in ("merged", "escalate") and r.get("ticket") == n for r in rows):
        return 0
    scored = _scored(rows)
    pending = {
        (n, r["attempt"], r["transcript"]) for r in rows
        if r.get("event") == "attempt" and r.get("ticket") == n and type(r.get("attempt")) is int
        and isinstance(r.get("transcript"), str) and (root / r["transcript"]).is_file()
    }
    return len(pending - scored)


def accepted_head(rows: list[dict], n: int) -> str | None:
    """Head of the ticket's newest durable approval, the head `results.retain` binds to."""
    for r in reversed(rows):
        if r.get("event") == "approved" and r.get("ticket") == n and isinstance(r.get("head"), str):
            return r["head"]
    return None


def _claimed(issue: dict) -> str | None:
    """Why an open issue is in flight on its own: assigned (claimed) or in an active lane."""
    if issue.get("assignees"):
        return "issue open and assigned"
    lanes = sorted({label.get("name") for label in issue.get("labels", [])} & ACTIVE_LANES)
    return "issue open in lane " + ", ".join(lanes) if lanes else None


def _in_flight(issue: dict, prs: list[dict]) -> str | None:
    """Why an issue/PR pair is still in flight, or None when the ticket is finished."""
    if any(pr.get("state") == "OPEN" for pr in prs):
        return "open PR #" + str(next(pr["number"] for pr in prs if pr.get("state") == "OPEN"))
    if str(issue.get("state", "")).upper() == "CLOSED":
        return None
    if why := _claimed(issue):
        return why
    return None if prs else "issue open with no merged or closed PR"


def _decision(n: int, wt: Path, **fields: object) -> dict:
    return {"ticket": n, "path": f"{dispatch.FACTORY.name}/{wt.name}", "bytes": None, "truncated": False,
            "stale": False, "action": "keep", "code": None, "reason": "", **fields}


def assess(n: int, wt: Path, issue: dict, prs: list[dict], rows: list[dict]) -> dict:
    """One worktree's decision from its GitHub state, its local state and the journal."""
    if why := _in_flight(issue, prs):
        return _decision(n, wt, code="in_flight", reason=f"in flight: {why}")
    closed = [pr for pr in prs if pr.get("state") in ("MERGED", "CLOSED")]
    done = (", ".join(f"PR #{pr['number']} {pr['state'].lower()}" for pr in closed) or "no PR") + (
        ", issue closed" if str(issue.get("state", "")).upper() == "CLOSED" else ", issue open outside every lane")
    base = {"stale": True, "pr": [pr["number"] for pr in closed], "issue_state": str(issue.get("state", "")).upper()}
    local = _local(n, wt)
    if "error" in local:
        return _decision(n, wt, **base, code=local["error"], reason=f"{done}; {local['detail']}")
    head = local["head"]
    remote_heads = [pr.get("headRefOid") for pr in closed if _SHA.fullmatch(str(pr.get("headRefOid")))]
    pushed_refs = [*remote_heads, _oid(f"refs/remotes/origin/agent/{n}"), _oid(f"refs/remotes/origin/{dispatch.cfg.main}")]

    def pushed(commit: str) -> bool:
        return any(_contains(commit, ref) for ref in pushed_refs)

    head_pushed = pushed(head)
    base.update(head=head)
    if local["changes"]:
        return _decision(n, wt, **base, code="dirty", reason=(
            f"{done}; dirty: {local['changes']} uncommitted or untracked path(s) outside the ignored scratch; "
            f"head {head[:12]} {'pushed' if head_pushed else 'not pushed'}"))
    tip = _oid(f"refs/heads/agent/{n}")
    on_branch = _contains(head, tip)
    if not head_pushed and not on_branch:
        return _decision(n, wt, **base, code="unpushed", reason=(
            f"{done}; head {head[:12]} is on no remote ref and not on agent/{n}"))
    handoff = wt / ".factory" / f"handoff-{n}.md"
    accepted = accepted_head(rows, n) if handoff.is_file() else None
    if handoff.is_file() and accepted is None and (pending := unscored_attempts(rows, n, dispatch.ROOT)):
        return _decision(n, wt, **base, code="evidence", reason=(
            f"{done}; {pending} unscored attempt(s) read this worktree's handoff; run `factory score` first"))
    branch = None if tip is None else ("delete" if pushed(tip) else "keep")
    notes = [done, "clean", f"head {head[:12]} " + ("pushed" if head_pushed else f"kept on agent/{n}")]
    if accepted:
        notes.append(f"accepted handoff (head {accepted[:12]}) retained before removal")
    if branch:
        notes.append(f"branch agent/{n}: {'delete (tip pushed)' if branch == 'delete' else 'keep (tip not pushed)'}")
    return _decision(n, wt, **base, action="remove", code="finished", reason="; ".join(notes),
                     branch=branch, branch_tip=tip, retain_head=accepted)


def _github(n: int) -> tuple[dict, list[dict]]:
    issue = dispatch.gh_json(["issue", "view", str(n), "--repo", dispatch.REPO,
                              "--json", "number,state,labels,assignees"])
    prs = dispatch.gh_json(["pr", "list", "--repo", dispatch.REPO, "--head", f"agent/{n}", "--state", "all",
                            "--json", "number,state,headRefOid"])
    if not isinstance(issue, dict) or not isinstance(prs, list):
        raise TypeError("unexpected GitHub response")
    return issue, prs


def _open_work() -> tuple[dict[int, dict], set[int]]:
    """Open issues by number and tickets with an open `agent/<n>` PR: one read each."""
    issues = dispatch.gh_json(["issue", "list", "--repo", dispatch.REPO, "--state", "open",
                               "--limit", str(LIST_CAP), "--json", "number,labels,assignees"])
    prs = dispatch.gh_json(["pr", "list", "--repo", dispatch.REPO, "--state", "open",
                            "--limit", str(LIST_CAP), "--json", "number,headRefName"])
    open_prs = {int(m[1]) for pr in prs if (m := re.fullmatch(r"agent/(\d+)", pr.get("headRefName", "")))}
    return {i["number"]: {**i, "state": "OPEN"} for i in issues}, open_prs


def _last_kept(rows: list[dict]) -> dict[int, dict]:
    return {r["ticket"]: r for r in rows if r.get("event") == "worktree-kept" and type(r.get("ticket")) is int}


def plan(limit: int = SCAN_CAP, rows: list[dict] | None = None, sizes: bool = True) -> dict:
    """Read-only decisions for at most `limit` finished candidates (in-flight ones cost nothing)."""
    rows = lifecycle.read_events(dispatch.EVENTS) if rows is None else rows
    out = {"worktrees": 0, "decisions": [], "unchecked": 0, "error": None}
    found = worktrees(dispatch.FACTORY)
    out["worktrees"] = len(found)
    if not found:
        return out
    try:
        open_issues, open_prs = _open_work()
    except _GH_ERRORS as exc:
        out["error"] = f"GitHub unavailable ({type(exc).__name__})"
        out["unchecked"] = len(found)
        return out
    kept = _last_kept(rows)
    candidates = []
    for n, wt in found:
        if dispatch.lock_held(dispatch.FACTORY / "locks" / f"{n}.lock"):
            out["decisions"].append(_decision(n, wt, code="in_flight", reason="in flight: ticket lock held"))
        elif n in open_prs:
            out["decisions"].append(_decision(n, wt, code="in_flight", reason="in flight: open PR"))
        elif n in open_issues and (why := _claimed(open_issues[n])):
            out["decisions"].append(_decision(n, wt, code="in_flight", reason=f"in flight: {why}"))
        else:
            candidates.append((n, wt))
    # Least recently reported first, so tickets kept for safety never starve newer ones.
    candidates.sort(key=lambda item: (str(kept.get(item[0], {}).get("at", "")), item[0]))
    out["unchecked"] = max(0, len(candidates) - limit)
    for n, wt in candidates[:limit]:
        try:
            issue, prs = _github(n)
            decision = assess(n, wt, issue, prs, rows)
        except _GH_ERRORS as exc:
            decision = _decision(n, wt, code="unchecked", reason=f"GitHub state unavailable ({type(exc).__name__})")
        if sizes and decision["stale"]:
            decision["bytes"], decision["truncated"] = size(wt)
        out["decisions"].append(decision)
    out["decisions"].sort(key=lambda d: d["ticket"])
    return out


def _try_lock(stack: ExitStack, path: Path) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = stack.enter_context(path.open("a"))
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return False
    stack.callback(fcntl.flock, handle, fcntl.LOCK_UN)
    return True


def _remove(decision: dict, rows: list[dict]) -> dict:
    """Remove one planned worktree under its ticket lock, rechecking what the plan read."""
    n = decision["ticket"]
    wt = dispatch.FACTORY / f"wt-{n}"
    with ExitStack() as stack:
        if not _try_lock(stack, dispatch.ticket_lock(n)):
            return {**decision, "action": "keep", "stale": False, "code": "in_flight",
                    "reason": "in flight: ticket lock taken since the plan"}
        local = _local(n, wt)
        if local.get("head") != decision["head"] or local.get("changes"):
            return {**decision, "action": "keep", "code": "changed",
                    "reason": "worktree changed since the plan; next pass re-reads it"}
        if decision.get("retain_head") and not dispatch.retain_handoff(n, decision["retain_head"]):
            return {**decision, "action": "keep", "code": "retention_incomplete",
                    "reason": "accepted handoff retention incomplete (see its result-retention row)"}
        if decision["bytes"] is None:
            decision["bytes"], decision["truncated"] = size(wt)
        # The clean check above excludes only the ignored scratch, which --force also drops.
        removed = _git("worktree", "remove", "--force", str(wt))
        if removed.returncode != 0:
            return {**decision, "action": "keep", "code": "remove_failed",
                    "reason": "git worktree remove failed: " + (removed.stderr.strip().splitlines() or ["?"])[-1]}
        branch = decision.get("branch")
        if branch == "delete":
            deleted = _git("update-ref", "-d", f"refs/heads/agent/{n}", decision["branch_tip"])
            branch = "deleted" if deleted.returncode == 0 else "kept"
        dispatch.record(
            "worktree-removed", ticket=n, path=decision["path"], head=decision["head"],
            branch=branch, pr=decision.get("pr"), issue_state=decision.get("issue_state"),
            bytes=decision["bytes"], bytes_truncated=decision["truncated"],
            retained_head=decision.get("retain_head"),
        )
        return {**decision, "action": "removed", "branch": branch}


def _journal_kept(decision: dict, last: dict | None) -> None:
    if last and last.get("code") == decision["code"]:
        try:
            at = datetime.fromisoformat(str(last.get("at")))
        except ValueError:
            at = None
        if at is not None and datetime.now(UTC) - at < KEPT_JOURNAL_INTERVAL:
            return
    dispatch.record("worktree-kept", ticket=decision["ticket"], path=decision["path"],
                    code=decision["code"], head=decision.get("head"), bytes=decision["bytes"])


def sweep(dry_run: bool, limit: int = SCAN_CAP, sizes: bool = True) -> dict:
    """Plan, then (unless `dry_run`) remove under the merge lock; never two sweeps at once."""
    with ExitStack() as stack:
        if not dry_run and not _try_lock(stack, dispatch.FACTORY / "locks" / "merge.lock"):
            return {"dry_run": dry_run, "worktrees": 0, "decisions": [], "unchecked": 0,
                    "error": "merge lock held by another dispatcher; nothing removed"}
        rows = lifecycle.read_events(dispatch.EVENTS)
        result = {"dry_run": dry_run, **plan(limit, rows, sizes=sizes)}
        if dry_run:
            return result
        kept, done = _last_kept(rows), []
        for decision in result["decisions"]:
            if decision["action"] == "remove":
                decision = _remove(decision, rows)
            if decision["action"] == "keep" and decision["stale"]:
                _journal_kept(decision, kept.get(decision["ticket"]))
            done.append(decision)
        result["decisions"] = done
        if any(d["action"] == "removed" for d in done):
            _git("worktree", "prune")
        return result


def counts(result: dict) -> dict:
    decisions = result["decisions"]
    return {
        "removable": sum(d["action"] in ("remove", "removed") for d in decisions),
        "kept": sum(d["action"] == "keep" and d["stale"] for d in decisions),
        "in_flight": sum(d["code"] == "in_flight" for d in decisions),
        "unchecked": result["unchecked"] + sum(d["code"] == "unchecked" for d in decisions),
    }


def dispatcher_pass(dry_run: bool) -> None:
    """End of a dispatcher pass: at most AUTO_LIMIT finished candidates; never fails the pass."""
    try:
        result = sweep(dry_run, AUTO_LIMIT, sizes=False)
    except Exception as exc:  # noqa: BLE001 - housekeeping never fails the dispatcher pass
        dispatch.log(f"worktree retention: failed ({type(exc).__name__}: {exc})")
        return
    if result["error"]:
        dispatch.log(f"worktree retention: {result['error']}")
    for d in result["decisions"]:
        if d["action"] == "removed":
            dispatch.log(f"#{d['ticket']}: removed finished worktree {d['path']} ({d['reason']})")
        elif d["action"] == "remove":
            dispatch.log(f"#{d['ticket']}: would remove finished worktree {d['path']} ({d['reason']})")
        elif d["stale"]:
            dispatch.log(f"#{d['ticket']}: stale worktree {d['path']} kept ({d['reason']})")


def doctor_row(cfg: config.Config) -> tuple[bool | None, str]:
    """(PASS True / WARN None, detail) for `factory doctor`: a read-only plan, never a FAIL."""
    dispatch.configure(cfg)
    result = {"dry_run": True, **plan(DOCTOR_CAP, sizes=False)}
    c = counts(result)
    if not result["worktrees"]:
        return True, "no ticket worktrees"
    kept = [d for d in result["decisions"] if d["action"] == "keep" and d["stale"]]
    parts = [f"{c['removable']} removable (factory prune-worktrees --dry-run)"]
    parts.append(f"{c['kept']} stale but kept"
                 + (": " + ", ".join(f"#{d['ticket']} {d['code']}" for d in kept[:10]) if kept else ""))
    if c["unchecked"] or result["error"]:
        parts.append(f"{c['unchecked']} unchecked" + (f" ({result['error']})" if result["error"] else ""))
    warn = c["removable"] or c["kept"] or c["unchecked"]
    return (None if warn else True), "; ".join(parts) + f"; {c['in_flight']} in flight"


def _label(d: dict, dry_run: bool) -> str:
    if d["action"] == "removed":
        return "removed"
    if d["action"] == "remove":
        return "would remove" if dry_run else "remove"
    return "keep (stale)" if d["stale"] else "keep"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="factory prune-worktrees",
        description="Remove finished tickets' clean, pushed worktrees after retaining their evidence.")
    parser.add_argument("--dry-run", action="store_true", help="list decisions and reasons; change nothing")
    parser.add_argument("--json", action="store_true", help="print one JSON object instead of text")
    parser.add_argument("--limit", type=int, default=SCAN_CAP,
                        help=f"finished candidates to read from GitHub (default {SCAN_CAP})")
    args = parser.parse_args(argv)
    if args.limit < 1:
        parser.error("--limit must be at least 1")
    cfg = config.load()
    dispatch.configure(cfg)
    result = sweep(args.dry_run, args.limit)
    summary = counts(result)
    failed = bool(result["error"]) or any(d["code"] == "remove_failed" for d in result["decisions"])
    if args.json:
        print(json.dumps({"ok": not failed, **result, "summary": summary}, indent=2))
        return int(failed)
    mode = " (dry run: nothing is changed)" if args.dry_run else ""
    print(f"factory prune-worktrees{mode}: {result['worktrees']} ticket worktree(s) under {cfg.factory}")
    for d in result["decisions"]:
        print(f"  {_label(d, args.dry_run):<13} #{d['ticket']:<6} {d['path']:<20} "
              f"{human_size(d['bytes'], d['truncated']):>11}  {d['reason']}")
    if result["error"]:
        print(f"  error: {result['error']}")
    print(f"summary: {summary['removable']} {'to remove' if args.dry_run else 'removed'}, "
          f"{summary['kept']} stale but kept, {summary['in_flight']} in flight, "
          f"{summary['unchecked']} unchecked")
    return int(failed)
