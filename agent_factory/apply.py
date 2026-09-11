"""`factory apply`: terraform apply for merged, apply-eligible tickets.

Distinct from dispatch's merge stage on purpose: for a repo with
`[apply].enabled = true`, `dispatch.merge_pass_locked` refuses to merge a
factory PR without a genuine human GitHub review approval (not just the
LLM reviewer's `factory-approved` label) -- so the merge itself already is
the human approval gate. This command is what actually runs
`terraform apply`, from a fresh checkout at the merge commit, re-running
the same tf-plan-safety check the gate ran so a human catches live-infra
drift between merge and apply rather than applying blind against a stale
plan.

One pass per invocation, same statelessness as `factory dispatch`. Never
uses the dispatcher's credentials -- only `[apply].env`, which the
dispatcher never sees (see docs/design/sre-fork-implementation-plan.md,
Phase 5).
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from agent_factory import config, dispatch, tf_plan_check
from agent_factory.config import Config

cfg: Config


def configure(c: Config) -> None:
    global cfg
    cfg = c
    dispatch.configure(c)


def log(msg: str) -> None:
    print(f"[apply] {msg}", flush=True)


def applied_tickets() -> set[int]:
    """Ticket numbers with a recorded `applied` event -- never re-apply."""
    if not dispatch.EVENTS.exists():
        return set()
    out = set()
    for line in dispatch.EVENTS.read_text().splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get("event") == "applied" and "ticket" in row:
            out.add(row["ticket"])
    return out


def merged_tickets() -> list[dict]:
    """Merged factory PRs for this repo: [{pr, ticket, commit}], any order."""
    prs = dispatch.gh_json(
        [
            "pr", "list", "--repo", cfg.repo, "--state", "merged",
            "--json", "number,headRefName,mergeCommit",
            "--limit", "100",
        ]
    )
    out = []
    for pr in prs:
        m = re.fullmatch(r"agent/(\d+)", pr["headRefName"])
        if not m or not pr.get("mergeCommit"):
            continue
        out.append({"pr": pr["number"], "ticket": int(m.group(1)), "commit": pr["mergeCommit"]["oid"]})
    return out


def fresh_checkout(commit: str) -> Path:
    """A throwaway worktree at the merge commit -- never the worker's own
    worktree (already removed by `cleanup_after_merge` by the time this
    runs), so apply never inherits anything a worker process touched."""
    wt = cfg.factory / "apply-checkout"
    if wt.is_dir():
        dispatch.run(["git", "worktree", "remove", "--force", str(wt)], cwd=cfg.root, check=False)
    dispatch.run(["git", "fetch", "origin", cfg.main], cwd=cfg.root)
    dispatch.run(["git", "worktree", "add", "--detach", str(wt), commit], cwd=cfg.root)
    return wt


def touches_apply_dir(commit: str) -> bool:
    proc = dispatch.run(
        ["git", "diff", "--name-only", f"{commit}~1", commit, "--", cfg.apply_dir],
        cwd=cfg.root,
        check=False,
    )
    return bool(proc.stdout.strip())


def apply_env() -> dict:
    """Subprocess env for `terraform apply` only: host env + [apply].env.
    Never touched by `factory dispatch`/`factory triage` -- that separation
    is the entire point of the credential boundary."""
    env = dict(os.environ)
    env.update(cfg.apply_env)
    return env


def apply_escalate(n: int, pr: int, reason: str) -> None:
    """Post-merge escalation: the tracking issue is already closed, so this
    only comments + records an event rather than touching labels the way
    `dispatch.escalate` does for in-flight tickets."""
    dispatch.record("apply-escalate", ticket=n, pr=pr, reason=reason)
    dispatch.run(
        [
            "gh", "issue", "comment", str(n), "--repo", cfg.repo,
            "--body", f"`factory apply` did not proceed: {reason}.",
        ],
        check=False,
    )
    log(f"#{n}: apply escalated ({reason})")


def apply_one(ticket: dict, dry_run: bool) -> None:
    n, pr, commit = ticket["ticket"], ticket["pr"], ticket["commit"]
    if not touches_apply_dir(commit):
        log(f"#{n}: PR #{pr} doesn't touch {cfg.apply_dir}; nothing to apply")
        dispatch.record("applied", ticket=n, pr=pr, commit=commit, ok=True, note="no changes under apply dir")
        return

    wt = fresh_checkout(commit)
    tf_dir = wt / cfg.apply_dir
    try:
        planfile = wt / ".factory" / f"apply-plan-{n}"
        planfile.parent.mkdir(parents=True, exist_ok=True)
        proc = tf_plan_check.run_plan(tf_dir, planfile)
        if proc.returncode != 0:
            apply_escalate(n, pr, f"fresh terraform plan failed:\n\n{proc.stdout + proc.stderr}")
            return

        # Re-validate against the *fresh* plan, not the one the gate saw at PR
        # time: this is the freshness check dispatch's git-ancestry check
        # can't provide -- live infra can drift independent of git entirely.
        issue = dispatch.gh_json(["issue", "view", str(n), "--repo", cfg.repo, "--json", "body"])
        plan = tf_plan_check.show_json(tf_dir, planfile)
        unexpected = tf_plan_check.unexpected_changes(plan, issue.get("body") or "")
        if unexpected:
            detail = ", ".join(f"{addr} ({'/'.join(actions)})" for addr, actions in unexpected)
            apply_escalate(
                n, pr,
                f"fresh plan destroys/replaces {detail}, not covered by an `AllowedDestroy:` "
                "line in the ticket -- live infra may have drifted since the PR was approved",
            )
            return

        if dry_run:
            log(f"#{n}: would terraform apply (PR #{pr})")
            return

        result = subprocess.run(
            ["terraform", "apply", "-input=false", "-auto-approve", str(planfile)],
            cwd=tf_dir, capture_output=True, text=True, env=apply_env(),
        )
        output = (result.stdout + result.stderr)[-4000:]
        dispatch.record("applied", ticket=n, pr=pr, commit=commit, ok=result.returncode == 0, output=output)
        dispatch.run(
            [
                "gh", "issue", "comment", str(n), "--repo", cfg.repo,
                "--body", f"`terraform apply` {'succeeded' if result.returncode == 0 else 'FAILED'} "
                f"for the merged change:\n\n```\n{output}\n```",
            ],
            check=False,
        )
        if result.returncode != 0:
            apply_escalate(n, pr, "terraform apply failed")
        else:
            log(f"#{n}: applied (PR #{pr})")
    finally:
        dispatch.run(["git", "worktree", "remove", "--force", str(wt)], cwd=cfg.root, check=False)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="factory apply",
        description="terraform apply for merged, human-review-approved, apply-eligible "
        "tickets (one pass, stateless). No-op unless [apply].enabled = true.",
    )
    parser.add_argument("--dry-run", action="store_true", help="print planned applies; no side effects")
    args = parser.parse_args(argv)
    configure(config.load())

    if not cfg.apply_enabled:
        log("apply not enabled for this repo ([apply].enabled = true to turn on)")
        return 0

    (cfg.factory / "locks").mkdir(parents=True, exist_ok=True)
    lock_fd = (cfg.factory / "locks" / "apply.lock").open("w")
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        log("skipped (another apply run holds the lock)")
        lock_fd.close()
        return 0
    try:
        # touches_apply_dir() diffs {commit}~1..commit locally -- if this repo's
        # main hasn't independently fetched since the merge (e.g. `factory
        # apply` invoked standalone, not right after a dispatch pass), the
        # merge commit doesn't exist locally yet, the diff silently fails
        # (check=False), and touches_apply_dir wrongly reports False.
        # Confirmed live (ticket #45): a genuinely apply-dir-touching merge
        # was skipped with "doesn't touch ...; nothing to apply" for exactly
        # this reason. fresh_checkout() also fetches, but only runs *after*
        # touches_apply_dir already (wrongly) decided there was nothing to do.
        dispatch.run(["git", "fetch", "origin", cfg.main], cwd=cfg.root)
        done = applied_tickets()
        pending = [t for t in merged_tickets() if t["ticket"] not in done]
        if not pending:
            log("nothing to apply")
            return 0
        for ticket in pending:
            apply_one(ticket, args.dry_run)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
