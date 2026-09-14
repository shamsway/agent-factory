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
import time
from pathlib import Path

from agent_factory import config, deploy, dispatch, tf_plan_check
from agent_factory.config import Config

cfg: Config


def configure(c: Config) -> None:
    global cfg
    cfg = c
    dispatch.configure(c)


def log(msg: str) -> None:
    print(f"[apply] {msg}", flush=True)


def applied_tickets(target: str = "default") -> set[int]:
    """Ticket numbers with a recorded terminal state -- never re-apply.

    Failed runs are terminal and never silently auto-retried.
    """
    return deploy.terminal_tickets(target=target, events_path=dispatch.EVENTS)


def merged_tickets(limit: int = 100) -> list[dict]:
    """Merged factory PRs for this repo: [{pr, ticket, commit, ...}], any order."""
    prs = dispatch.gh_json(
        [
            "pr", "list", "--repo", cfg.repo, "--state", "merged",
            "--json", "number,headRefName,mergeCommit,reviewDecision,headRefOid,latestReviews",
            "--limit", str(limit),
        ]
    )
    out = []
    if not isinstance(prs, list):
        return out
    for pr in prs:
        m = re.fullmatch(r"agent/(\d+)", pr.get("headRefName", ""))
        if not m or not pr.get("mergeCommit"):
            continue
        merge_oid = (
            pr["mergeCommit"]["oid"]
            if isinstance(pr["mergeCommit"], dict)
            else str(pr["mergeCommit"])
        )
        row = {"pr": pr["number"], "ticket": int(m.group(1)), "commit": merge_oid}
        if "headRefOid" in pr and pr["headRefOid"] is not None:
            row["head_commit"] = pr["headRefOid"]
        if "reviewDecision" in pr and pr["reviewDecision"] is not None:
            row["reviewDecision"] = pr["reviewDecision"]
        if "latestReviews" in pr and pr["latestReviews"] is not None:
            row["latestReviews"] = pr["latestReviews"]
        out.append(row)
    return out


def fetch_pr_review_evidence(pr_number: int, repo: str = "") -> dict | None:
    """Fetch complete review decision, head commit, and review details for a PR."""
    try:
        r = repo or cfg.repo
        args = ["pr", "view", str(pr_number)]
        if r:
            args.extend(["--repo", r])
        args.extend(["--json", "reviewDecision,headRefOid,latestReviews"])
        res = dispatch.gh_json(args)
        if isinstance(res, dict):
            return res
    except Exception:
        pass
    return None


def fetch_all_merged_prs(page_size: int = 100, max_pages: int = 10) -> list[dict]:
    """Discover merged PRs with pagination up to max_pages.

    Uses a consistent paginated query for merged PRs, stopping only at the actual
    raw query boundary (when raw returned count < page_size or no next page),
    never based on the filtered count of matching factory PRs.
    """
    all_prs: list[dict] = []
    seen_prs: set[int] = set()

    owner, repo_name = (cfg.repo.split("/", 1) if "/" in cfg.repo else ("", cfg.repo))
    cursor: str | None = None

    for page in range(1, max_pages + 1):
        raw_items: list[dict] = []
        has_next = False
        next_cursor = None

        if owner and repo_name:
            cursor_param = f', after: "{cursor}"' if cursor else ""
            query = f"""query {{
  repository(owner: "{owner}", name: "{repo_name}") {{
    pullRequests(states: [MERGED], first: {page_size}{cursor_param}, orderBy: {{field: CREATED_AT, direction: DESC}}) {{
      pageInfo {{
        hasNextPage
        endCursor
      }}
      nodes {{
        number
        headRefName
        headRefOid
        mergeCommit {{
          oid
        }}
        reviewDecision
        latestReviews(first: 20) {{
          nodes {{
            state
            authorAssociation
            author {{
              login
            }}
            commit {{
              oid
            }}
          }}
        }}
      }}
    }}
  }}
}}"""
            try:
                data = dispatch.gh_json(["api", "graphql", "-f", f"query={query}"])
                if isinstance(data, dict) and "data" in data and data["data"]:
                    repo_data = data["data"].get("repository") or {}
                    pr_conn = repo_data.get("pullRequests") or {}
                    page_info = pr_conn.get("pageInfo") or {}
                    has_next = bool(page_info.get("hasNextPage"))
                    next_cursor = page_info.get("endCursor")
                    raw_items = pr_conn.get("nodes") or []
            except Exception:
                raw_items = []

        if page == 1 and not raw_items:
            try:
                prs = dispatch.gh_json(
                    [
                        "pr", "list", "--repo", cfg.repo, "--state", "merged",
                        "--json", "number,headRefName,mergeCommit,reviewDecision,headRefOid,latestReviews",
                        "--limit", str(page_size),
                    ]
                )
                if isinstance(prs, list):
                    raw_items = prs
                    has_next = len(raw_items) >= page_size
            except Exception:
                raw_items = []

        if not raw_items:
            break

        for pr in raw_items:
            m = re.fullmatch(r"agent/(\d+)", pr.get("headRefName", ""))
            merge_commit = pr.get("mergeCommit")
            if not m or not merge_commit:
                continue
            merge_oid = (
                merge_commit["oid"]
                if isinstance(merge_commit, dict)
                else str(merge_commit)
            )
            pr_num = int(pr["number"])
            if pr_num in seen_prs:
                continue
            seen_prs.add(pr_num)

            row: dict[str, Any] = {
                "pr": pr_num,
                "ticket": int(m.group(1)),
                "commit": merge_oid,
            }
            if pr.get("headRefOid"):
                row["head_commit"] = pr["headRefOid"]
            if pr.get("reviewDecision"):
                row["reviewDecision"] = pr["reviewDecision"]
            if pr.get("latestReviews"):
                reviews_val = pr["latestReviews"]
                if isinstance(reviews_val, dict) and "nodes" in reviews_val:
                    reviews_val = reviews_val["nodes"]
                row["latestReviews"] = reviews_val
            all_prs.append(row)

        if len(raw_items) < page_size or not has_next or not next_cursor:
            break
        cursor = next_cursor

    return all_prs


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


def touches_target_dir(commit: str, target_dir: str) -> bool:
    proc = dispatch.run(
        ["git", "diff", "--name-only", f"{commit}~1", commit, "--", target_dir],
        cwd=cfg.root,
        check=False,
    )
    return bool(proc.stdout.strip())


def touches_apply_dir(commit: str) -> bool:
    return touches_target_dir(commit, cfg.apply_dir)


def apply_env() -> dict:
    """Subprocess env for `terraform apply` only: host env + [apply].env.
    Never touched by `factory dispatch`/`factory triage` -- that separation
    is the entire point of the credential boundary."""
    env = dict(os.environ)
    env.update(cfg.apply_env)
    return env


def apply_escalate(n: int, pr: int, reason: str, commit: str = "", target: str = "default", dry_run: bool = False) -> None:
    """Post-merge escalation: the tracking issue is already closed, so this
    only comments + records an event rather than touching labels the way
    `dispatch.escalate` does for in-flight tickets."""
    if dry_run:
        log(f"#{n}: would escalate ({reason})")
        return

    attempt = deploy.next_attempt(target, n, commit, events_path=dispatch.EVENTS)
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    run = deploy.DeployRun(
        run_id=f"deploy-{target}-{commit[:8] if commit else '0'}-{attempt}",
        target=target,
        commit=commit,
        ticket=n,
        attempt=attempt,
        status=deploy.DeployStatus.FAILED,
        started_at=now,
        completed_at=now,
        pr=pr,
        error=reason,
        version=deploy.CONTRACT_VERSION,
    )
    deploy.record_deploy_run(run)
    dispatch.record("apply-escalate", ticket=n, pr=pr, reason=reason, run_id=run.run_id, target=target)
    body = f"`factory apply` did not proceed: {reason}."
    try:
        dispatch.run(
            [
                "gh", "issue", "comment", str(n), "--repo", cfg.repo,
                "--body", body,
            ],
            check=False,
        )
        dispatch.pr_comment(n, body)
    except Exception as exc:
        log(f"#{n}: notification failed: {exc}")
    log(f"#{n}: apply escalated ({reason})")


def apply_one(ticket: dict, dry_run: bool, target: str = "default", adapter: deploy.DeployAdapter | None = None) -> bool:
    n, pr, commit = ticket["ticket"], ticket["pr"], ticket["commit"]
    attempt = deploy.next_attempt(target, n, commit, events_path=dispatch.EVENTS)
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    target_obj = cfg.targets.get(target) or config.DeployTarget(
        name=target, dir=cfg.apply_dir, enabled=cfg.apply_enabled
    )
    target_dir = target_obj.dir if target_obj else cfg.apply_dir
    touches = touches_apply_dir(commit) if target == "default" else touches_target_dir(commit, target_dir)

    if not touches:
        if dry_run:
            log(f"#{n}: would skip (doesn't touch {target_dir})")
            return True
        log(f"#{n}: PR #{pr} doesn't touch {target_dir}; nothing to apply")
        run = deploy.DeployRun(
            run_id=f"deploy-{target}-{commit[:8] if commit else '0'}-{attempt}",
            target=target,
            commit=commit,
            ticket=n,
            attempt=attempt,
            status=deploy.DeployStatus.SKIPPED,
            started_at=now,
            completed_at=now,
            pr=pr,
            output=f"no changes under {target_dir}",
            version=deploy.CONTRACT_VERSION,
        )
        deploy.record_deploy_run(run)
        dispatch.record("applied", ticket=n, pr=pr, commit=commit, ok=True, note=f"no changes under {target_dir}", run_id=run.run_id, target=target)
        return True

    if adapter is None:
        adapter = deploy.get_adapter(target_obj.adapter)

    ctx = deploy.DeployContext(
        target=target_obj,
        ticket=ticket,
        root=cfg.root,
        factory_dir=cfg.factory,
        env=apply_env(),
        repo=cfg.repo,
    )

    try:
        prep_ok, prep_err = adapter.prepare(ctx)
        if not prep_ok:
            apply_escalate(n, pr, prep_err or "adapter prepare failed", commit=commit, target=target, dry_run=dry_run)
            return False

        check_ok, check_err = adapter.check(ctx)
        if not check_ok:
            apply_escalate(n, pr, check_err or "pre-apply check failed", commit=commit, target=target, dry_run=dry_run)
            return False

        if dry_run:
            res = adapter.execute(ctx, dry_run=True)
            log(f"#{n}: {res.output}")
            return True

        # Durable RUNNING state recorded BEFORE execution!
        run_id = f"deploy-{target}-{commit[:8] if commit else '0'}-{attempt}"
        running_run = deploy.DeployRun(
            run_id=run_id,
            target=target,
            commit=commit,
            ticket=n,
            attempt=attempt,
            status=deploy.DeployStatus.RUNNING,
            started_at=now,
            pr=pr,
            version=deploy.CONTRACT_VERSION,
        )
        deploy.record_deploy_run(running_run)

        exec_res = adapter.execute(ctx, dry_run=False)

        if exec_res.ok:
            v_ok, v_err = adapter.verify(ctx)
            if not v_ok:
                exec_res.ok = False
                exec_res.error = v_err or "post-apply verify failed"

        completed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        final_run = deploy.DeployRun(
            run_id=run_id,
            target=target,
            commit=commit,
            ticket=n,
            attempt=attempt,
            status=deploy.DeployStatus.SUCCEEDED if exec_res.ok else deploy.DeployStatus.FAILED,
            started_at=now,
            completed_at=completed_at,
            duration_sec=exec_res.duration_sec,
            pr=pr,
            output=exec_res.output,
            error=exec_res.error,
            version=deploy.CONTRACT_VERSION,
        )

        # Durable disk persistence written BEFORE notifications!
        deploy.record_deploy_run(final_run)
        dispatch.record("applied", ticket=n, pr=pr, commit=commit, ok=exec_res.ok, output=exec_res.output, run_id=final_run.run_id, target=target)

        verb = "succeeded" if exec_res.ok else "FAILED"
        prefix = "terraform apply" if target_obj.adapter == "terraform" else f"{target_obj.adapter} deploy"
        summary = (
            f"`{prefix}` {verb} "
            f"for the merged change:\n\n```\n{exec_res.output}\n```"
        )
        try:
            dispatch.run(
                [
                    "gh", "issue", "comment", str(n), "--repo", cfg.repo,
                    "--body", summary,
                ],
                check=False,
            )
            dispatch.pr_comment(n, summary)
        except Exception as notify_err:
            log(f"#{n}: notification failed: {notify_err}")

        if not exec_res.ok:
            apply_escalate(n, pr, exec_res.error or "deploy failed", commit=commit, target=target, dry_run=dry_run)
            return False
        else:
            log(f"#{n}: applied (PR #{pr})")
            return True
    finally:
        adapter.cleanup(ctx)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="factory apply",
        description="deploy merged, human-review-approved, apply-eligible "
        "tickets (one pass, stateless). No-op unless [apply].enabled = true.",
    )
    parser.add_argument("--dry-run", action="store_true", help="print planned applies; no side effects")
    parser.add_argument("--reconcile-run", metavar="RUN_ID", help="run_id of interrupted run to reconcile")
    parser.add_argument("--reconcile-status", choices=["succeeded", "failed", "acknowledged", "superseded"], default="failed", help="status to mark reconciled run")
    parser.add_argument("--reconcile-note", default="manual operator reconciliation", help="reconciliation explanation")
    parser.add_argument("--acknowledge-failure", metavar="TICKET_OR_RUN", help="acknowledge a failed run or ticket to authorize repair PRs")
    parser.add_argument("--target", help="optional target name to limit apply or reconciliation")
    args = parser.parse_args(argv)
    configure(config.load())

    if args.acknowledge_failure:
        target_name = args.target or "default"
        deploy.acknowledge_failure(
            target=target_name,
            ticket_or_run_id=args.acknowledge_failure,
            note=args.reconcile_note,
            events_path=dispatch.EVENTS,
        )
        log(f"acknowledged failure for `{args.acknowledge_failure}` on target `{target_name}`")
        return 0

    if args.reconcile_run:
        target_name = args.target or "default"
        st_map = {
            "succeeded": deploy.DeployStatus.SUCCEEDED,
            "failed": deploy.DeployStatus.FAILED,
            "acknowledged": deploy.DeployStatus.ACKNOWLEDGED,
            "superseded": deploy.DeployStatus.SUPERSEDED,
        }
        st = st_map.get(args.reconcile_status, deploy.DeployStatus.FAILED)
        rec = deploy.reconcile_interrupted_run(
            target=target_name,
            run_id=args.reconcile_run,
            status=st,
            note=args.reconcile_note,
            events_path=dispatch.EVENTS,
        )
        if rec:
            log(f"reconciled {args.reconcile_run} on target `{target_name}` as {args.reconcile_status}")
            return 0
        log(f"error: run {args.reconcile_run} not found for target `{target_name}`")
        return 1

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
        dispatch.run(["git", "fetch", "origin", cfg.main], cwd=cfg.root)
        all_prs = fetch_all_merged_prs()

        targets = cfg.targets or {
            "default": config.DeployTarget(name="default", dir=cfg.apply_dir, enabled=cfg.apply_enabled)
        }

        any_candidates_found = False
        has_errors = False
        for target_name, target in targets.items():
            if args.target and target_name != args.target:
                continue
            if not target.enabled:
                continue

            t_ok, t_fd = deploy.acquire_target_lock(cfg.factory, target_name)
            if not t_ok:
                log(f"target `{target_name}`: skipped (another process holds target lock)")
                continue

            b_ok, b_fd = deploy.acquire_backend_lock(cfg.factory, target.backend_key)
            if not b_ok:
                log(f"target `{target_name}`: skipped (another process holds backend lock for `{target.backend_key}`)")
                deploy.release_lock(t_fd)
                continue

            try:
                tstate = deploy.get_target_state(target=target_name, events_path=dispatch.EVENTS)
                if tstate.has_interrupted_run:
                    interrupted = tstate.interrupted_runs[0]
                    log(f"target `{target_name}`: interrupted run detected ({interrupted.run_id}); reconciliation required")
                    adapter = deploy.get_adapter(target.adapter)
                    rec_ok, rec_msg = adapter.reconcile(target, interrupted, events_path=dispatch.EVENTS)
                    if not rec_ok:
                        log(f"target `{target_name}`: stopped (reconciliation required: {rec_msg})")
                        has_errors = True
                        continue
                    log(f"target `{target_name}`: {rec_msg}")
                    tstate = deploy.get_target_state(target=target_name, events_path=dispatch.EVENTS)

                if tstate.unacknowledged_failed_tickets and cfg.apply_supersession == "sequential":
                    log(f"target `{target_name}`: stopped (unreconciled failed tickets: {sorted(tstate.unacknowledged_failed_tickets)})")
                    has_errors = True
                    continue

                def check_touch(c: str) -> bool:
                    if target.dir == cfg.apply_dir:
                        return touches_apply_dir(c)
                    return touches_target_dir(c, target.dir)

                candidates, unauthorized = deploy.select_candidates_for_target(
                    target_name=target_name,
                    target_dir=target.dir,
                    all_prs=all_prs,
                    root=cfg.root,
                    main_branch=cfg.main,
                    baseline=cfg.apply_baseline,
                    events_path=dispatch.EVENTS,
                    touches_fn=check_touch,
                    supersession=cfg.apply_supersession,
                    repo=cfg.repo,
                )

                if unauthorized:
                    for unauth_commit in unauthorized:
                        msg = f"unauthorized direct merge detected for target `{target_name}`: commit {unauth_commit[:8]} touches {target.dir} without an approved PR"
                        log(msg)
                        if not args.dry_run:
                            deploy.record_unauthorized_event(unauth_commit, target_name, msg, events_path=dispatch.EVENTS)
                    has_errors = True
                    continue

                if not candidates:
                    continue

                any_candidates_found = True
                for candidate in candidates:
                    if "unauthorized_reason" in candidate:
                        reason = candidate["unauthorized_reason"]
                        log(f"#{candidate['ticket']}: {'would reject' if args.dry_run else 'apply rejected'} ({reason})")
                        if not args.dry_run:
                            apply_escalate(candidate["ticket"], candidate["pr"], reason, commit=candidate["commit"], target=target_name, dry_run=args.dry_run)
                        has_errors = True
                        if cfg.apply_supersession == "sequential":
                            log(f"target `{target_name}`: stopping further applies after unauthorized revision #{candidate['ticket']}")
                            break
                        continue

                    success = apply_one(candidate, args.dry_run, target=target_name)
                    if not args.dry_run:
                        latest_state = deploy.get_target_state(target=target_name, events_path=dispatch.EVENTS)
                        is_failed = (success is False) or (candidate["ticket"] in latest_state.failed_tickets)
                    else:
                        is_failed = (success is False)
                    if is_failed:
                        has_errors = True
                        if cfg.apply_supersession == "sequential":
                            log(f"target `{target_name}`: stopping further applies after failure of #{candidate['ticket']}")
                            break
            finally:
                deploy.release_lock(b_fd)
                deploy.release_lock(t_fd)

        if not any_candidates_found and not has_errors:
            log("nothing to apply")
            return 0
        return 1 if has_errors and not args.dry_run else 0
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
