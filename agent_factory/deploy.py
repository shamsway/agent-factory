"""Deployment lifecycle, run persistence, and target state tracking.

Maintains explicit terminal states, attempt tracking, versioned result contracts,
and target state projection from .factory/events.jsonl. Replays both modern
`deploy_run` events and legacy `applied` / `apply-escalate` events, guaranteeing
that failed legacy runs are preserved as terminal failures and never silently
auto-retried.
"""

from __future__ import annotations

import fcntl
import json
import re
import subprocess
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

CONTRACT_VERSION = 1


class DeployStatus(str, Enum):
    """Explicit deployment lifecycle states."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


TERMINAL_STATUSES = frozenset(
    {
        DeployStatus.SUCCEEDED,
        DeployStatus.FAILED,
        DeployStatus.SKIPPED,
        DeployStatus.CANCELLED,
    }
)


@dataclass
class DeployRun:
    """Versioned result contract for a deployment run attempt."""

    run_id: str
    target: str
    commit: str
    ticket: int
    attempt: int
    status: DeployStatus
    started_at: str
    pr: int | None = None
    completed_at: str | None = None
    duration_sec: float | None = None
    output: str = ""
    error: str | None = None
    version: int = CONTRACT_VERSION

    def is_terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DeployRun:
        status = (
            data["status"]
            if isinstance(data["status"], DeployStatus)
            else DeployStatus(data["status"])
        )
        return cls(
            run_id=str(data["run_id"]),
            target=str(data.get("target", "default")),
            commit=str(data.get("commit", "")),
            ticket=int(data["ticket"]),
            attempt=int(data.get("attempt", 1)),
            status=status,
            started_at=str(data.get("started_at", "")),
            pr=int(data["pr"]) if data.get("pr") is not None else None,
            completed_at=data.get("completed_at"),
            duration_sec=float(data["duration_sec"]) if data.get("duration_sec") is not None else None,
            output=str(data.get("output", "")),
            error=data.get("error"),
            version=int(data.get("version", CONTRACT_VERSION)),
        )


@dataclass
class TargetState:
    """Projected state for a specific deployment target."""

    target: str
    latest_run: DeployRun | None = None
    latest_succeeded_commit: str | None = None
    runs: list[DeployRun] = field(default_factory=list)
    runs_by_commit: dict[str, list[DeployRun]] = field(default_factory=dict)
    runs_by_ticket: dict[int, list[DeployRun]] = field(default_factory=dict)

    @property
    def has_interrupted_run(self) -> bool:
        """True if the latest run started but never reached a terminal state."""
        return bool(self.latest_run and not self.latest_run.is_terminal())

    @property
    def interrupted_runs(self) -> list[DeployRun]:
        """Runs that started but never reached a terminal state."""
        return [r for r in self.runs if not r.is_terminal()]

    @property
    def terminal_tickets(self) -> set[int]:
        """Tickets whose latest run for this target is in a terminal state."""
        out = set()
        for ticket, runs in self.runs_by_ticket.items():
            if runs and runs[-1].is_terminal():
                out.add(ticket)
        return out

    @property
    def failed_tickets(self) -> set[int]:
        """Tickets whose latest run for this target ended in failure."""
        out = set()
        for ticket, runs in self.runs_by_ticket.items():
            if runs and runs[-1].status == DeployStatus.FAILED:
                out.add(ticket)
        return out

    @property
    def succeeded_tickets(self) -> set[int]:
        """Tickets whose latest run for this target succeeded."""
        out = set()
        for ticket, runs in self.runs_by_ticket.items():
            if runs and runs[-1].status == DeployStatus.SUCCEEDED:
                out.add(ticket)
        return out

    @property
    def skipped_tickets(self) -> set[int]:
        """Tickets whose latest run for this target was skipped (e.g. no changes)."""
        out = set()
        for ticket, runs in self.runs_by_ticket.items():
            if runs and runs[-1].status == DeployStatus.SKIPPED:
                out.add(ticket)
        return out


def parse_legacy_row(row: dict[str, Any]) -> DeployRun | None:
    """Translate legacy `applied` and `apply-escalate` events into DeployRun instances.

    Guarantees that failed legacy applied events (ok=False) or apply-escalate
    events are translated strictly to DeployStatus.FAILED and never treated as
    successes.
    """
    event = row.get("event")
    ticket_raw = row.get("ticket")
    if ticket_raw is None:
        return None
    try:
        ticket = int(ticket_raw)
    except (ValueError, TypeError):
        return None

    pr = int(row["pr"]) if row.get("pr") is not None else None
    commit = str(row.get("commit", ""))
    target = str(row.get("target", "default"))
    at = str(row.get("at", ""))
    output = str(row.get("output", ""))

    if event == "applied":
        note = row.get("note")
        if note and "no changes" in str(note):
            status = DeployStatus.SKIPPED
            err = None
            out = str(note)
        elif row.get("ok") is True:
            status = DeployStatus.SUCCEEDED
            err = None
            out = output
        else:
            status = DeployStatus.FAILED
            err = output or "terraform apply failed"
            out = output

        run_id = str(row.get("run_id") or f"legacy-{target}-{ticket}-{commit[:8] if commit else '0'}-1")
        return DeployRun(
            run_id=run_id,
            target=target,
            commit=commit,
            ticket=ticket,
            attempt=1,
            status=status,
            started_at=at,
            completed_at=at,
            pr=pr,
            output=out,
            error=err,
            version=CONTRACT_VERSION,
        )
    elif event == "apply-escalate":
        reason = str(row.get("reason", "apply escalated"))
        run_id = str(row.get("run_id") or f"legacy-escalate-{target}-{ticket}-{commit[:8] if commit else '0'}-1")
        return DeployRun(
            run_id=run_id,
            target=target,
            commit=commit,
            ticket=ticket,
            attempt=1,
            status=DeployStatus.FAILED,
            started_at=at,
            completed_at=at,
            pr=pr,
            output="",
            error=reason,
            version=CONTRACT_VERSION,
        )
    return None


def replay_events(events_path: Path) -> dict[str, TargetState]:
    """Replay events.jsonl into target states, preserving full run history."""
    if not events_path.exists():
        return {}

    states: dict[str, TargetState] = {}
    runs_by_id: dict[str, DeployRun] = {}

    for line in events_path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict):
            continue

        event = row.get("event")
        run: DeployRun | None = None
        if event == "deploy_run":
            data = dict(row)
            data.pop("event", None)
            data.pop("at", None)
            try:
                run = DeployRun.from_dict(data)
            except Exception:
                continue
        elif event in ("applied", "apply-escalate"):
            run = parse_legacy_row(row)

        if run is None:
            continue

        target = run.target or "default"
        if target not in states:
            states[target] = TargetState(target=target)
        tstate = states[target]

        if run.run_id in runs_by_id:
            existing = runs_by_id[run.run_id]
            existing.status = run.status
            existing.completed_at = run.completed_at or existing.completed_at
            existing.duration_sec = run.duration_sec or existing.duration_sec
            existing.output = run.output or existing.output
            existing.error = run.error if run.error is not None else existing.error
        else:
            runs_by_id[run.run_id] = run
            tstate.runs.append(run)
            tstate.runs_by_commit.setdefault(run.commit, []).append(run)
            tstate.runs_by_ticket.setdefault(run.ticket, []).append(run)

        tstate.latest_run = run
        if run.status == DeployStatus.SUCCEEDED and run.commit:
            tstate.latest_succeeded_commit = run.commit

    return states


def get_target_state(target: str = "default", events_path: Path | None = None) -> TargetState:
    """Get the projected state for a given deployment target."""
    if events_path is None:
        from agent_factory import dispatch
        events_path = dispatch.EVENTS

    states = replay_events(events_path)
    return states.get(target, TargetState(target=target))


def next_attempt(target: str, ticket: int, commit: str, events_path: Path | None = None) -> int:
    """Calculate the next attempt number for a target and ticket/commit."""
    state = get_target_state(target=target, events_path=events_path)
    existing_runs = [r for r in state.runs if r.ticket == ticket and (not commit or r.commit == commit)]
    if not existing_runs:
        return 1
    return max(r.attempt for r in existing_runs) + 1


def terminal_tickets(target: str = "default", events_path: Path | None = None) -> set[int]:
    """Ticket numbers whose latest run for this target is in a terminal state.

    Includes succeeded, skipped, and failed runs. Failed runs are terminal and
    must not be selected for silent auto-retry.
    """
    state = get_target_state(target=target, events_path=events_path)
    return state.terminal_tickets


def record_deploy_run(run: DeployRun, events_path: Path | None = None) -> None:
    """Record a DeployRun event to events.jsonl."""
    if events_path is not None:
        events_path.parent.mkdir(parents=True, exist_ok=True)
        row = {
            "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": "deploy_run",
            **run.to_dict(),
        }
        with events_path.open("a") as f:
            f.write(json.dumps(row) + "\n")
    else:
        from agent_factory import dispatch
        dispatch.record("deploy_run", **run.to_dict())


def record_unauthorized_event(
    commit: str, target: str, reason: str, events_path: Path | None = None
) -> None:
    """Record an unauthorized direct merge or unapproved revision event."""
    row = {
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": "deploy_unauthorized",
        "commit": commit,
        "target": target,
        "reason": reason,
    }
    if events_path is not None:
        events_path.parent.mkdir(parents=True, exist_ok=True)
        with events_path.open("a") as f:
            f.write(json.dumps(row) + "\n")
    else:
        from agent_factory import dispatch
        dispatch.record("deploy_unauthorized", commit=commit, target=target, reason=reason)


def resolve_main_ref(root: Path, main_branch: str = "main") -> str:
    """Find the most up-to-date ref between main and origin/main."""
    has_origin = subprocess.run(
        ["git", "rev-parse", "--verify", f"origin/{main_branch}"],
        cwd=root, capture_output=True, check=False,
    ).returncode == 0
    has_local = subprocess.run(
        ["git", "rev-parse", "--verify", main_branch],
        cwd=root, capture_output=True, check=False,
    ).returncode == 0

    if has_origin and has_local:
        proc = subprocess.run(
            ["git", "merge-base", "--is-ancestor", f"origin/{main_branch}", main_branch],
            cwd=root, capture_output=True, check=False,
        )
        if proc.returncode == 0:
            return main_branch
        return f"origin/{main_branch}"
    if has_origin:
        return f"origin/{main_branch}"
    if has_local:
        return main_branch
    return "HEAD"


def sort_candidates_topologically(
    candidates: list[dict], root: Path, main_branch: str = "main"
) -> list[dict]:
    """Sort candidates in git topological commit order on main."""
    if len(candidates) <= 1:
        return list(candidates)

    ref = resolve_main_ref(root, main_branch)
    proc = subprocess.run(
        ["git", "rev-list", "--reverse", "--topo-order", ref],
        cwd=root, capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        return list(candidates)

    ordered_commits = proc.stdout.splitlines()
    order = {c: i for i, c in enumerate(ordered_commits)}

    def key_fn(item: dict) -> int:
        c = item.get("commit", "")
        if c in order:
            return order[c]
        for full, idx in order.items():
            if full.startswith(c) or c.startswith(full):
                return idx
        return 999999999

    return sorted(candidates, key=key_fn)


def verify_revision_authorization(pr_data: dict, commit: str = "") -> tuple[bool, str]:
    """Verify that a candidate PR has explicit human review approval on the merged revision."""
    if "reviewDecision" in pr_data and pr_data["reviewDecision"] != "APPROVED":
        return False, f"reviewDecision is '{pr_data['reviewDecision']}', expected APPROVED"

    reviews = pr_data.get("latestReviews") or []
    head_commit = pr_data.get("head_commit")
    if reviews and head_commit:
        approved = [r for r in reviews if r.get("state") == "APPROVED"]
        if not approved:
            return False, "no APPROVED reviews found in latestReviews"
        matching = False
        approved_commits = []
        for r in approved:
            rev_commit = (
                r.get("commit", {}).get("oid", "")
                if isinstance(r.get("commit"), dict)
                else str(r.get("commit", ""))
            )
            if rev_commit:
                approved_commits.append(rev_commit[:8])
                if rev_commit.startswith(head_commit[:8]) or head_commit.startswith(rev_commit[:8]):
                    matching = True
                    break
        if not matching:
            return (
                False,
                f"approval is on revision {approved_commits}, but merged head is {head_commit[:8]} (stale review on unapproved revision)",
            )
    return True, ""


def is_before_baseline(
    pr_number: int, commit: str, baseline: str | None, root: Path
) -> bool:
    """True if PR or commit is at or before the adoption baseline."""
    if not baseline:
        return False
    if baseline.isdigit():
        return pr_number <= int(baseline)
    if commit:
        if commit.startswith(baseline) or baseline.startswith(commit):
            return True
        proc = subprocess.run(
            ["git", "merge-base", "--is-ancestor", commit, baseline],
            cwd=root, capture_output=True, check=False,
        )
        if proc.returncode == 0:
            return True
    return False


def touches_target_dir(commit: str, target_dir: str, root: Path) -> bool:
    """Check if commit touches target_dir."""
    proc = subprocess.run(
        ["git", "diff", "--name-only", f"{commit}~1", commit, "--", target_dir],
        cwd=root, capture_output=True, text=True, check=False,
    )
    return bool(proc.stdout.strip())


def find_unauthorized_direct_merges(
    target_dir: str,
    authorized_commits: set[str],
    root: Path,
    since_commit: str | None = None,
    main_branch: str = "main",
) -> list[str]:
    """Find commits on main touching target_dir that were not merged via an authorized PR."""
    ref = resolve_main_ref(root, main_branch)
    rev_range = f"{since_commit}..{ref}" if since_commit else ref
    proc = subprocess.run(
        ["git", "log", "--min-parents=1", "--format=%H", rev_range, "--", target_dir],
        cwd=root, capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        return []

    unauthorized = []
    for c in proc.stdout.splitlines():
        c = c.strip()
        if not c:
            continue
        matched = False
        for auth in authorized_commits:
            if c.startswith(auth) or auth.startswith(c):
                matched = True
                break
        if not matched:
            unauthorized.append(c)
    return unauthorized


def acquire_backend_lock(factory_dir: Path, backend_key: str) -> tuple[bool, Any]:
    """Acquire exclusive flock on backend_key so concurrent targets do not overlap."""
    if not backend_key:
        return True, None
    safe_key = re.sub(r"[^a-zA-Z0-9_.-]", "_", backend_key)
    locks_dir = factory_dir / "locks"
    locks_dir.mkdir(parents=True, exist_ok=True)
    lock_file = locks_dir / f"backend-{safe_key}.lock"
    lock_fd = lock_file.open("w")
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True, lock_fd
    except OSError:
        lock_fd.close()
        return False, None


def acquire_target_lock(factory_dir: Path, target_name: str) -> tuple[bool, Any]:
    """Acquire exclusive flock on target_name."""
    safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", target_name)
    locks_dir = factory_dir / "locks"
    locks_dir.mkdir(parents=True, exist_ok=True)
    lock_file = locks_dir / f"target-{safe_name}.lock"
    lock_fd = lock_file.open("w")
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True, lock_fd
    except OSError:
        lock_fd.close()
        return False, None


def release_lock(lock_fd: Any) -> None:
    """Release an flock."""
    if lock_fd is not None:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            lock_fd.close()
        except OSError:
            pass


def select_candidates_for_target(
    target_name: str,
    target_dir: str,
    all_prs: list[dict],
    root: Path,
    main_branch: str = "main",
    baseline: str | None = None,
    events_path: Path | None = None,
    touches_fn: Any = None,
) -> tuple[list[dict], list[str]]:
    """Select, filter, and order deployment candidates for a target.

    Enforces:
    - Target state checks (interrupted runs or unreconciled failures block selection).
    - Adoption baseline filtering.
    - Direct merge detection on main touching target_dir.
    - Revision authorization verification.
    - Git topological ordering.

    Returns:
      (ordered_candidates, unauthorized_direct_merges)
    """
    tstate = get_target_state(target=target_name, events_path=events_path)
    if tstate.has_interrupted_run or tstate.failed_tickets:
        return [], []

    check_touches = touches_fn or (lambda c: touches_target_dir(c, target_dir, root))

    # Identify PRs touching this target and not terminal or before baseline
    candidates = []
    authorized_commits = set()
    for pr in all_prs:
        commit = pr.get("commit", "")
        pr_num = int(pr["pr"])
        ticket_num = int(pr.get("ticket") or pr["pr"])
        authorized_commits.add(commit)
        if head := pr.get("head_commit"):
            authorized_commits.add(head)

        if not check_touches(commit):
            continue
        if pr_num in tstate.terminal_tickets or ticket_num in tstate.terminal_tickets:
            continue
        if is_before_baseline(pr_num, commit, baseline, root):
            continue

        candidates.append(dict(pr))

    # Detect unauthorized direct merges on main
    since = tstate.latest_succeeded_commit
    if not since and baseline:
        if baseline.isdigit():
            for pr in all_prs:
                if str(pr.get("pr")) == str(baseline):
                    since = pr.get("commit")
                    break
        else:
            since = baseline

    unauthorized = find_unauthorized_direct_merges(
        target_dir=target_dir,
        authorized_commits=authorized_commits,
        root=root,
        since_commit=since,
        main_branch=main_branch,
    )
    if unauthorized:
        return [], unauthorized

    # Verify revision-bound authorization
    for c in candidates:
        ok, reason = verify_revision_authorization(c, c["commit"])
        if not ok:
            c["unauthorized_reason"] = reason

    ordered = sort_candidates_topologically(candidates, root=root, main_branch=main_branch)
    return ordered, []


@dataclass
class DeployContext:
    """Execution context passed through deploy adapter lifecycle hooks."""

    target: Any
    ticket: dict
    root: Path
    factory_dir: Path
    env: dict[str, str] = field(default_factory=dict)
    repo: str = ""
    worktree: Path | None = None
    planfile: Path | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class DeployExecutionResult:
    """Bounded subprocess execution result from an adapter."""

    ok: bool
    output: str = ""
    error: str | None = None
    duration_sec: float = 0.0


class DeployAdapter:
    """Base interface for deployment adapters (Terraform, fake/mock, etc.)."""

    def prepare(self, ctx: DeployContext) -> tuple[bool, str]:
        """Prepare worktree, environment, plan files, or deployment artifacts."""
        return True, ""

    def check(self, ctx: DeployContext) -> tuple[bool, str]:
        """Pre-apply safety, freshness, drift, and destroy validation."""
        return True, ""

    def execute(self, ctx: DeployContext, dry_run: bool = False) -> DeployExecutionResult:
        """Execute bounded subprocess mutation."""
        raise NotImplementedError

    def verify(self, ctx: DeployContext) -> tuple[bool, str]:
        """Post-apply verification check."""
        return True, ""

    def cleanup(self, ctx: DeployContext) -> None:
        """Guaranteed cleanup of temporary resources."""
        pass

    def reconcile(
        self,
        target: Any,
        interrupted_run: DeployRun,
        events_path: Path | None = None,
    ) -> tuple[bool, str]:
        """Inspect and reconcile an interrupted run."""
        return False, f"interrupted run {interrupted_run.run_id} requires operator reconciliation"


class TerraformDeployAdapter(DeployAdapter):
    """Deploy adapter for Terraform roots with bounded subprocess execution."""

    def __init__(self, timeout_sec: int = 1800) -> None:
        self.timeout_sec = timeout_sec

    def prepare(self, ctx: DeployContext) -> tuple[bool, str]:
        from agent_factory import apply
        wt = apply.fresh_checkout(ctx.ticket["commit"])
        ctx.worktree = wt
        ctx.planfile = wt / ".factory" / f"apply-plan-{ctx.target.name}-{ctx.ticket['ticket']}"
        ctx.planfile.parent.mkdir(parents=True, exist_ok=True)
        return True, ""

    def check(self, ctx: DeployContext) -> tuple[bool, str]:
        if not ctx.worktree or not ctx.planfile:
            return False, "worktree or planfile missing in check phase"
        from agent_factory import dispatch, tf_plan_check

        tf_dir = ctx.worktree / ctx.target.dir
        proc = tf_plan_check.run_plan(tf_dir, ctx.planfile, env=ctx.env)
        if proc.returncode != 0:
            return False, f"fresh terraform plan failed:\n\n{proc.stdout + proc.stderr}"

        repo_arg = ["--repo", ctx.repo] if ctx.repo else []
        issue = dispatch.gh_json(["issue", "view", str(ctx.ticket["ticket"]), *repo_arg, "--json", "body"])
        plan = tf_plan_check.show_json(tf_dir, ctx.planfile)
        unexpected = tf_plan_check.unexpected_changes(plan, issue.get("body") or "")
        if unexpected:
            detail = ", ".join(f"{addr} ({'/'.join(actions)})" for addr, actions in unexpected)
            return False, (
                f"fresh plan destroys/replaces {detail}, not covered by an `AllowedDestroy:` "
                "line in the ticket -- live infra may have drifted since the PR was approved"
            )
        return True, ""

    def execute(self, ctx: DeployContext, dry_run: bool = False) -> DeployExecutionResult:
        if dry_run:
            return DeployExecutionResult(
                ok=True,
                output=f"would terraform apply (PR #{ctx.ticket.get('pr')})",
                duration_sec=0.0,
            )
        if not ctx.worktree or not ctx.planfile:
            return DeployExecutionResult(
                ok=False,
                error="worktree or planfile missing in execute phase",
            )

        tf_dir = ctx.worktree / ctx.target.dir
        t0 = time.monotonic()
        try:
            result = subprocess.run(
                ["terraform", "apply", "-input=false", "-auto-approve", str(ctx.planfile)],
                cwd=tf_dir,
                capture_output=True,
                text=True,
                env=ctx.env,
                timeout=self.timeout_sec,
            )
            duration = round(time.monotonic() - t0, 3)
            output = (result.stdout + result.stderr)[-4000:]
            ok = result.returncode == 0
            return DeployExecutionResult(
                ok=ok,
                output=output,
                error=None if ok else "terraform apply failed",
                duration_sec=duration,
            )
        except subprocess.TimeoutExpired as exc:
            duration = round(time.monotonic() - t0, 3)
            out_str = (getattr(exc, "output", None) or getattr(exc, "stdout", None) or "")
            err_str = exc.stderr or ""
            out = (out_str + err_str)[-4000:]
            return DeployExecutionResult(
                ok=False,
                output=out,
                error=f"terraform apply timed out after {self.timeout_sec}s",
                duration_sec=duration,
            )

    def verify(self, ctx: DeployContext) -> tuple[bool, str]:
        return True, ""

    def cleanup(self, ctx: DeployContext) -> None:
        if ctx.worktree:
            from agent_factory import dispatch
            dispatch.run(["git", "worktree", "remove", "--force", str(ctx.worktree)], cwd=ctx.root, check=False)

    def reconcile(
        self,
        target: Any,
        interrupted_run: DeployRun,
        events_path: Path | None = None,
    ) -> tuple[bool, str]:
        return False, f"interrupted terraform run {interrupted_run.run_id} requires operator reconciliation"


class FakeDeployAdapter(DeployAdapter):
    """Second deploy adapter demonstrating the contract without external platforms."""

    def __init__(
        self,
        name: str = "fake",
        can_auto_reconcile: bool = False,
        prepare_error: str | None = None,
        check_error: str | None = None,
        execute_error: str | None = None,
        verify_error: str | None = None,
        output: str = "fake deploy succeeded",
        duration_sec: float = 0.05,
    ) -> None:
        self.name = name
        self.can_auto_reconcile = can_auto_reconcile
        self.prepare_error = prepare_error
        self.check_error = check_error
        self.execute_error = execute_error
        self.verify_error = verify_error
        self.output = output
        self.duration_sec = duration_sec
        self.calls: list[str] = []

    def prepare(self, ctx: DeployContext) -> tuple[bool, str]:
        self.calls.append("prepare")
        if self.prepare_error:
            return False, self.prepare_error
        return True, ""

    def check(self, ctx: DeployContext) -> tuple[bool, str]:
        self.calls.append("check")
        if self.check_error:
            return False, self.check_error
        return True, ""

    def execute(self, ctx: DeployContext, dry_run: bool = False) -> DeployExecutionResult:
        self.calls.append("execute")
        if dry_run:
            return DeployExecutionResult(ok=True, output=f"would fake deploy {ctx.target.name} (PR #{ctx.ticket.get('pr')})")
        if self.execute_error:
            return DeployExecutionResult(
                ok=False,
                output=self.output,
                error=self.execute_error,
                duration_sec=self.duration_sec,
            )
        return DeployExecutionResult(
            ok=True,
            output=self.output,
            duration_sec=self.duration_sec,
        )

    def verify(self, ctx: DeployContext) -> tuple[bool, str]:
        self.calls.append("verify")
        if self.verify_error:
            return False, self.verify_error
        return True, ""

    def cleanup(self, ctx: DeployContext) -> None:
        self.calls.append("cleanup")

    def reconcile(
        self,
        target: Any,
        interrupted_run: DeployRun,
        events_path: Path | None = None,
    ) -> tuple[bool, str]:
        self.calls.append("reconcile")
        if self.can_auto_reconcile:
            reconcile_interrupted_run(
                target=target.name,
                run_id=interrupted_run.run_id,
                status=DeployStatus.SUCCEEDED,
                note="auto-reconciled by fake adapter",
                events_path=events_path,
            )
            return True, "interrupted run reconciled automatically by fake adapter"
        return False, f"fake adapter requires operator reconciliation for {interrupted_run.run_id}"


def reconcile_interrupted_run(
    target: str,
    run_id: str,
    status: DeployStatus = DeployStatus.FAILED,
    note: str = "manual operator reconciliation",
    events_path: Path | None = None,
) -> DeployRun | None:
    """Reconcile an interrupted run by marking it terminal in events.jsonl."""
    tstate = get_target_state(target=target, events_path=events_path)
    matching = [r for r in tstate.runs if r.run_id == run_id]
    if not matching:
        return None

    run = matching[-1]
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    reconciled_run = DeployRun(
        run_id=run.run_id,
        target=run.target,
        commit=run.commit,
        ticket=run.ticket,
        attempt=run.attempt,
        status=status,
        started_at=run.started_at or now,
        completed_at=now,
        duration_sec=run.duration_sec,
        pr=run.pr,
        output=run.output,
        error=note,
        version=CONTRACT_VERSION,
    )
    record_deploy_run(reconciled_run, events_path=events_path)
    if events_path is None:
        from agent_factory import dispatch
        dispatch.record(
            "deploy_reconciled",
            run_id=run_id,
            target=target,
            status=status.value,
            note=note,
        )
    return reconciled_run


ADAPTERS: dict[str, type[DeployAdapter]] = {
    "terraform": TerraformDeployAdapter,
    "fake": FakeDeployAdapter,
    "mock": FakeDeployAdapter,
}


def get_adapter(name: str = "terraform") -> DeployAdapter:
    """Get an instantiated deploy adapter by name."""
    cls = ADAPTERS.get(name.lower(), TerraformDeployAdapter)
    return cls()


def register_adapter(name: str, adapter_cls: type[DeployAdapter]) -> None:
    """Register a deploy adapter class by name."""
    ADAPTERS[name.lower()] = adapter_cls


