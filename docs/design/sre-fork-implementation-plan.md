# SRE Agent Fork — Implementation Plan

**Status (2026-09-04): Phases 1, 2, 3, 4, 5, and 8 implemented and tested**
(`triage.py`, `dispatch.py`, `gate.py`, `config.py`, `onboard.py`,
`tf_plan_check.py`, `apply.py`, `cli.py`, `templates/factory.toml`,
`README.md`, `tests/test_factory.py`). Phases 6 (`factory detect`) and 7
(cross-repo state concurrency) remain deferred, per their own sections
below — no concrete ops ticket flow exists yet to build them against. One
implementation detail differs from the original draft: Phase 4's freshness
re-check (step 5) reuses `tf_plan_check`'s own `AllowedDestroy:` allow-list
mechanism directly (fetching the issue body fresh at apply time) rather
than diffing against a stored copy of the merged PR's gate report — simpler,
and the allow-list *is* what a human reviewed, so re-validating against it
is the right comparison, not an approximation of one.

Derived from `sre-fork-notes.md` in this directory (the carried-over design
memory) after reading the current code on `main`: `config.py`, `gate.py`,
`triage.py`, `dispatch.py`, `learn.py`, `cli.py`, `templates/factory.toml`,
and `tests/test_factory.py`. The notes were written against an Octant-internal
analysis session and reference Octant-specific tools (Barlow, vault-publisher,
Nomad, Linear ticket IDs) — those are dropped here since this fork
(`shamsway/agent-factory`) is a standalone personal project with no
dependency on that stack. What's kept is the actual design decision: **stay
close to upstream for well-specified code-change tickets; add a second,
parallel path for ops/infra tickets that reuses dispatch's plumbing
(worktrees, `gate.py`'s check runner, `events.jsonl`, `escalate()`) but
diverges at three points** — a third triage outcome, live-system gate
checks, and a distinct, always-human-gated apply step.

Confirmed against the code: this is a straightforward extension, not a
rewrite. `gate.py`'s check mechanism (`[[gate.check]]`, arbitrary argv,
already-timeout-guarded) needs **no code change** to run live-system checks —
that's a template/docs update only. The real code work is in `config.py`
(new label, new tables), `triage.py` (third decision), `dispatch.py` (a
non-PR terminal path for investigation tickets), and two new modules
(`apply.py`, `detect.py`) plus one new gate-check script (Terraform plan
safety).

## Phase 1 — Triage: `ready-for-investigation`

**Why first:** everything downstream depends on issues being classified
correctly; an "service is down, cause unknown" ticket must not get bounced
by the acceptance-criteria lint the way it does today.

`config.py`:
- Add `LABEL_INVESTIGATE = "ready-for-investigation"` alongside the other
  `LABEL_*` constants (config.py:21-26), with an entry in `LABELS`
  (config.py:27-34), e.g. `("1D76DB", "Evidence-gathering pass; agent reports, does not diff")`.

`triage.py`:
- Add `LABEL_INVESTIGATE` to `DECISIONS` (triage.py:54).
- Extend `system_prompt()` (triage.py:91-105) with a fifth decision:
  `"ready-for-investigation": the problem is real but the cause and fix are
  unknown — service down, alert firing, unexplained drift. The agent's job
  is to gather evidence and report, not produce a diff.` Reuse the existing
  `"brief"` field for what to investigate instead of what to implement.
- `deterministic_needs_info()` (triage.py:62-76) today requires acceptance
  criteria in every issue, which wrongly bounces incident-style ops tickets.
  Gate that requirement on a `kind/ops` label (or similar) supplied by the
  reporter or by `factory detect` (Phase 6): when present, skip the
  acceptance-criteria check and let the LLM choose between
  `ready-for-investigation` and `needs-info` freely. Without that label,
  behavior is unchanged — software tickets still need acceptance criteria.

`dispatch.py`:
- `frontier()` (dispatch.py:150-176) currently only looks for
  `LABEL_AGENT`. It needs a second query for `LABEL_INVESTIGATE`, or a
  combined query tagging each issue with which lane it's in.
- `process_ticket()` (dispatch.py:815-926) hard-codes the
  worker → gate → push_and_pr → review → merge pipeline. Investigation
  tickets have no diff to gate/review/merge. Add a branch, keyed off the
  ticket's label at claim time: after one `worker_round`-equivalent pass
  (the investigation worker's prompt says "write findings to
  `.factory/handoff-{n}.md`; do not open a PR"), skip
  `push_and_pr`/`review`/`approve_pr` entirely and instead:
  1. Post the handoff content as an issue comment (reuse the pattern in
     `escalate()`, dispatch.py:309-314, that already reads
     `handoff-{n}.md`).
  2. Swap `LABEL_AGENT` → `LABEL_HUMAN` (a human decides what happens next —
     file a follow-up implementation ticket, or close as resolved) rather
     than `LABEL_APPROVED`.
  3. Record a new event type, `investigated`, in `events.jsonl` so
     `stats.py`/the dashboard can count these separately from merges.
- The existing gate/review/merge machinery is untouched for
  `LABEL_AGENT` tickets — this is additive, not a rewrite of
  `process_ticket()`'s main path.

## Phase 2 — Live-system gate checks

**No code change.** `.factory.toml`'s `[[gate.check]]` already runs
arbitrary argv with a process-group timeout (gate.py:37-55) — a health-check
curl, a Prometheus query, a `consul catalog services` call all work today.
Action item is documentation only: add an example to
`templates/factory.toml` (after gate.py:43-46) showing a live-system check,
and a line in `README.md` noting that gate checks aren't limited to
repo-local test commands.

One real gap worth a small patch: `[gate].timeout` (config.py:59,249) is
global, but a live-system check (health endpoint, 5s timeout) and a
Terraform plan (could legitimately take minutes) want different budgets.
Add an optional per-check `timeout` field to `Check` (gate.py's dataclass
lives in config.py:73-83) that overrides `CHECK_TIMEOUT` when set; falls
back to the existing global value otherwise. Small, backward-compatible
(`CHECK_KEYS` in config.py:65 gains `"timeout"`).

## Phase 3 — Terraform plan safety check

A passing `terraform plan` and a *safe* one aren't the same thing — a
forced-new attribute change plans clean but destroys a resource. This has
to exist before Phase 4 (apply), since apply's freshness re-plan reuses it.

New script, invoked as an ordinary `[[gate.check]]` (no gate.py change
needed — it's just another argv):

```toml
[[gate.check]]
name = "tf-plan-safety"
run = ["python", "-m", "agent_factory.tf_plan_check", "--allow-destroy-of", "AllowedDestroy:"]
```

New module `agent_factory/tf_plan_check.py`:
- Runs `terraform init -input=false && terraform plan -out=.factory/tfplan-{n}
  && terraform show -json .factory/tfplan-{n}` inside the worktree.
- Parses `resource_changes[].change.actions`; any entry containing
  `"delete"` (covers both `["delete"]` and the replace pair
  `["delete","create"]`/`["create","delete"]`) fails the check unless the
  resource's address appears in an `AllowedDestroy: <address>` line in the
  ticket body (passed in via an env var the worker/gate already has access
  to, or read from the PR body once `push_and_pr` has written it).
- On failure, prints the offending resource addresses and actions to
  stdout — this becomes the gate report's failure excerpt (gate.py:151-154
  already tails and renders it), so the reviewer/human sees exactly what
  would be destroyed without re-running Terraform themselves.
- Exit code only; no other integration surface needed. Keep it a single
  focused script rather than a `gate.py` special case — consistent with how
  every other check is just an argv.

## Phase 4 — Apply as a distinct, human-gated step

Resolved design (confirmed 2026-09-04): **the PR merge itself is the human
approval gate for apply** — no separate post-merge label/comment step.
This matches the original vision directly ("PR approval is manual and is
the gate that kicks off terraform deploy") but requires one change to how
merging works, because merging is *not* currently a human action.

**The gap this closes:** `merge_pass_locked()` (dispatch.py:663-777) merges
automatically once the LLM reviewer's `factory-approved` label is present +
CI is green + the branch is fresh (dispatch.py:681-733). `reviewDecision`
is already fetched in the PR list (dispatch.py:673) but is only ever
checked for `CHANGES_REQUESTED` as a block (dispatch.py:683-685) — it's
never required to be `APPROVED`. So today, "merged" means "codex approved
it," not "a human approved it." For software tickets that's the intended
design (LLM review + CI is the whole evidence chain). For infra tickets, if
merge = apply-trigger, merge has to mean a human actually clicked Approve.

**Change to `merge_pass_locked()`:** for PRs against a repo/ticket flagged
as apply-eligible (e.g. a `terraform` or `infra` label present at claim
time, carried onto the PR), add a precondition alongside the existing
`factory-approved` check: `pr["reviewDecision"] == "APPROVED"`. Until a
human submits a real GitHub review approval, the PR sits exactly like a
CI-pending PR does today — logged, not merged (mirrors the `buckets.get("pending")`
branch at dispatch.py:720-721). Software-ticket merging is untouched: the
new condition only applies when the ticket is marked apply-eligible.

New module `agent_factory/apply.py`, new CLI entry in `cli.py`'s `COMMANDS`
dict (cli.py:8-18): `"apply": ("apply", "main", "apply following a human-
approved, merged infra change (terraform apply)")`.

Flow, modeled on `land_pass`'s locking pattern (dispatch.py:632-660):
1. Take an `apply.lock` (own file under `.factory/locks/`, same
   `fcntl.flock` pattern as `merge.lock`) so concurrent apply runs never
   overlap.
2. Find recently-merged PRs for apply-eligible tickets not yet recorded as
   `applied` in `events.jsonl` — no label to look for; "merged" (which now
   implies a real human review, per above) is itself the trigger.
3. Fresh checkout at the merge commit — **not** the worker's worktree
   (which may be gone; `cleanup_after_merge`, dispatch.py:624-629, removes
   it after merge) and **not** using the dispatcher's credentials (Phase 5).
4. Re-run the Terraform plan from scratch (`tf_plan_check`'s plan step) —
   this is the freshness check the notes flagged as missing: git-ancestry
   freshness (already handled by `merge_pass_locked`'s `behind_by` check,
   dispatch.py:726-733) says nothing about *live infra state* moving between
   plan-time and apply-time.
5. Re-validate the fresh plan the same way the gate did — fetch the issue
   body fresh (`gh issue view`, works on a closed issue) and run
   `tf_plan_check.unexpected_changes(plan, body)` again. Nothing unexpected →
   proceed. Anything not covered by an `AllowedDestroy:` line → abort,
   comment + record an `apply-escalate` event rather than apply against a
   plan nobody signed off on — the human approved *that* allow-list, not
   whatever infra has drifted to since. (Implemented this way rather than
   diffing against a stored gate report — see the status note at the top of
   this file.)
6. `terraform apply -auto-approve` the fresh plan, using `[apply].env`
   credentials, never the dispatcher's.
7. Record a new `applied` event to `events.jsonl` (same `record()` helper,
   dispatch.py:204-214) and comment the apply output on the issue.
   Merged PRs whose commit doesn't touch `[apply].dir` are recorded as
   applied immediately with a no-op note, so they're never reconsidered.

If real usage later shows a human approving the PR doesn't leave enough
of a paper trail (e.g. they want to review the *fresh* re-plan from step 4
before it applies, not just the plan that was visible at PR time), the
fallback is the originally-drafted `apply-approved` label or a `/apply`
PR-comment command as a second, explicit gate on top of the merge. Not
building that now — it's more moving parts than the stated vision asked
for, and easy to add later if the merge-is-approval model proves too thin.

## Phase 5 — Credential boundary (worker vs. apply)

Enforced as a deployment/config split, not by trusting the "human gates
apply" convention alone — a bug, bad prompt, or compromised dependency in
the worker path must not be *capable* of applying, regardless of what it's
told to do.

- Worker/dispatcher processes (`factory dispatch`, `factory triage`) run
  under read-only/plan-only credentials for whatever they touch
  (cloud IAM role, Terraform backend token, etc.) — no write scope.
  `factory apply` runs under a separate credential profile with the write
  scope, loaded only in that process's environment.
- Config seam: add an `[apply]` table to `.factory.toml` (`config.py`'s
  `KNOWN_KEYS`, config.py:54-64) with its own `env` dict, parallel to but
  never merged with `[install.env]` (config.py:42,63-64) — keeping the two
  structurally separate is the point; a shared `env` table would be exactly
  the kind of convention-only boundary this phase exists to avoid.
- `onboard.py doctor` gains a check: if any variable named in `[apply].env`
  is already set in the *dispatcher's* running environment, fail loudly —
  a canary for "someone pointed both paths at the same credential."

## Phase 6 — Issue-creation automation (`factory detect`)

Lowest priority per the notes ("no ticket filed yet to scope this"), and
intentionally generic: agent-factory should not embed drift-detection
logic itself, only a thin runner.

New module `agent_factory/detect.py`, CLI entry `"detect"`. Config table
`[[detect.check]]` mirroring `[[gate.check]]`'s shape (`name`, `run`): each
check's argv, run on a schedule (systemd timer, like `dispatch`), emits
JSON on stdout — `{"key": "...", "title": "...", "body": "...", "labels":
[...]}` for zero or more findings. `key` is a stable dedupe identifier
(hash of the drifted resource/alert), embedded as an HTML comment in the
issue body so a second run recognizes an already-filed issue and skips it
instead of re-filing. `detect.py`'s only job is that loop + `gh issue
create`; every actual detector (drift check, upgrade check, health signal)
is an external script the user supplies, same relationship `gate.check`
already has to test commands.

## Phase 7 — Concurrency on shared Terraform state

No code change required for the common case: `.factory.toml`'s
`max_active` (config.py:92, KNOWN_KEYS at config.py:56) already limits
tickets in flight per repo. Recommendation: set `max_active = 1` in any
infra repo's `.factory.toml` where multiple tickets could touch the same
state file. Cross-repo sharing of one state backend is a real but rarer
case — flagged as a follow-up, not built now: `active_ticket_count()`
(dispatch.py:119-122) counts per-repo lock files, so serializing across
repos would need a lock keyed on the state backend rather than the repo,
which is more machinery than is justified without a concrete second repo
that needs it.

## Phase 8 — Secret scanning

No core change. `gate.py`'s `check_leaks()` (gate.py:75-95) is a plain
regex over added lines — fine as a cheap first pass, not a replacement for
a real scanner. Recommended pattern, same as Phase 2: add a real scanner
(e.g. gitleaks) as an ordinary `[[gate.check]]` entry rather than teaching
`gate.py` a second built-in scanning mode:

```toml
[[gate.check]]
name = "gitleaks"
run = ["gitleaks", "detect", "--source", ".", "--no-git"]
```

Optionally tighten `DEFAULT_LEAK_PATTERN` (config.py:36) to also catch
common credential shapes (`AKIA[0-9A-Z]{16}`, `-----BEGIN.*PRIVATE KEY-----`)
as a defense-in-depth backstop even when no external scanner is configured
— cheap, and catches the case where a repo's `.factory.toml` hasn't been
updated yet.

## Sequencing

1. **Phase 1** (triage) and **Phase 2** (docs-only) — independent, land
   first, low risk.
2. **Phase 3** (tf-plan-safety) before **Phase 4** (apply) — apply's
   freshness re-plan reuses it directly.
3. **Phase 5** (credential boundary) lands *with* Phase 4, not after —
   an apply path without the credential split is the exact gap the notes
   flagged as highest risk.
4. **Phase 8** (secret scanning) can land anytime; cheapest phase.
5. **Phase 6** (detect) and **Phase 7** (cross-repo concurrency) are
   deferred until there's a concrete ops ticket flow to build them against —
   matches the notes' explicit "don't design the ops path up front."

## Testing

Follow `tests/test_factory.py`'s existing convention: throwaway git repos
under `tempfile.mkdtemp()`, plain `unittest`, no mocking framework, real
`gh`/`terraform` calls stubbed by putting a fake executable earlier on
`PATH` inside the test's temp dir (same trick already implied by
`XDG_CONFIG_HOME` isolation at the top of that file). `tf_plan_check.py`
in particular should ship with a unit test that feeds it a canned
`terraform show -json` fixture with both a clean and a destroy/replace
plan, independent of having Terraform installed in CI.

## Open decisions

- **Apply trigger (resolved 2026-09-04):** PR merge is the approval gate,
  per the original vision — no separate `apply-approved` label. This
  requires tightening `merge_pass_locked()` so apply-eligible PRs need a
  real human `reviewDecision == "APPROVED"`, not just the LLM's
  `factory-approved` label (see Phase 4). Fallback if this proves too thin
  in practice (e.g. a human wants to see the fresh re-plan before it
  applies, not just the plan visible at PR time): add an explicit
  `apply-approved` label or `/apply` PR-comment step on top of the merge.
  Not building that now.
- **Credential storage for `factory apply` (undecided, needs hands-on
  testing):** a distinct 1Password item read once per invocation, vs. a
  short-lived token minted per run. No strong prior either way for this
  fork — plan is to try both against Phase 4/5 once they're built and see
  which is less friction, rather than settle it on paper now.
