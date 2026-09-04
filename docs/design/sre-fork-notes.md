# SRE Agent Fork — Design Notes

> Copied verbatim from Claude memory
> (`project_agent_factory_sre_fork`, originating session
> `c8c14bb0-0a2e-4fb6-9563-0d41ad7df821`, last modified 2026-09-04) as the
> starting record for this branch. See `sre-fork-implementation-plan.md` in
> this directory for the actionable plan derived from these notes.

---

User forked `shamsway/agent-factory` (fork of `mikeroySoft/agent-factory`) — a
label-driven, GitHub-Issues-based autonomous coding-agent pipeline: issues
labelled `ready-for-agent` are claimed by a worker agent in a git worktree,
gated by deterministic checks (`.factory.toml`'s `[[gate.check]]`), reviewed
by a second LLM, opened as a PR, and merged once gate PASS + review APPROVE +
green CI + freshness-against-main all agree. Fork was identical to upstream
as of 2026-09-04 (no customization yet).

## Analysis performed (2026-09-04)

Reviewed core modules (`dispatch.py`, `gate.py`, `config.py`, `learn.py`,
`triage.py`) for patterns applicable to Octant. Findings mapped onto existing
Linear tickets via comments, plus 3 new tickets filed:

- **SHA-19** (ticket-triage gating) — steal `gate.py`'s process-group timeout
  (`start_new_session=True` + `os.killpg()` on timeout, not a plain kill —
  their comment: "a wedged check must FAIL, not sit on the lock, ticket #5's
  gate hung for 2h") and its trivial conflict-marker check.
- **SHA-21** (Q&A lane) — `review()`'s prompt pattern (cite `path:line` or it
  doesn't count, don't re-derive what a deterministic check already covers,
  end with one parseable `VERDICT:` line) and `triage.py`'s
  deterministic-lint-before-LLM-call pattern.
- **SHA-23** / **SHA-28** (lesson distillation, still Todo) — `learn.py` is
  close to a working implementation of both: evidence only from finished
  (merged/escalated) tickets, bounded + *merged* lesson list (not
  ever-appended), eval signal = first-pass-rate before/after. Flagged SHA-23
  and SHA-28 as likely-duplicate scope, needing reconciliation.
- **SHA-29** (gated remediation graduation path, still Todo) —
  `merge_pass_locked()`'s four-independent-evidence-sources + one-merge-per-
  pass + fail-closed-on-ambiguous-CI design is a mature reference. Flagged one
  real gap for Octant: their model treats "merge = safe to auto-apply" once
  evidence agrees; Octant's standing policy is that live infra apply is
  *always* human-gated regardless of evidence. See "Fork direction" below —
  this is now the resolved design, not just a caveat.
- **SHA-172** (new) — audit Barlow subprocess call sites for the
  process-group-timeout pattern.
- **SHA-173** (new) — document + audit a "reread authoritative state
  immediately before mutating" house rule (their `gh issue list` staleness bug
  double-claimed tickets; same failure class as Octant's own vault-morning
  stale-base-commit race).
- **SHA-174** (new, low priority) — keep pipeline-alive lock state outside any
  disposable/ephemeral working directory (their comment: "deleting a worktree
  must not erase the evidence its pipeline is alive, ticket #5's mid-flight
  wipe"). Likely already satisfied by Nomad's `prohibit_overlap` +
  vault-publisher's Consul-session lease for Octant's nomad-mode producers —
  ticket scope is to confirm, not necessarily to build anything.

## Fork direction decided (2026-09-04)

User's original vision, stated directly: **automate issue creation and PR
opening; PR approval is manual and is the gate that kicks off any necessary
`terraform` deploy** (new deployments/upgrades). Non-terraform operational
work is explicitly TBD — plan is to scope/test specific agent workflows for
typical ops tasks later, not design that path up front.

Tracking for this work stays on **GitHub Issues**, not Linear — user's
explicit call, since agent-factory is already built around GitHub and it's
simpler to keep using what's already wired up rather than porting
triage.py/dispatch.py to read from Linear.

My recommendation (given, not yet pushed back on): don't rework
agent-factory's core merge state machine to serve both software and ops
tickets. Keep the fork close to upstream for well-specified code-change
work; build the ops path as a second pipeline reusing agent-factory's
plumbing (worktree management, `gate.py`'s check runner, `events.jsonl`
audit trail, `escalate()`), diverging in three places:

1. Triage gets a third outcome beyond `ready-for-agent`/`needs-info`/
   `ready-for-human` — something like `ready-for-investigation`, where the
   agent's first pass is allowed to just gather evidence and report, not
   produce a diff (a lot of real ops tickets start as "service is down,
   cause unknown," which the current lint would wrongly bounce as
   under-specified).
2. Gate checks can include live-system checks (Consul/Prometheus/etc, not
   just repo-local test commands) — `.factory.toml`'s existing
   `[[gate.check]]` mechanism (arbitrary argv + timeout) already supports
   this with no new code.
3. Apply is a distinct, always-human-gated step, separate from the
   review/CI evidence-gathering stage — matches the user's stated vision
   above almost exactly: automation gets to "PR with a verified plan and a
   passing gate," a human approval is what actually triggers
   `terraform apply`.

This matches [[project_sha85_86_nomad_migration]]'s and the vault-publisher
design's existing pattern of never letting automation apply live-affecting
changes without an explicit human step, generalized to a GitHub-PR-driven
flow instead of a Nomad-dispatch one.

## Gap analysis (2026-09-04) — considerations not yet in the design above

Asked directly "anything I'm missing." Ranked by risk:

1. **Credential boundary between worker and apply.** "Human approval gates
   apply" must be an enforced permission boundary, not a convention — if the
   worker agent's own creds are apply-capable, a bug/bad prompt/compromised
   dependency could apply without approval. Worker holds plan-only (read)
   creds; a separate actor, triggered only by the approval event, holds
   apply-capable (write) creds. Same split already used for
   `homelab-readonly` vs matt's own SSH creds, and `octant-agent-ro` vs
   write-scoped 1Password items — reuse the pattern, don't reinvent it.
2. **A passing `terraform plan` isn't the same as a safe one.** Nothing in
   agent-factory's gate model distinguishes "plan succeeded" from "plan wants
   to destroy/replace something" — a forced-new attribute change can produce
   a clean plan that still destroys a resource. Needs a dedicated check
   parsing `terraform show -json` on the plan, failing/flagging any
   `destroy`/`replace` action unless the ticket explicitly expects it.
3. **Plan freshness against live infra state, not just git.**
   Agent-factory's freshness check only confirms the branch contains current
   `main`. Terraform plans can also go stale because live state changed
   (matt, Nomad, drift) between plan-time and apply-time, independent of git
   entirely. Apply needs its own re-plan-immediately-before-applying step, not
   just a git-ancestry check.
4. **Where do the issues themselves come from?** "Automate issue creation" is
   new work — upstream agent-factory only triages issues a human already
   filed. Needs an explicit detector (drift check, available-upgrade check, a
   failing health signal) that writes a well-formed issue with enough spec
   that the deterministic triage lint doesn't bounce it as underspecified.
   Don't assume this falls out of the fork for free.
5. **Unattended 1Password auth.** Hit the interactive desktop-app auth
   timeout repeatedly this session even with a human at the keyboard (see
   [[reference_octant_1password_auth]]). A dispatcher running plan/apply
   unattended needs a service-account token path, not the interactive flow —
   and the existing "apply always needs confirmation" policy needs explicit
   reconciling with "PR approval *is* the confirmation," so it's clear that's
   the one path allowed to bypass the interactive prompt.
6. **Concurrent tickets on one shared state file.** `max_active` defaults to
   2 — two agent-worked tickets touching `terraform/homelab-collectors/main.tf`
   at once risks either a merge conflict or a second PR whose plan was
   computed against state the first PR's apply already moved past. Pin
   `max_active = 1` for infra repos, or teach the merge stage to serialize on
   the state backend, not just the branch.
7. **Reuse the existing secret scanner, not theirs.** Agent-factory's
   leak-scan is a plain regex tuned for company-internal terminology
   (`jira|confluence|\.corp`), not credentials. `vault-lib.sh`'s
   `secret_scan_guard` (gitleaks-based, documented regex fallback) is a
   stronger, already-built tool for this — wire the gate to that instead of
   porting their weaker one.

## Open / not yet decided

- No ticket filed yet to actually scope/build the ops path itself — user was
  given the option and hadn't decided as of this writing.
- Non-terraform operational workflows are explicitly deferred; whatever
  design happens next should not try to solve this class up front.
- The 7 gap-analysis items above are not yet filed as GitHub issues or
  otherwise tracked as actionable work — captured here only.
