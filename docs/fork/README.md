# Fork operator material

Host-specific operator procedures, helper scripts and acceptance records live in
the operator's private ops repository, not in this public fork. Public source,
tests and docs here stay generic; `scripts/privacy-check.py` (see AGENTS.md)
guards each change against private identifiers.

## Design direction

The fork adds an operations lane to the code pipeline without changing how code
tickets merge:

- **Human approval gates every live change.** Automation reaches "merged PR with
  a verified plan and a passing gate"; `factory apply` acts only on merged,
  human-approved revisions, and a recorded operator approval stands in only when
  no second reviewer exists.
- **Credential boundary.** Workers hold plan-only credentials; apply-capable
  credentials exist only in the apply step's environment (`[apply].env`).
- **A clean plan is not a safe plan.** The `tf_plan_check` gate check flags
  destroy and replace actions, and applies re-plan against live state.
- **Evidence-first tickets.** `ready-for-investigation` and `kind/ops` tickets
  may gather evidence and report instead of producing a diff.
- **One writer per target.** Per-target locks and latest-wins supersession keep
  concurrent merges from applying stale plans.

Details: [deployment lifecycle](../deployment-lifecycle.md),
[incidents](../deployment-incidents.md),
[diagnostics](../deployment-diagnostics.md) and
[investigation](../deployment-investigation.md).
