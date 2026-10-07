# SHA-201 Barlow acceptance and release plan — approval required

Status: plan only, 2026-10-07. No command in this plan has been run on Barlow.
Diagnostics remain off; PR3 and PR4 remain draft. Approve the specific step before
execution. Source/CI success does not prove the host boundary or failed-deployment
pipeline. [Option B and residual risk](investigation-option-b.md) apply throughout.

## A. Provisioning verification (operator runs)

Approval A covers only the provisioning guide and local verification. Confirm the
exact candidate series/fork SHA, wheel manifest and rollback paths first. Create
the dedicated user/stores/root-owned venv/policies/read-only Git mirror, provision
the key using the hidden manual systemd encryption procedure, and install the
stopped oneshot service. No service runtime replacement or diagnostics enablement.

Verify owner/mode metadata, source/wheel hashes, UID and systemd feature support.
Check the credential inside the temporary check unit, check matt's negative access
and credential cleanup; verify matt has no execution/start/edit privilege capable
of bypassing the dedicated identity. Preserve the durable outbox even if any
verification fails. Validate the accepted 14 scope v2 mappings and actual commit
availability. Use a synthetic export/import to prove group readability, atomic
snapshot installation and missing/observed/stale status reporting in inspect/doctor.

**Separate approval A2:** execute `investigation-broker --policy POLICY
--verify-token` through the dedicated encrypted-credential unit. This performs
bounded App identity/installation/mint and bot identity GETs, no comment POST and
no model call. Record only login, outcome/expiry/request counts. Verify status
visible to doctor and no credential persisted. Stop the unit. A failed/unknown
mint is not automatically retried. A does not authorize A2.

## B. Controlled failed-deployment acceptance

Before approval B, present a concrete small Terraform/Nomad diff for **one**
low-risk collector, its target/namespace, exact source revision, incident issue,
expected placement/resource/OOM failure, resource limits, recovery diff, time
window and rollback command. Prefer a deliberately unsatisfiable placement
constraint on an expendable collector over crashing a host process. Do not choose
a collector that the current health policy would mark healthy merely because its
periodic registration exists. Confirm no other diagnostics target is enabled.
The operator approves the exact diff and temporary diagnostics setting; the
current source alone is not permission to create/merge/apply it.

Run the normal gated deployment workflow under the separately approved candidate
runtime arrangement; record exact installed interpreter/wheel/source versions.
If that requires a Factory rollout, stop for separate rollout approval first.
Within the bounded diagnostics window, record FAILED/health evidence and delivered
incident with human label. Legacy worker must remain fenced. Run the bounded model
command only after explicit provider-call approval; record route/budget/outcome,
not model prose/credentials. Require a supported proposal or an honest fixed
escalation. Check scope v2 against the actual failed commit and refresh the
root-owned Git mirror explicitly if required.

**Advance conditional approval B2:** before starting the terminal session, agree
on the exact repository (`shamsway/octant-private`), incident issue number,
incident/run and reviewed candidate executables. B2 authorizes one send only if
the local preview matches that repository/issue, the operator approves the complete
shown body and independently verifies the failure remains unresolved. This is
conditional authorization in advance, not a chat approval between preview and send.
The five-minute (300s) transfer expiry is unchanged.

Root reviews/installs [scripts/manual-publish-investigation.sh](../scripts/manual-publish-investigation.sh)
and pins its candidate executable/repository paths during separately approved
provisioning. With B2 already approved, run this **single root-run sequence** in
one terminal session:

```sh
sudo /root/reviewed/manual-publish-investigation.sh INCIDENT RUN PREAGREED_ISSUE
```

It exports as matt, imports/previews as publisher without loading credentials,
checks the exact pre-agreed destination, displays the complete marker/body, and
asks the local operator to type `SEND unresolved ISSUE` only after verifying the
failure is still unresolved. It then temporarily enables both switches and starts
the fixed encrypted-credential publisher unit with `--send --confirm-public-write`.
The broker rechecks the 300s age and saved preview binding before a first POST.
If local review takes too long, abort and restart with a fresh export; never extend
expiry. No model call, deployment change or automatic POST retry is in this script.

EXIT/INT/TERM/HUP traps disable switches on success, refusal, error or interruption,
stop/remove the temporary unit override and reload the manager. No shell trap can
handle SIGKILL or power loss: after either, keep the unit stopped and manually
verify both switches false before any further operation. A root-held lock rejects
concurrent sessions. Private operator/publisher preview/result files are retained for review; remove
that temporary metadata directory only after reviewing it before another session.
Outbox/locks/token audit are never removed or restored. `status_write_failed` is a
separate metadata warning: a delivered primary result remains delivered with its
original exit code; inspect the outbox/status path rather than resending blindly.
Unknown POST response retains an uncertain receipt for exact marker/author/body
reconciliation and never authorizes another POST.

**Separate approval B3:** operator-approved repeat of the same confirmed command
(with the temporary switches restored only for that invocation) must return the
same delivered result, no mint/POST and no duplicate. Count the remote marker
comments read-only. Check status counts/token outcome/expiry/import result through
inspect/doctor. Revert the controlled failure through the normal approved workflow
and prove healthy recovery separately; publishing a finding is not recovery proof.

## C. Mandatory window cleanup

Approval B must include cleanup: turn temporary target diagnostics off again,
restore the collector configuration, stop the publisher unit and keep both broker
switches false. Record metadata-only config readback and normal service health.
If the planned window expires or any acceptance step fails, perform this cleanup
immediately and leave SHA-201 In Progress with the unproven gate stated. No
unattended sending, timers or scheduled model investigations are enabled afterward.

## D. Release plan (item 6, separate approval after acceptance)

1. Verify exact series/fork/PR CI green with zero skips; preserve scripts/test-linux.sh
   Linux evidence, complete REVIEW.md and A–C acceptance artifacts. Release notes:
   PR3 token/plan-lineage fixes plus PR4 evidence, bounded transport, operator-only
   publication, scope v2 and one-way status. Include Option B risk and SHA-245 deferral.
2. Only at this approved step, take PR3 and PR4 out of draft, review their base/order,
   merge through the existing sre-agent rollout pattern, publish source before
   installing. Keep series first, then fork and exact merge/content evidence.
3. Follow docs/deployment-lifecycle.md Barlow pause/drain → immutable runtime build
   with hashes → install --no-start → preverify/credential-role checks → controlled
   resume → postverify/health. Inspect actual running runtime/tag first; do not
   assume the historic 40be81b runtime is still current. Record its rollback target.
   Malformed routing receipts fail preverify; do not delete receipts to proceed.
4. Keep diagnostics and publication off at rollout. Verify runtime source/wheel,
   units, dashboard, doctor/status and scheduled dispatch/apply separately from
   empty-queue success. Tag deployed/barlow-SHA only after exact-runtime proof and
   CI. Preserve rollback executable, policies and encrypted credential reference.
5. Close SHA-201 only when applicable live gates and operator acceptance pass.
   SHA-245 remains Backlog. No code-editing/proposal execution or deployment authority
   is added to the publisher in this release.
