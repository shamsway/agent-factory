# Deployment incidents and notification recovery

`factory apply` records terminal deployment state first. A failed current run
then enters a durable incident outbox under `.factory/incidents/` (directory
0700, records 0600). Artifact and incident delivery do not change deployment
status, authorize repair, acknowledge failure, or block candidate selection
when delivery fails. Escalation queues locally; delivery runs once at the end
of an apply pass, after target/backend locks are released. Dry runs do not
create outbox entries or send notifications.

The root identity hashes repository, target and original ticket. Replays and
additional failed attempts on that ticket share the root. Records link the
ticket, explicit PR, commit, run and sanitized artifact manifest reference;
they contain no raw plan, log, environment or failure output. A missing manifest
is unavailable evidence. Private-plan paths are never included.

## Delivery and investigation

The outbox is persisted and synced before any GitHub create request. An
exclusive, nonblocking local store lock serializes writers/deliverers. A busy
store is reported and retried on a later pass; dashboard/inspect reads use
atomic records without taking this lock.

Delivery lists repository issues, including closed issues, through the REST
API and locates an exact stable HTML marker. It does not rely on lagged issue
search or a title match. Lookup stops safely if the ten-page bound is reached;
at 1,000 or more repository issue/PR entries a full lookup may not be possible.
It refuses creation on incomplete coverage rather than risk a duplicate.
Requests have a twenty-second maximum and the client has a sixty-second total
budget. Three create/update attempts survive restart; exhaustion becomes
`failed`. Lookup failures do not consume this side-effect budget; they remain
visible with a separate failure count. Errors store only exception types,
fixed diagnostic codes or HTTP status numbers, never provider output.

The GitHub identity is the same process environment/gh login used by
`apply.post_comment`; it does not substitute an install-role token from host
configuration or define a second fallback credential path. Ensure that this
identity can create and update repository issues and that the investigation
label exists before live activation. Verify credentials through Factory's
supported inspection commands rather than printing host config or tokens.

New issues receive `ready-for-investigation`: the existing worker gathers
evidence and posts findings, then hands control to a human. This is not the
implementation lane, and incident creation does not allow production writes.
Human approval, pinned revision gates, failed-run acknowledgement and interrupted
run reconciliation continue to apply to any later repair.

## Uncertain creation

Before sending create, the durable state becomes `uncertain`. A crash before
sending, lost success response, timeout, or malformed response can leave the
same state. Explicit GitHub 4xx refusals are known not-created outcomes:
403/422 stop for operator repair; 429 and transient conflicts remain pending
within the persisted side-effect budget. No manual absence confirmation is
needed for a definite refusal. Later delivery reconciles the marker. One matching issue is adopted;
multiple matches stop as ambiguous. No match after an uncertain create **never
causes automatic creation again**: absence is not proof of failure to create.

This deliberately trades automatic recovery for duplicate prevention. The
operator must manually check GitHub before rearming a missing uncertain create.
Independent controllers with separate stores are unsupported; this is a single
shared-store lock, not distributed exactly-once delivery.

## Operator commands

Run from the configured repository with its installed runtime:

```sh
factory incidents                            # read-only status and correlated run index
factory inspect --json                       # includes the same incident status
factory incidents --id incident-<24hex>      # inspect one root
factory incidents --deliver                  # replay current unacknowledged failures and deliver
factory incidents --retry incident-<24hex> --deliver
```

`--retry` first reconciles the remote marker and resets the delivery budget.
It cannot recreate an unavailable previously recorded issue or resolve multiple
matches. If an uncertain create has no match, inspect GitHub manually, including
closed issues and the stable marker. Only after confirming that no issue exists:

```sh
factory incidents --retry incident-<24hex> --confirm-not-created --deliver
```

The confirmation is a human assertion. It permits another create attempt and
must not be scripted in automatic retry. Operator retries are counted. Commands
print metadata, never provider output; uncertain/failed rows remain visible in
the read-only status until reconciled. Fix permissions/malformed local records
before retrying an `unavailable` store. Preserve the outbox in runtime backup,
upgrade and rollback; never restore an older outbox over active delivery state.

To associate a later failed repair with the same root (or from SHA-202 code,
use `enqueue(..., root_id=...)`):

```sh
factory incidents --id incident-<24hex> --attach-run deploy-<run-id>
factory incidents --deliver
```

The run must exist uniquely in the journal and belong to the same target/repo.
Replay preserves this attachment. The generated incident section is refreshed
idempotently while preserving text outside its markers. A newly attached
failure reopens the same issue and restores `ready-for-investigation`, removing
the prior `ready-for-human` routing label while preserving unrelated labels.
It does not reset a remediation budget or authorize another deployment.

The first real apply/delivery pass also queues current unacknowledged historical
failures from the journal. Acknowledged, superseded and subsequently successful
runs are excluded; review this backlog before activating. Corrupt records are
preserved and reported individually in `factory incidents`/inspection while
unrelated roots can still be queued and delivered. A corrupt record for the
same root is never overwritten; repair it before that root can proceed.

## Acceptance boundary

Unit/contract fixtures must prove replay, concurrent delivery, crash on either
side of create, lost response, transient API/rate-limit failures, ambiguity,
exhaustion and safe recovery. Those fixtures are separate from live GitHub
delivery and production failure/repair proof. Live acceptance should use an
isolated controlled failed target and reviewed permissions/notification scope;
do not fail a healthy production job to test notifications. This module does
not claim diagnostic collection (SHA-200), investigation proposals (SHA-201),
bounded remediation (SHA-202), or unknown-secret sanitizer hardening (SHA-238).
