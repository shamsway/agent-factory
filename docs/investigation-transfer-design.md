# Trusted publisher transfer — design for operator review

Status: future design deferred to **SHA-245**, 2026-10-07. It does not block
SHA-201 Option B. The current release uses [operator export/import](investigation-option-b.md)
and requires operator confirmation of every public write. No authenticated producer,
socket, host provisioning or diagnostic enablement is included. App-key delivery is manual
systemd encrypted credentials, not a 1Password service account/vault.

## Trust decision that must precede implementation

Today Factory, the evidence reader and workers run as `matt`. A Unix socket's
SO_PEERCRED identifying `matt`, a process name/executable path, a receipt in
`.factory`, or a hash supplied beside a bundle cannot distinguish the trusted
reader from a worker. Copying those files as root and changing ownership does
not authenticate their producer. The current journal/manifests are useful
correlation evidence, not cryptographic attestations against another `matt`
process. This design does not claim otherwise.

Proposed unattended boundary: a separate trusted evidence producer, with a root-
owned executable and policy, runs outside `matt` (a dedicated `factory-evidence`
OS account). It owns the authoritative incident/run identity records and its
attestation key. The publisher pins its public verification key. Lifecycle events
must reach that producer from an authenticated deployment executor identity or an
operator-approved import; moving only the reader while retaining a worker-writable
authoritative ledger does not solve the provenance problem. Establishing that
executor/ledger boundary is a prerequisite requiring operator review and a
separate source/deployment plan. Until it exists, use explicit operator-reviewed
imports for controlled acceptance only; never mark them as unattended proof.

## Producer and authenticated handoff

The trusted producer runs the deterministic evidence reader, correlates the
failed revision/run against its protected authoritative identity, validates the
bundle hash/schema/lineage/time, and constructs the projection. Model transport
receives that projection only. Model results return to the trusted producer for
closed-schema/hash/reference validation; a model/worker cannot choose destination,
path, publication prose or expand policy. The attestation covers repository,
incident/run, failed revision, destination, monotonic generation, content hashes,
policy versions, projection hash and result hash. Publisher verifies the pinned
producer signature and repeats its own fixed rendering/reference/scope checks.
No shared signing secret is supplied to `matt`.

Use a bounded producer-to-publisher socket restricted to the dedicated producer
UID (SO_PEERCRED), plus the signed manifest. Requests carry one generation and
allowlisted length-delimited objects, never filesystem paths, tokens, commands or
model prose for publication. Reject unknown fields, over-budget sizes, duplicate
JSON keys, unexpected object types and generations. A producer key rotation is
an explicit operator trust update, not a request option. Limits and schema details
must be finalized and reviewed before implementing this endpoint.

## Exact transferred objects

- Committed terminal failed-run identity and necessary resolution/ack/supersession
  state, anchored to the trusted lifecycle generation (including later success).
- Root incident identity and delivered issue mapping, with delivery certainty.
- Sanitized manifest and hash-verified structured evidence required by the reader;
  free-form logs/plans/config/credentials are excluded from this transfer.
- Immutable projection and closed-schema validated result, bound by hashes to the
  attested identity. Preserve timestamps and lineage, never refresh their ages.
- Operator scope-policy digest/version. Scope approval is a job/file mapping;
  source files are rechecked at the actual failed commit. No worker-supplied policy.

If the current evidence reader requires additional source objects, review a
minimal export format rather than granting broad access to the Factory store.
The exporter must not accept arbitrary `.factory` paths from the submitter.

## Atomicity, durable state and replay

Publisher stages a generation in a private directory with no links/devices,
checks byte/file/depth caps, signature and every digest, fsyncs files and directory,
then atomically renames the complete snapshot into its generation directory on
the same filesystem. Commit an immutable generation pointer only after validation.
Interrupted/incomplete staging is never selectable. Concurrent transfers serialize
per incident/run; no partly updated ledger/manifest/projection combination.

Publication outbox, locks, post intents, uncertain receipts and token audit stay
in a separate publisher-owned durable state directory. They are not transferred,
replaced, deleted or rolled back with snapshots. Current combined-store broker
layout must be split before integration; this document does not claim that split
is implemented. Persist generation/hash bindings with the outbox.

Replayed identical generation is idempotent. Lower generation is refused. Changed
binding for an already queued first POST blocks and requires review. A later
ack/success invalidates queued publication. For an uncertain POST, reconcile the
original destination/marker/body digest/author before evaluating new evidence;
never automatically repost. Unknown transfer acknowledgement retries only the
same immutable generation; it does not authorize a GitHub POST. Missing/bad
signature, stale generation, inconsistent lineage and resource limits are fixed
refusals, with a bounded local operator-visible receipt.

## Status to inspect/doctor

The publisher emits a fixed status document containing schema/generation/time,
outbox state counts, token outcome/expiry (no token), transfer refusal enum and
freshness. A root-owned one-way export copies only that closed schema atomically
into a read-only status directory visible to `matt`; mode ownership and freshness
are checked by inspect/doctor. Publisher implementation accepts no requests on
this status path, and it cannot carry paths, prose, credentials or commands.
Missing/stale/unavailable status is reported honestly; it is not permission to
send. The status exporter and consumer are still design-only.

## Acceptance required

Prove worker UID cannot connect as producer, forge signature, read App credentials,
modify publisher snapshots/outbox or write status. Exercise interrupted transfer,
replay, lower generation, changed binding, later success/ack, timeout/size limits,
uncertain GitHub delivery and stale status. These must precede a controlled real
failure and unattended enablement. No implementation until operator design review.
