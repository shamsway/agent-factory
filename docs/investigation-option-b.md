# SHA-201 Option B: operator-controlled publication

Decision: 2026-10-07. This is the release boundary. The authenticated producer,
factory-evidence account, signed attestations, socket and authenticated executor
are deferred to SHA-245. See [future design](investigation-transfer-design.md).
No background sending, dispatcher integration, timer or automatic fallback is
introduced. Dedicated publisher user and encrypted App credential remain required.

## Residual risk

A compromised `matt` process can forge incident evidence and cause a misleading
fixed-template finding to be **proposed** on an octant-private incident issue.
It cannot choose free text, post without operator confirmation, mint tokens, or
touch code, PRs or deployments through this publisher. Root/operator compromise
is outside this boundary. Hashes prove internal consistency, not producer identity.
Operator review of the exact destination and complete body is mandatory each time.

## Export and import

As `matt`, using the reviewed candidate interpreter and the actual selected host
configuration, invoke:

```sh
factory investigation-export --incident INCIDENT --run RUN --staging-dir /var/lib/factory-transfer
```

The exporter first runs the original evidence reader (journal replay including
acknowledgement/later success, manifest and diagnostics hash/lineage/time checks),
checks the completed model receipt and renders the fixed publication. It exports
one closed object: identities, timestamps, hashed job/version pairs, structured
projection, validated result and exact publication binding. It does **not** copy
raw diagnostics, task prose, journal errors, credentials or host configuration.
No supplied relative file paths are used. Staging filename is derived from the
repository/incident/run; the existing operator-provisioned setgid directory gives
the publisher read access to the mode 0640 export. The publisher has no staging
write permission. Staging is untrusted input, never a command queue.

The publisher-side one-shot command is run by the root operator through the
reviewed credential unit, with `--import-bundle /var/lib/factory-transfer/HASH.json`.
It bounds input to 256 KiB, rejects duplicate/unknown keys, links/devices, changed
hashes/bindings/identities, unsupported rows/states, invalid time windows, unmatched
job/version/task-event lineage and unsupported model evidence references. Proposal
scope v2 is rechecked against tracked regular files at the actual failed commit.
The original raw manifest/diagnostic hashes are retained as correlation metadata;
they are not independently rehashed without those private raw files. The import
trusts the exporter for original source validation and resolution at export time.
This is the explicit Option B provenance limitation, not an authenticated handoff.

Snapshots expire five minutes after export. Re-export after a delay or any source
change; current-state observations retain their original one-hour bound. Historical
version-bound rows do not acquire a one-hour expiration. The operator must check
that the failure remains unresolved immediately before confirming publication;
imports cannot observe changes to the matt ledger made after export.

A publisher-only import lock protects immutable generation directories. Import
writes a private stage, renames it, then atomically changes the incident/run pointer.
A failure before pointer replacement leaves the prior generation selected. A lost
receipt after replacement can be retried idempotently. Old generations are retained;
no pruning or automatic rollback is added. Durable outbox/locks/token audit live in
another directory and are never restored/replaced by import.

## Preview and send

Preview uses no key, model or GitHub request. It renders the exact marker/body and
destination and saves their binding in publisher-owned state. Root/operator reviews
that output, then separately invokes `--send --confirm-public-write` for the same
incident/run with both broker policy switches enabled. A changed binding requires
a new preview. Switches remain off outside the controlled test window. CLI flags
are human confirmation, not a cryptographic identity mechanism: do not grant matt
sudo, systemd or executable access permitting invocation as the publisher.

Queued sends revalidate the imported snapshot and preview before minting and again
before the first POST. Uncertain receipts reconcile exact marker/body/publisher
login **before** needing fresh evidence; they never issue another POST. Delivered,
blocked and failed rows return without minting. Import cannot reset any of them.
There is no unattended or scheduled sending in this release.

## One-way operator status

Every import/preview/send writes a fixed metadata file in a publisher-owned,
matt-readable directory: outbox state counts, last token outcome/reported expiry,
and last import result/time. No token survives the process and expiry is not a
claim of a reusable credential. Failure diagnostics contain enum codes only.

Configure only `publisher.status_file` and `publisher.status_uid` in the existing
selected Factory host config through the reviewed configuration path. Both shared
publication switches remain false. `inspect --json` reports `publisher_status`;
doctor reports missing/stale/malformed status honestly, pending outbox counts,
expired/failed token operations and refused imports. Status expires after five
minutes; because there is no timer, stale between operator sessions is expected.
The file accepts no requests or directions. Factory never writes it or invokes
the publisher. A failed status write adds `status_write_failed: true` without changing the primary
result or exit code. Publication may already have occurred; inspect the durable
outbox/status path rather than retry a POST.
