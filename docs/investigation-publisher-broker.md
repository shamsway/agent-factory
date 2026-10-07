# Dedicated publisher broker (inactive source integration)

The operator retains a separate Barlow publisher OS account. App key delivery
is a manual root-owned systemd encrypted credential, provisioned from the operator
Private vault and loaded only by the dedicated publisher system unit through
`LoadCredentialEncrypted=`. This replaces the proposed 1Password service account,
vault and materialization job. No accounts, credentials, units or hooks are
created by this source. See [operator setup](investigation-publisher-setup.md).

## Configuration and access

Install the `publisher` Python extra only in the dedicated publisher environment.
`factory investigation-broker` never calls `config.load()` and never reads the
shared Factory host config. It uses an absolute `--policy` JSON file owned by
root/the publisher, under ancestors that root/the publisher owns and no other
account can write. Run as the configured non-root `publisher_uid`.

Policy schema (replace IDs and paths during separately approved provisioning):

```json
{
  "version": 1,
  "publisher_uid": 1001,
  "store": "/var/lib/factory-publisher/octant-private",
  "enabled": false,
  "allow_publish": false,
  "app": {
    "app_id": 1,
    "installation_id": 2,
    "repository_id": 3,
    "repository": "shamsway/octant-private",
    "login": "shamsway-factory-findings[bot]",
    "key_file": "/run/credentials/factory-publisher.service/app-key"
  }
}
```

`store` is a separate broker-owned snapshot/outbox directory, not a worker-writable
`.factory` path. Provision the exact bytes of `broker-store.json` as canonical JSON
`{"repository":"shamsway/octant-private","version":1}` (no newline). The full
snapshot must contain only root/publisher-owned regular files/directories, no
symlinks or group/other writes. Its scan is capped at 10,000 entries and two seconds.
Broker preview/send accepts only `--incident` and `--run`, never body, destination,
paths, model instructions or tokens. Both policy switches plus
`--send --confirm-public-write` are required for a write. Preview makes no token
request and never calls a model. A terminal outbox replay returns without minting.

The App key file must be private (no group/other permission) and all ancestors
protected. The optional cryptography dependency signs RS256 in process; keys,
JWTs and installation tokens never enter shell argv or stdout. Token minting
checks App ID/slug, installation account/permissions/suspension, then explicitly
requests one repository ID with Issues write and Metadata read. Returned scope,
expiry and token shape must match; no permission fallback. Each operation makes
at most three bounded mint/identity calls; no automatic retries. Tokens are cached
in memory only and reused only while more than 60 seconds remain. There is no
in-process refresh: the three-request lifetime budget never resets. After expiry
(or the 60-second safety margin) this instance refuses. A fresh, explicitly invoked
one-shot process can mint a new token. Unknown mint outcomes are not retried
automatically.
Status results contain only outcome/expiry/validity; shared inspect/doctor do not
yet have a cross-account broker-status channel.

## Provisioning still required before unattended operation

The operator must manually provision the App key into a root-owned encrypted
systemd credential, with manual re-provision for rotation. Only the dedicated
publisher system unit loads it. No 1Password service account, vault or key-sync
job is required. Never expose it to `matt`, Factory units, install/apply config,
workers or a general token-vending interface. No credential has been provisioned
by this source slice.

A trusted transfer mechanism must produce an atomic publisher-owned snapshot of
incident routing, ledger, manifests, diagnostic bundles and validated model result.
It must authenticate the producer and reject arbitrary worker-supplied findings,
paths or destinations. Copying worker-controlled files and changing ownership is
not proof of provenance. No socket listener/queue admission is enabled in this
slice. Do not activate the broker until this transfer boundary is reviewed and
proven on Barlow. This deliberate gap is an activation blocker, not live isolation
proof. Outbox state must remain on the publisher side across snapshot refreshes;
never replace uncertain receipts or rebuild the store to retry a post.

## Approved source scope

`investigation_scope.load_policy` reads the same protected operator-file boundary.
Its exact closed schema is version=2, approved=true, repository, approved_at,
bindings. Each binding has hashed job/namespace and a list of approved paths.
`approved_at` is review provenance only. `prepare_from_policy` rechecks selected
paths at the actual failed revision: tracked regular blobs, approved extensions,
no secrets/traversal and at most 1 MiB each. New merge commits and changed contents
do not require approval; changed mappings (rename/new job/removed file) refuse
with a fixed code and require operator re-approval. No revision equality or blob
pins remain. The Octant artifact approves 14 own-file mappings, namespace default,
reviewed at 25ae5fddb8949d2478578306adb5a9100cf40f2f. Approval authorizes no patch
or production operation.

Full failed-deployment → evidence → model → scoped proposal → publisher acceptance,
manual encrypted-credential provisioning, cross-account transfer and service deployment remain
unproven. Diagnostics stay off; PR3/PR4 stay draft until the applicable gates pass.

### Token audit

Before each App identity/installation/mint request, the broker atomically writes
`publisher-token-status.json` with reserved request count (maximum three), outcome,
expiry and validity booleans only. Failure/ready states are recorded without
provider error text or credentials. `investigation-broker --policy PATH --status`
reads that closed schema without minting. Because tokens are never persisted, a
later status command honestly reports no cached valid token even if the last
mint's reported expiry is in the future. Shared inspect/doctor integration awaits
a reviewed cross-account metadata channel. A failed/unknown mint is not retried
within an invocation; any operator retry creates a new one-shot token budget.

## Validation and error behavior

Queued rows re-render and compare the durable binding before token minting. The
first POST revalidates again inside deliver. Uncertain rows bypass fresh evidence
until exact marker/body/author reconciliation; terminal rows return without a token.
The CLI publishes only allowlisted fixed PublisherRefused/EvidenceRefused codes;
unknown exceptions become publisher_unavailable, without tracebacks/error text.

Broker-only release dependencies are pinned with wheel SHA-256 hashes in
requirements/publisher-wheels.txt. See the setup guide for isolated offline install.
CI and scripts/test-linux.sh install those dependencies in disposable test environments;
worker/service installs remain unchanged. The transfer design is separately reviewable
in [investigation-transfer-design.md](investigation-transfer-design.md), with no transfer
implementation in this slice.
