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
  "version": 2,
  "publisher_uid": 1001,
  "snapshots": "/var/lib/factory-publisher/snapshots",
  "state": "/var/lib/factory-publisher/state",
  "status_file": "/var/lib/factory-publisher-status/status.json",
  "repository_root": "/opt/factory-publisher/octant-private",
  "scope_file": "/etc/factory-publisher/scope.json",
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

`snapshots` and `state` are separate publisher-owned directories, with neither
nested in the other. Each requires canonical `broker-store.json` bytes
`{"repository":"shamsway/octant-private","version":1}` (no newline). The status
parent requires the same sentinel. No worker ownership, symlinks/devices or group/
other writes are allowed. Recursive store scans are capped at 10,000 entries and
two seconds. Both policy switches plus `--send --confirm-public-write` and a
matching saved preview are required before a first POST. Preview makes no token
request and never calls a model. Terminal replay returns without minting.

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
Status results contain only fixed metadata. See [Option B](investigation-option-b.md)
for one-way status, import and the accepted unauthenticated evidence risk. There is
no unattended operation. The encrypted key is manually provisioned by the operator;
no 1Password service account, vault, sync job or token-vending interface is added.

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
mint's reported expiry is in the future. Shared inspect/doctor read only the publisher-owned status file. A failed/unknown mint is not retried
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
worker/service installs remain unchanged. The authenticated transfer design is
deferred to SHA-245; current operator transfer is described in Option B.
