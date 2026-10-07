# Dedicated publisher broker (inactive source integration)

The operator approved a separate Barlow publisher OS account and its own
1Password service account restricted to a publisher-only vault. No accounts,
vaults, key copies, systemd units, or scheduled hooks are created by this source.
The existing operator Private-vault key remains unchanged.

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
in memory only and refresh 60 seconds before expiry. One-shot processes mint anew.
Status results contain only outcome/expiry/validity; shared inspect/doctor do not
yet have a cross-account broker-status channel.

## Provisioning still required before unattended operation

A separate publisher-only 1Password service account/vault must supply the App key
to a protected systemd credential. This source does not implement or install the
vault-to-credential materialization job. Do not give the Factory worker account
the 1Password credential or App key, or a general token-vending interface.

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
Its exact closed schema is version=1, approved=true, repository, commit, bindings.
Each binding has hashed job/namespace and files containing exact path/blob pairs.
`prepare_from_policy` requires the failed revision to equal the approved revision,
and rechecks selected regular Git blobs at that revision. It does not repin policy.
The Octant artifact approves 14 own-file mappings at
25ae5fddb8949d2478578306adb5a9100cf40f2f with namespace default. Future failed commits
need a newly approved policy or a separately reviewed revalidation rule. No patch
or production operation is authorized by scope approval.

Full failed-deployment → evidence → model → scoped proposal → publisher acceptance,
1Password materialization, cross-account transfer and service deployment remain
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
