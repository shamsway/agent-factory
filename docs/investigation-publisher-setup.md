# Dedicated publisher operator setup (not executed)

Decision, 2026-10-07: keep the separate publisher Unix account; replace the proposed
1Password service account/vault/materialization job with manual App-key delivery
from the operator Private vault into a root-owned **systemd encrypted credential**.
No unattended transfer or release is authorized by these instructions. Execute
only after separately approving host provisioning and checking Barlow's installed
systemd supports `systemd-creds` and `LoadCredentialEncrypted=` for system services.

## Existing Factory configuration

Barlow currently selects `/home/matt/.config/agent-factory/config.toml`. Confirm
`config_path` via the reviewed interpreter's `factory inspect --json` before any
edit. `/home/matt/.config/factory/config.toml` takes precedence if present; doctor
warns when both files exist. Never create the preferred file just to add settings.
Never print/read the shared host config by hand. The dedicated broker uses its
own protected policy and **does not read either shared host file**.

The App is `shamsway-factory-findings`, installed only on octant-private with
Issues write/Metadata read. The manual token was used for the approved #101
comment and expires; no manual token is copied into the new broker. Both shared
host publication switches stay false. App key never enters `[install].env`,
`[apply].env`, a Factory unit, worker environment or `matt`-readable path.

## 1. Prepare broker-only dependencies during release

Use a clean publisher virtual environment on the target Linux architecture and
reviewed Python version, separate from every Factory worker/service runtime.
`requirements/publisher-wheels.txt` pins cryptography 46.0.7 and its cffi/pycparser
closure using wheel hashes from versioned PyPI metadata. Download **binary wheels
only**; no source builds or unpinned resolver fallback:

```sh
publisher-venv/bin/python -m pip download --require-hashes --only-binary=:all: \
  -r requirements/publisher-wheels.txt --dest publisher-wheelhouse
publisher-venv/bin/python -m pip install --no-index --find-links publisher-wheelhouse \
  --require-hashes --only-binary=:all: -r requirements/publisher-wheels.txt
```

Archive wheel filenames/SHA-256, Python/architecture, pinned requirements file and
Factory source/wheel digest with release artifacts. Verify the downloaded hashes
again on Barlow. Install the reviewed Factory wheel with `--no-deps` into this
broker environment after separately supplying its ordinary pinned/hash-verified
runtime dependencies (tomlkit, as in the release process). Run focused broker/RSA
and missing-cryptography tests there, followed by metadata-only dependency checks.
CI/local Linux checks exercise this dependency set in disposable test environments;
they do not install cryptography into existing worker or service runtimes.

## 2. Encrypt and install the key, without a plaintext file

Use a trusted **root operator terminal on Barlow**, never a `matt` worker shell or
agent tool session. Obtain the PEM from the operator Private vault manually.
Do not export it into an environment variable, shell argument, clipboard log,
shell history or terminal output. No local/remote plaintext key file is needed.
Run this reviewed procedure by hand. It reads a hidden paste from `/dev/tty`, sends
bytes only through the encryptor's stdin pipe, and writes only encrypted data.
It is documentation, not an automated provisioning job.

```sh
sudo python3 - <<'PY'
import os
from pathlib import Path
import subprocess
import termios

assert os.geteuid() == 0
store = Path('/etc/credstore.encrypted')
store.mkdir(mode=0o700, exist_ok=True)
assert not store.is_symlink() and store.stat().st_uid == 0
assert store.stat().st_mode & 0o077 == 0
stage = store / 'factory-publisher-app-key.cred.new'
assert not stage.exists() and not stage.is_symlink()
os.umask(0o077)
with open('/dev/tty', 'r+') as terminal:
    original = termios.tcgetattr(terminal.fileno())
    hidden = termios.tcgetattr(terminal.fileno())
    hidden[3] &= ~(termios.ECHO | termios.ECHONL)
    lines = []
    terminal.write('Paste the PEM key; input is hidden. Finish at its END line.\n')
    terminal.flush()
    try:
        termios.tcsetattr(terminal.fileno(), termios.TCSAFLUSH, hidden)
        while True:
            line = terminal.readline()
            if not line or sum(map(len, lines)) + len(line) > 32768:
                raise RuntimeError('key input refused')
            lines.append(line)
            if line.strip() in ('-----END PRIVATE KEY-----', '-----END RSA PRIVATE KEY-----'):
                break
    finally:
        termios.tcsetattr(terminal.fileno(), termios.TCSAFLUSH, original)
        terminal.write('\n')
    key = ''.join(lines).encode()
try:
    subprocess.run(['openssl', 'pkey', '-check', '-noout'], input=key,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    subprocess.run(['systemd-creds', 'encrypt', '--with-key=host', '--name=app-key',
                    '-', str(stage)], input=key, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, check=True)
    stage.chmod(0o600)
    assert stage.stat().st_uid == 0
    with stage.open('rb') as handle:
        os.fsync(handle.fileno())
    os.replace(stage, store / 'factory-publisher-app-key.cred')
    fd = os.open(store, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
finally:
    stage.unlink(missing_ok=True)
    del key, lines
print('Encrypted credential installed; no plaintext key file created.')
PY
```

Do not use `--with-key=null`. Host-key encryption requires root access to the
machine's credential secret. Do not run `systemd-creds decrypt` to a terminal or
file. Deleting Python references is not a promise of memory zeroization; exit the
operator process and do not capture core dumps. Use a trusted terminal with input
logging disabled. This procedure creates **no plaintext file to shred**. If an
operator deviates and creates one, stop, treat it as a handling deviation and
securely remove it before proceeding; `shred` is not reliable on SSD/COW storage.
Do not offer shredding a regular file as an equivalent to this memory/pipe-only
procedure. The unit's transient plaintext credential mount is removed by systemd
when the unit stops; never copy it elsewhere.

## 3. Unit boundary and verification (separate approval required)

The root-owned **system** unit (not `matt`'s user manager) must contain:

```ini
[Service]
User=factory-publisher
Group=factory-publisher
UMask=0077
LoadCredentialEncrypted=app-key:/etc/credstore.encrypted/factory-publisher-app-key.cred
```

Only this unit references the credential. Root owns its executable, environment
and policy; workers cannot change them or start arbitrary commands as this user.
Keep both publisher-policy switches false. Set `key_file` to the credential mount
for the reviewed unit; use the manager-provided `$CREDENTIALS_DIRECTORY` in a
trusted launcher when wiring it, not a worker-supplied path. Systemd unit path
and broker policy must agree. Do not grant `matt` membership in publisher groups,
read ACLs, sudo/systemd rules for arbitrary publisher execution, or access to the
publisher's process memory. Privileged human root access remains trusted.

Before any mint/write, perform separately approved local-only verification through
a temporary check-only system unit with the same User and LoadCredentialEncrypted
settings. Its trusted checker runs `openssl pkey -check -noout -in
<credential-mount>/app-key` with stdout/stderr suppressed and returns only a fixed
pass/fail. Check filesystem owner/mode metadata; as unprivileged `matt`, verify the
credential is unreadable, and check the key is absent from Factory configuration,
unit environments and workers using purpose-built status tools, never grep/cat
secret-bearing files. Stop the check unit and verify the credential mount is gone.
Do not invoke broker send or model/provider calls for this filesystem check.

An exact check-only invocation, after provisioning the account and the isolated
broker environment, is:

```sh
sudo systemd-run --wait --collect --unit=factory-publisher-key-check \
  --property=User=factory-publisher --property=Group=factory-publisher \
  --property=UMask=0077 --property=LimitCORE=0 --property=RuntimeMaxSec=30 \
  --property=LoadCredentialEncrypted=app-key:/etc/credstore.encrypted/factory-publisher-app-key.cred \
  /opt/factory-publisher/venv/bin/python -I -c '
import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
try:
    path = Path(os.environ["CREDENTIALS_DIRECTORY"]) / "app-key"
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    assert isinstance(key, rsa.RSAPrivateKey) and key.key_size >= 2048
except Exception:
    print("credential check failed")
    raise SystemExit(1)
print("credential check passed")
'
sudo -u matt test ! -r /run/credentials/factory-publisher-key-check.service/app-key
sudo test ! -e /run/credentials/factory-publisher-key-check.service/app-key
```

The first command verifies actual readability/type inside the credential unit,
not merely the existence of encrypted bytes on disk. The two following commands
check unprivileged access and post-unit mount cleanup; they alone are insufficient
proof because the unit uses its own mount namespace. Root must also review the
unit's User, credential reference and filesystem access metadata. If the checker
fails or the mount remains, stop the check unit, investigate and keep publishing
off. Never copy/decrypt the key out to troubleshoot. Key-check commands perform
no GitHub/provider request and leave no plaintext file for shredding.

This is a procedure for future provisioning, not a shipped or enabled service.
Trusted transfer design review is still required; a key mount alone does not
activate the broker or prove producer authenticity.

## 4. Manual rotation

After separately approving rotation, generate a replacement App key and keep it
in the operator Private vault. Re-run the no-plaintext procedure above; `.new` is
encrypted and atomically replaces the installed encrypted file. Never overwrite a
live plaintext mount. Re-run the local-only check unit, stop it, and verify cleanup.
The next authorized broker invocation loads the new encrypted credential. Revoke
the old App key only after separately approved App verification succeeds; do not
retry an uncertain GitHub POST to test rotation. No Factory restart/install or
worker/service environment change is part of rotation. Existing installation
tokens can remain valid until expiry; key rotation is not guaranteed token revocation.

References: [systemd encrypted credentials](https://github.com/systemd/systemd/blob/main/docs/CREDENTIALS.md),
[systemd-creds options](https://github.com/systemd/systemd/blob/main/man/systemd-creds.xml).

## 5. Option B account, storage and mapping installation

This is an **operator-run provisioning plan**, not authorization to execute it.
Use the immutable reviewed candidate paths/hashes recorded in REVIEW.md. Root
creates a non-login `factory-publisher` system account with no sudo rights. The
operator is trusted root; `matt` and dispatched workers must have no noninteractive
sudo/polkit rule granting root, arbitrary `systemd-run`, this service start/edit,
or arbitrary execution as `factory-publisher`. Check the actual host rules before
claiming isolation; do not remove existing host privileges without a separate plan.

Example root-only directory provisioning, after checking names/UID conflicts:

```sh
useradd --system --user-group --home-dir /var/lib/factory-publisher --shell /usr/sbin/nologin factory-publisher
groupadd --system factory-transfer
usermod --append --groups factory-transfer factory-publisher
install -d -o factory-publisher -g factory-publisher -m 0700 /var/lib/factory-publisher
install -d -o factory-publisher -g factory-publisher -m 0700 /var/lib/factory-publisher/snapshots /var/lib/factory-publisher/state
install -d -o matt -g factory-transfer -m 2750 /var/lib/factory-transfer
install -d -o factory-publisher -g factory-publisher -m 0755 /var/lib/factory-publisher-status
install -d -o root -g factory-publisher -m 0750 /etc/factory-publisher
install -d -o root -g factory-publisher -m 0750 /opt/factory-publisher
```

The transfer group grants publisher read/traverse on matt's staging directory;
it grants matt **no** access to publisher state, key or executable. Export produces
0640 files in this setgid directory. Check group inheritance/readability using a
synthetic export before using real incident data. Root installs the broker v2
policy example from investigation-publisher-broker.md, replacing the nonsecret
App IDs, configured UID and all exact paths. Mode 0640 root:factory-publisher;
both switches false. Create the exact no-newline sentinel in snapshots, state and
status directories, mode 0600 in the private stores, 0644 in the status directory:

```sh
printf '%s' '{"repository":"shamsway/octant-private","version":1}' > /var/lib/factory-publisher/snapshots/broker-store.json
printf '%s' '{"repository":"shamsway/octant-private","version":1}' > /var/lib/factory-publisher/state/broker-store.json
printf '%s' '{"repository":"shamsway/octant-private","version":1}' > /var/lib/factory-publisher-status/broker-store.json
chown factory-publisher:factory-publisher /var/lib/factory-publisher/{snapshots,state}/broker-store.json /var/lib/factory-publisher-status/broker-store.json
chmod 0600 /var/lib/factory-publisher/{snapshots,state}/broker-store.json
chmod 0644 /var/lib/factory-publisher-status/broker-store.json
```

Install the already accepted **scope v2** artifact as
`/etc/factory-publisher/scope.json`, root:factory-publisher 0640. Record its SHA-256
against the accepted artifact (14 namespace-default job/file mappings reviewed at
25ae5fd). Root prepares a read-only Octant Git mirror at
`/opt/factory-publisher/octant-private`, including the actual failed commit; no
worker writable ancestors, alternate object stores, replace refs or symlinks.
Root refreshes it explicitly if a later failed commit is missing. The broker never
fetches or uses worker Git credentials. A new job/path mapping needs operator
approval; ordinary changes to contents do not change scope v2 approval.

Install the source and dependency wheels in a root-owned, publisher-readable venv
under `/opt/factory-publisher/venv`; workers cannot write any ancestor. Record all
wheel SHA-256 values including Factory and tomlkit, install only reviewed hashes
with `--no-index --require-hashes --only-binary=:all:` from an offline wheelhouse.
The earlier broker dependency instructions are one part of this manifest; **do
not** resolve/install ordinary dependencies online on Barlow. No worker runtime
or service venv is replaced during publisher provisioning.

Root installs a **non-enabled oneshot** system service. No timer or socket. Use a
fixed `ExecStart` for the one approved operation, edited only by the root operator:

```ini
[Unit]
Description=Operator-confirmed Factory investigation publisher
[Service]
Type=oneshot
User=factory-publisher
Group=factory-publisher
SupplementaryGroups=factory-transfer
UMask=0077
LimitCORE=0
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/factory-publisher /var/lib/factory-publisher-status
LoadCredentialEncrypted=app-key:/etc/credstore.encrypted/factory-publisher-app-key.cred
ExecStart=/opt/factory-publisher/venv/bin/factory investigation-broker --policy /etc/factory-publisher/policy.json --verify-token
```

`--verify-token` is a separately approved live GitHub operation, never a default
boot/start action. There is intentionally no `[Install]` section. Keep the unit
stopped. Root manually changes ExecStart to one of the reviewed import/preview/
confirmed-send invocations from the acceptance plan before starting it. Never
read ExecStart arguments from staging/status files, accept an arbitrary command
from matt, or install a service-start permission for workers. For preview/import,
root can instead run the exact broker command as the publisher without loading a
credential; those operations do not access the key. With no automatic sending,
root edits the two policy switches only during the confirmed live test.

Using the reviewed configuration command/API on the **actually selected** existing
host config, set `publisher.status_file` to
`/var/lib/factory-publisher-status/status.json` and `publisher.status_uid` to the
new numeric UID. Keep existing shared publisher switches off. Verify with
`factory inspect --json` and doctor; neither should see a valid cached token.
Missing/stale status is honest until an operator runs an import/preview/status
refresh. Check all owner/mode metadata and negative access tests as matt; do not
print key material, host config, decrypted credentials or token responses.

## 6. Rollback and removal

Stop the publisher unit and restore both broker switches false before any
rollback. Keep snapshots and **all durable outbox/locks/token audit** in place;
never roll them back with the executable. Uncertain posts require exact remote
comment reconciliation, never outbox deletion or a new incident ID to repost.
Restore the prior immutable publisher venv/policy only after compatibility review.
Factory service rollback follows its normal separately approved rollout procedure.

For removal, disable any accidentally enabled unit and remove root-owned unit/
credential references, then remove the encrypted credential only after deciding
whether a future restoration is needed. Revoke the App key in GitHub if retiring
it; installation tokens may remain valid until expiry. Remove status config using
the selected configuration path and report not configured. Archive durable state
privately for dedupe/audit before any separately approved account/data deletion.
Do not delete the old Private-vault key or vault content as part of this guide.
Manual key rotation remains section 4. The future authenticated transfer design
is SHA-245; it is not required for this operator-confirmed release.

## Conditional acceptance sequence

The B/B2 acceptance plan now supports advance **conditional** approval for an exact
repository/incident issue and unresolved failure. Root reviews and installs
`scripts/manual-publish-investigation.sh` in a root-owned location, pins its candidate
exporter and broker paths, and runs it manually in one terminal session. The script
exports as matt, imports/previews as publisher, checks the pre-agreed destination,
displays the complete body, and requires a local unresolved-failure confirmation.
The transfer age stays 300 seconds. It creates a temporary root-owned ExecStart
override for the already provisioned encrypted-credential publisher service and
disables both switches in EXIT/INT/TERM/HUP cleanup, including errors. No worker
can install/invoke it as root; no scheduled invocation or sudo grant is added.
After SIGKILL/power loss, manually verify the stopped unit and disabled switches.
The script is a future operator procedure, syntax-checked only, not host-tested
or run by this source slice. See investigation-barlow-acceptance.md for approvals,
cleanup and exact replay rules.
