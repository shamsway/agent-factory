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
