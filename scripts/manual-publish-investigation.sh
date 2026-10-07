#!/usr/bin/env bash
# OPERATOR PLAN ONLY. Root installs/reviews paths before approval; no timer/hook.
# Pre-approved conditional B2: exact repo/issue + unresolved failure only.
set -euo pipefail
umask 0077
[[ $(id -u) == 0 ]] || { echo 'root_operator_required' >&2; exit 1; }
[[ $# == 3 && $1 =~ ^incident-[0-9a-f]{24}$ && $2 =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ && $3 =~ ^[1-9][0-9]*$ ]] || {
  echo 'usage: manual-publish-investigation.sh INCIDENT RUN PREAGREED_ISSUE' >&2; exit 1;
}
incident=$1 run=$2 issue=$3
repository=shamsway/octant-private
# Pin the installed service runtime identified by inspect during provisioning.
# The placeholder deliberately refuses to run until the operator pins that path.
service_runtime=/REPLACE_WITH_INSTALLED_SERVICE_RUNTIME
exporter_python=$service_runtime/bin/python
matt_repo=/home/matt/git/octant-private
broker=/opt/factory-publisher/venv/bin/factory
python=/opt/factory-publisher/venv/bin/python
policy=/etc/factory-publisher/policy.json
staging=/var/lib/factory-transfer
unit=factory-publisher.service
work_root=/run/factory-publisher-acceptance
override=/run/systemd/system/factory-publisher.service.d/50-acceptance.conf

# Root-held lock; no concurrent switch changes/acceptance sessions.
exec 9>/run/factory-publisher-acceptance.lock
flock -n 9 || { echo 'acceptance_already_running' >&2; exit 1; }
stamp=$(date -u +%Y%m%dT%H%M%S.%NZ)
work=$work_root/$stamp
[[ ! -L $work_root && ( ! -e $work_root || -d $work_root ) && ! -e $work && ! -L $work && ! -e $override && ! -L $override ]] || {
  echo 'acceptance_paths_in_use' >&2; exit 1;
}
[[ $(systemctl is-active "$unit" || true) == inactive ]] || {
  echo 'publisher_must_be_inactive' >&2; exit 1;
}

[[ $service_runtime != /REPLACE_WITH_INSTALLED_SERVICE_RUNTIME && -x $exporter_python ]] || {
  echo 'installed_service_runtime_required' >&2; exit 1;
}

set_switches() {
  "$python" -I - "$policy" "$1" <<'PY'
import json, os, stat, sys, tempfile
from pathlib import Path
from factory.publisher_credentials import protected_read
try:
    path = Path(sys.argv[1])
    raw = json.loads(protected_read(path))
    meta = path.stat()
    assert meta.st_uid == 0 and not meta.st_mode & 0o022
    assert raw['version'] == 2
    assert raw['app']['repository'] == 'shamsway/octant-private'
    assert raw['app']['key_file'] == '/run/credentials/factory-publisher.service/app-key'
    assert sys.argv[2] in ('true', 'false')
    raw['enabled'] = raw['allow_publish'] = sys.argv[2] == 'true'
    fd, name = tempfile.mkstemp(prefix='.acceptance-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchown(stream.fileno(), meta.st_uid, meta.st_gid)
            os.fchmod(stream.fileno(), stat.S_IMODE(meta.st_mode))
            stream.write(json.dumps(raw, sort_keys=True, separators=(',', ':')).encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if os.path.exists(name): os.unlink(name)
except Exception:
    print('policy_switch_update_failed', file=sys.stderr)
    raise SystemExit(1)
PY
}

cleanup() {
  primary=$?
  trap - EXIT INT TERM HUP
  # Disable first, even if stop/reload fails. Never replace durable outbox state.
  if ! set_switches false; then
    echo 'CRITICAL: switch_disable_failed; stop and repair as root; never resend blindly' >&2
    [[ $primary != 0 ]] || primary=1
  fi
  if [[ -e $override ]]; then
    systemctl stop "$unit" >/dev/null 2>&1 || { echo 'publisher_stop_failed' >&2; primary=1; }
    rm -f -- "$override"
    systemctl daemon-reload >/dev/null 2>&1 || { echo 'unit_reload_failed' >&2; primary=1; }
  fi
  # Deliberately retain root-only preview/result metadata for operator review.
  exit "$primary"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
set_switches false
install -d -o root -g factory-publisher -m 0750 "$work_root"
mkdir -m 0750 "$work"
chown root:factory-publisher "$work"
printf 'acceptance_work=%s\n' "$work"

# Export as matt; neither import nor preview loads the App credential.
(
  cd "$matt_repo"
  runuser -u matt -- "$exporter_python" -P -m factory investigation-export --incident "$incident" --run "$run" --staging-dir "$staging"
) > "$work/export.json"
name=$("$python" -I - "$work/export.json" <<'PY'
import json, re, sys
try:
    row = json.load(open(sys.argv[1]))
    assert set(row) == {'state', 'file', 'sha256'} and row['state'] == 'exported'
    assert re.fullmatch(r'[0-9a-f]{64}\.json', row['file'])
    print(row['file'])
except Exception: raise SystemExit('export_result_invalid')
PY
)
runuser -u factory-publisher -- "$broker" investigation-broker --policy "$policy" --import-bundle "$staging/$name"
runuser -u factory-publisher -- "$broker" investigation-broker --policy "$policy" --incident "$incident" --run "$run" > "$work/preview.json"
"$python" -I - "$work/preview.json" "$repository" "$issue" <<'PY'
import json, sys
try:
    row = json.load(open(sys.argv[1]))
    assert set(row) <= {'repository', 'issue', 'body', 'public_write', 'status_write_failed'}
    assert row['repository'] == sys.argv[2] and type(row['issue']) is int and str(row['issue']) == sys.argv[3]
    assert row['public_write'] is False and isinstance(row['body'], str)
    assert not row.get('status_write_failed', False)
    print('Destination:', row['repository'], '#' + str(row['issue']))
    print(row['body'])
except Exception: raise SystemExit('preview_destination_or_status_invalid')
PY
# This local human review is the pre-approved condition, not a new chat round.
printf 'Confirm the shown body and independently verify failure still unresolved.\nType SEND unresolved %s to publish, anything else to abort: ' "$issue" > /dev/tty
IFS= read -r confirmation < /dev/tty
[[ $confirmation == "SEND unresolved $issue" ]] || { echo 'operator_aborted' >&2; exit 1; }
# Broker rechecks 300s expiry + exact saved preview before any first POST.
set_switches true
install -d -o root -g root -m 0755 "$(dirname "$override")"
# Identifiers are regex-validated; fixed root-owned executable/policy/unit only.
cat > "$override" <<EOF
[Service]
ExecStart=
ExecStart=$broker investigation-broker --policy $policy --incident $incident --run $run --send --confirm-public-write
StandardOutput=file:$work/result.json
StandardError=null
ReadWritePaths=$work
EOF
chmod 0600 "$override"
install -o factory-publisher -g factory-publisher -m 0600 /dev/null "$work/result.json"
systemctl daemon-reload
send_exit=0
systemctl start --wait "$unit" >/dev/null 2>&1 || send_exit=$?
# Report bounded fixed result fields even if the unit failed; do not expose tokens.
"$python" -I - "$work/result.json" <<'PY'
import json, sys
try:
    with open(sys.argv[1], 'rb') as handle: raw = handle.read(65537)
    assert len(raw) <= 65536
    row = json.loads(raw)
    state = row.get('state')
    assert state in (None, 'delivered', 'uncertain', 'queued', 'blocked', 'failed')
    print(json.dumps({'state': state, 'ok': row.get('ok'), 'status_write_failed': row.get('status_write_failed', False)}))
except Exception: raise SystemExit('publisher_result_unavailable; inspect outbox; never resend blindly')
PY
exit "$send_exit"
