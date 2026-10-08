#!/usr/bin/env bash
# PREPARE ONLY. Operator runs only after specific A2 approval.
set -euo pipefail
umask 0077
[[ $(id -u) == 0 && $(hostname -s) == barlow && $# == 0 ]] || { echo 'root_barlow_no_args_required' >&2; exit 1; }
python=/opt/factory-publisher/venv/bin/python
helper=/usr/local/libexec/factory-publisher/a2-fields.py
unit=factory-publisher.service
check=factory-publisher-check.service
lock=/run/factory-publisher-acceptance.lock
root=/run/factory-publisher-a2
override=/run/systemd/system/factory-publisher.service.d/50-a2.conf
[[ ! -L $lock && ! -L $root && ! -e $override && ! -L $override ]] || { echo 'a2_paths_in_use' >&2; exit 1; }
# Reject ALL pre-existing runtime overrides, not just our filename.
[[ ! -d /run/systemd/system/factory-publisher.service.d || -z $(find /run/systemd/system/factory-publisher.service.d -mindepth 1 -maxdepth 1 -print -quit) ]] || { echo 'runtime_override_in_use' >&2; exit 1; }
exec 9>"$lock"
flock -n 9 || { echo 'acceptance_already_running' >&2; exit 1; }
[[ $(stat -c '%u:%a' "$lock") == 0:600 ]] || { echo 'lock_permissions_invalid' >&2; exit 1; }
for item in "$unit" "$check"; do
  [[ $(systemctl is-active "$item" || true) == inactive ]] || { echo 'publisher_units_must_be_inactive' >&2; exit 1; }
done
[[ ! -e $root || $(stat -c '%u:%a' "$root") == 0:700 ]] || { echo 'work_parent_invalid' >&2; exit 1; }
install -d -o root -g root -m 0700 "$root"
work=$root/$(date -u +%Y%m%dT%H%M%S.%NZ)
mkdir -m 0700 "$work"
"$python" -I "$helper" before "$work"
owned_override=false
cleanup() {
  primary=$?
  trap - EXIT INT TERM HUP
  systemctl stop "$unit" >/dev/null 2>&1 || { echo 'a2_stop_failed' >&2; primary=1; }
  systemctl reset-failed "$unit" >/dev/null 2>&1 || { echo 'a2_reset_failed' >&2; primary=1; }
  if [[ $owned_override == true ]]; then rm -f -- "$override"; fi
  systemctl daemon-reload >/dev/null 2>&1 || { echo 'a2_reload_failed' >&2; primary=1; }
  for item in "$unit" "$check"; do
    [[ $(systemctl is-active "$item" || true) == inactive ]] || { echo 'a2_unit_not_inactive' >&2; primary=1; }
  done
  [[ ! -e $override ]] || { echo 'a2_override_retained' >&2; primary=1; }
  # Check false switches even after a failed start; never change policy here.
  "$python" -I -c 'import runpy; m=runpy.run_path("/usr/local/libexec/factory-publisher/a2-fields.py"); m["policy"]()' >/dev/null 2>&1 || { echo 'a2_switch_check_failed' >&2; primary=1; }
  printf '{"cleanup_state":"%s","units_inactive":%s,"override_removed":%s}\n' "$([[ $primary == 0 ]] && echo complete || echo attention)" "$([[ $(systemctl is-active "$unit" || true) == inactive ]] && echo true || echo false)" "$([[ ! -e $override ]] && echo true || echo false)" > "$work/cleanup.json"
  exit "$primary"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
install -d -o root -g root -m 0755 "$(dirname "$override")"
# Exclusive creation; cleanup owns this override from the instant it is created.
owned_override=true
(set -o noclobber; : > "$override")
cat > "$override" <<EOF
[Service]
ExecStart=
ExecStart=$python -I -m factory investigation-broker --policy /etc/factory-publisher/policy.json --verify-token
StandardOutput=file:$work/result.json
StandardError=null
TimeoutStartSec=60
TimeoutStopSec=10
KillMode=control-group
EOF
chmod 0600 "$override"
systemctl daemon-reload >/dev/null 2>&1
start_exit=0
systemctl start --wait "$unit" >/dev/null 2>&1 || start_exit=$?
if [[ $start_exit != 0 ]]; then echo '{"state":"failed","code":"a2_service_failed_no_automatic_retry"}'; exit "$start_exit"; fi
"$python" -I "$helper" after "$work" > "$work/summary.json"
# Non-live inspection only. Raw metadata receipt remains root0700/0600.
(cd /home/matt/git/octant-private && runuser -u matt -- env HOME=/home/matt XDG_RUNTIME_DIR=/run/user/$(id -u matt) DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u matt)/bus /REPLACE_WITH_INSTALLED_SERVICE_RUNTIME/bin/python -P -m factory inspect --json) > "$work/inspect.json"
"$python" -I - "$work/inspect.json" <<'PY'
import json,sys
try:
    r=json.load(open(sys.argv[1]))['publisher_status']
    assert r['status']=='observed' and r['token']['outcome']=='ready'
except Exception: raise SystemExit('a2_status_not_observed')
PY
"$python" -I -c 'import json,sys; r=json.load(open(sys.argv[1])); print(json.dumps({k:r[k] for k in ("state","login","token_outcome","token_expiry","request_count")}))' "$work/summary.json"
