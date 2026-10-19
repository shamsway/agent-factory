#!/usr/bin/env bash
# Run the test suite the way CI does (.github/workflows/ci.yml), in a Linux
# container, against the working tree (tracked + untracked, honouring
# .gitignore). The suite targets Linux; macOS runs are not evidence.
#
#   scripts/test-linux.sh                 # whole suite
#   scripts/test-linux.sh tests.test_apply  # unittest module/test names
#
# Needs podman (or set CONTAINER=docker with ISOLATION=0). PYTHON_IMAGE /
# PLATFORM override the image and platform.
#
# Like CI's "Prepare required Linux isolation boundary" step, the throwaway
# container is privileged and boots systemd (podman --systemd=always) so root
# has a user manager and session bus: the real bubblewrap and systemd-scope
# tests (tests/test_sandbox.py, tests/test_investigation_isolation.py, the
# b1-build SandboxTest) run, and FACTORY_REQUIRE_ISOLATION=1 makes a missing
# boundary fail instead of skip. The host must allow unprivileged user
# namespaces (CI relaxes kernel.apparmor_restrict_unprivileged_userns).
# ISOLATION=0 runs an unprivileged container without systemd; those tests skip.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
engine="${CONTAINER:-podman}"
image="${PYTHON_IMAGE:-docker.io/library/python:3.12-slim}"
# Native arch: an emulated amd64 image under qemu is ~10x slower.
platform="${PLATFORM:-linux/$(uname -m | sed s/x86_64/amd64/)}"
if [ "$#" -gt 0 ]; then
  run="python -m unittest $*"
else
  run="python -m unittest discover -s tests"
fi
packages="git gh bubblewrap python3" options=() init="sleep infinity" isolation_env=()
if [ "${ISOLATION:-1}" != 0 ]; then
  if [ "$engine" != podman ]; then
    echo "test-linux: the isolation run boots systemd via podman; use ISOLATION=0 with $engine" >&2
    exit 2
  fi
  packages+=" systemd systemd-sysv dbus-user-session"
  options=(--privileged --systemd=always) init=/sbin/init
  isolation_env=(-e FACTORY_REQUIRE_ISOLATION=1 -e XDG_RUNTIME_DIR=/run/user/0
                 -e DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/0/bus)
fi
cid=$("$engine" run -d "${options[@]}" --platform "$platform" "$image" bash -c "
  apt-get update -qq >/dev/null && apt-get install -y -qq $packages >/dev/null && touch /ready && exec $init")
trap '"$engine" rm -f -t 0 "$cid" >/dev/null' EXIT
wait_for() {  # retry a command in the container until it succeeds
  until "$engine" exec "$cid" "$@" >/dev/null 2>&1; do
    if [ "$("$engine" inspect -f '{{.State.Running}}' "$cid")" != true ]; then
      "$engine" logs "$cid" >&2; echo "test-linux: container setup failed" >&2; exit 1
    fi
    sleep 2
  done
}
wait_for test -e /ready
if [ "${ISOLATION:-1}" != 0 ]; then
  # The user manager and session bus CI gets from enable-linger, here for root.
  wait_for loginctl enable-linger root
  "$engine" exec "$cid" systemctl start user@0.service
fi
# COPYFILE_DISABLE: macOS tar would otherwise add AppleDouble ._* files.
git ls-files -z --cached --others --exclude-standard \
  | COPYFILE_DISABLE=1 tar --null -T - -cf - \
  | "$engine" exec -i "${isolation_env[@]}" "$cid" bash -c "
      set -e
      # Fixtures use #!/usr/bin/python shebangs, as on the CI runner. The
      # isolation boundaries run the distro /usr/bin/python3, which they can
      # mount from /usr; /usr/local is outside the sandbox.
      ln -sf /usr/local/bin/python3 /usr/bin/python
      git config --global user.email ci@example.invalid
      git config --global user.name ci
      mkdir /src && cd /src && tar -xf -
      pip install -q --root-user-action=ignore --require-hashes --only-binary=:all: -r requirements/publisher-wheels.txt
      pip install -q --root-user-action=ignore '.[atlas,publisher]'
      $run"
