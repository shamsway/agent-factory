#!/usr/bin/env bash
# Run the test suite the way CI does (.github/workflows/ci.yml), in a Linux
# container, against the working tree (tracked + untracked, honouring
# .gitignore). The suite targets Linux; macOS runs are not evidence.
#
#   scripts/test-linux.sh                 # whole suite
#   scripts/test-linux.sh tests.test_apply  # unittest module/test names
#
# Needs podman (or set CONTAINER=docker). PYTHON_IMAGE / PLATFORM override
# the image and platform.
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
git ls-files -z --cached --others --exclude-standard \
  | tar --null -T - -cf - \
  | "$engine" run --rm -i --init --platform "$platform" "$image" bash -c "
      set -e
      apt-get update -qq >/dev/null && apt-get install -y -qq git gh >/dev/null
      # Fixtures use #!/usr/bin/python shebangs, as on the CI runner.
      ln -sf /usr/local/bin/python3 /usr/bin/python
      ln -sf /usr/local/bin/python3 /usr/bin/python3
      git config --global user.email ci@example.invalid
      git config --global user.name ci
      mkdir /src && cd /src && tar -xf -
      pip install -q --root-user-action=ignore '.[atlas]'
      $run"
