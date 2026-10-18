#!/usr/bin/env bash
# Confine a Factory worker or gate check with bubblewrap. For [worker_wrap] and
# [check_wrap] (README "worker_wrap"); the host chooses what to expose:
#
#   bwrap-sandbox.sh --cwd {cwd} --root {root} [--rw PATH]... [--ro PATH]...
#                    [--bind-at SRC DEST]... [--hide PATH]... [--drop-env NAME]... -- CMD...
#
# The filesystem is read-only, $HOME is an empty tmpfs (an allowlist: nothing
# under it is visible unless exposed), /tmp and $XDG_RUNTIME_DIR are private
# and empty (no session bus, agent or credential-daemon sockets), and the
# container and VM sockets are hidden. The worktree and the main checkout's .git
# are writable; .git/config and .git/hooks are not, because Factory's own git
# commands run outside the sandbox and would otherwise run hooks or
# config-defined commands the worker planted. bwrap sets no_new_privs, so
# setuid helpers such as sudo cannot raise privilege. The network is shared:
# this is a credential and host boundary, not a network one.
set -euo pipefail

die() { echo "bwrap-sandbox: $*" >&2; exit 125; }
command -v bwrap >/dev/null || die "bwrap not found"

cwd= root=
rw=() ro=() bind_at=() hide=() drop=()
while (($#)); do
  case $1 in
    --cwd) cwd=$2; shift 2 ;;
    --root) root=$2; shift 2 ;;
    --rw) rw+=("$2"); shift 2 ;;
    --ro) ro+=("$2"); shift 2 ;;
    --bind-at) bind_at+=("$2" "$3"); shift 3 ;;
    --hide) hide+=("$2"); shift 2 ;;
    --drop-env) drop+=("$2"); shift 2 ;;
    --) shift; break ;;
    *) die "unknown option $1" ;;
  esac
done
(($#)) || die "no command after --"
[[ -d $cwd && -d $root/.git ]] || die "--cwd must be a directory and --root a checkout with .git"
cwd=$(realpath "$cwd") root=$(realpath "$root") home=$(realpath "$HOME")

args=(--ro-bind / / --dev /dev --proc /proc --tmpfs /tmp
      --unshare-pid --unshare-ipc --unshare-uts --die-with-parent
      --tmpfs "$home")
run_dir=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
[[ -d $run_dir ]] && args+=(--tmpfs "$run_dir")

# Tools: PATH entries under $HOME, read-only. Their symlinks into other hidden
# directories must be exposed with --ro.
IFS=: read -r -a path_dirs <<<"${PATH:-}"
for dir in "${path_dirs[@]}"; do
  [[ $dir == "$home"/* && -d $dir ]] && args+=(--ro-bind "$dir" "$dir")
done
for f in "$home/.gitconfig" "$home/.config/git"; do args+=(--ro-bind-try "$f" "$f"); done
for p in "${ro[@]}"; do args+=(--ro-bind "$p" "$p"); done

# The checkout: readable, its .factory state hidden, the worktree and the git
# store writable, git's executable configuration not.
args+=(--ro-bind "$root" "$root" --tmpfs "$root/.factory" --bind "$cwd" "$cwd"
       --bind "$root/.git" "$root/.git")
for p in config hooks; do args+=(--ro-bind-try "$root/.git/$p" "$root/.git/$p"); done
for p in "${rw[@]}"; do args+=(--bind "$p" "$p"); done
for ((i = 0; i < ${#bind_at[@]}; i += 2)); do args+=(--bind "${bind_at[i]}" "${bind_at[i+1]}"); done

for sock in /run/docker.sock /run/containerd/containerd.sock /run/podman/podman.sock \
            /run/libvirt/libvirt-sock /run/libvirt/libvirt-sock-ro "${hide[@]}"; do
  if [[ -S $sock || -f $sock ]]; then args+=(--ro-bind /dev/null "$sock")
  elif [[ -d $sock ]]; then args+=(--tmpfs "$sock")
  fi
done

for name in SSH_AUTH_SOCK DBUS_SESSION_BUS_ADDRESS GH_TOKEN GITHUB_TOKEN "${drop[@]}"; do
  args+=(--unsetenv "$name")
done

exec bwrap "${args[@]}" --chdir "$cwd" -- "$@"
