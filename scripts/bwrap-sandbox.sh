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
# container and VM sockets are hidden. The worktree is writable, and so is, for a
# linked worktree of the checkout, the object store and that worktree's own
# administrative directory (.git/worktrees/<name>, found from the checkout's side),
# plus a ticket worktree's .factory/transcripts/<n>. The rest of .git stays
# read-only: config, hooks, refs (the shared baseline and every other ticket's
# branch), packed-refs, replace refs, info/grafts, shallow and the other
# worktrees' metadata. Factory's own git commands run outside the sandbox, and
# detach the worktree's HEAD for the worker, so its commits only move that
# worktree's own HEAD. bwrap sets no_new_privs, so
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

# The checkout: readable, its .factory state hidden, the worktree writable.
args+=(--ro-bind "$root" "$root" --tmpfs "$root/.factory" --bind "$cwd" "$cwd")
# A run from the checkout itself (cwd = root) must not re-expose .factory or a
# writable .git through the cwd bind.
[[ $cwd == "$root" ]] && args+=(--tmpfs "$root/.factory" --ro-bind "$root/.git" "$root/.git")
# A linked worktree's own admin dir: the one whose gitdir names $cwd/.git, read from
# the checkout's side (the worktree's own .git pointer file is worker-written).
admin=
for gitdir in "$root"/.git/worktrees/*/gitdir; do
  [[ -f $gitdir ]] || continue
  named=$(<"$gitdir")
  [[ ${named##*/} == .git && $(realpath -m "${named%/*}") == "$cwd" ]] || continue
  [[ -z $admin ]] || die "two worktree admin dirs name $cwd"
  admin=${gitdir%/gitdir}
done
if [[ -n $admin && -d $root/.git/objects && ! -L $root/.git/objects && ! -L $admin ]]; then
  args+=(--bind "$root/.git/objects" "$root/.git/objects" --bind "$admin" "$admin")
fi
# A ticket worktree's OMP session dir (dispatch keeps transcripts per ticket under the
# hidden .factory): only this ticket's, so a worker never reads another ticket's sessions.
ticket=${cwd#"$root/.factory/wt-"}
if [[ $ticket != "$cwd" && $ticket =~ ^[0-9]+$ && -d $root/.factory/transcripts/$ticket ]]; then
  args+=(--bind "$root/.factory/transcripts/$ticket" "$root/.factory/transcripts/$ticket")
fi
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
