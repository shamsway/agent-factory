"""Factory's own git commands read the checkout's Git state, not worker-planted state.

A ticket worktree's `.git` is a pointer file inside the worker-writable worktree,
and its administrative directory names the common directory in a `commondir`
file. A worker that rewrites either can point the dispatcher's next `git` call
(commit, status, diff, push) at a planted repository whose config runs commands
(`core.fsmonitor`, `diff.external`, ...) outside any sandbox. Replace refs and
an `info/grafts` file make Git read different content or parents for a commit
than the commit's hash names, so a pinned base revision alone is not enough.

`env` pins `GIT_DIR`/`GIT_COMMON_DIR`/`GIT_WORK_TREE` for a linked worktree under
the checkout's `.factory/`, found from the checkout's side (the admin directory
whose `gitdir` names that worktree), and always disables replace objects and
grafts. A worktree with no matching admin directory gets a `GIT_DIR` that does
not exist, so git fails closed instead of discovering whatever the worktree
names. `strip` removes these again for commands that are not Factory's own
(configured gate checks), so a repository's tests see an ordinary checkout.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

# A grafts path that cannot exist (a file under /dev/null): an existing one, even
# /dev/null, makes git print a deprecation hint into every command's output.
HARDENED = {"GIT_NO_REPLACE_OBJECTS": "1", "GIT_GRAFT_FILE": os.path.join(os.devnull, "no-grafts")}
PINNED = ("GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE")
UNRESOLVED = "factory-gitguard-unresolved-worktree"


def admin_dir(root: Path, worktree: Path) -> Path | None:
    """`<root>/.git/worktrees/<name>` whose `gitdir` names `worktree`, or None (also when ambiguous)."""
    want = os.path.realpath(worktree)
    found = []
    for gitdir in sorted((root / ".git" / "worktrees").glob("*/gitdir")):
        try:
            named = gitdir.read_text().strip()
        except OSError:
            continue
        if os.path.basename(named) == ".git" and os.path.realpath(os.path.dirname(named)) == want:
            found.append(gitdir.parent)
    return found[0] if len(found) == 1 else None


def pinned(root: Path, cwd: Path) -> dict[str, str] | None:
    """GIT_DIR/GIT_COMMON_DIR/GIT_WORK_TREE for a linked worktree under `<root>/.factory/`, else None."""
    real_root, real = Path(os.path.realpath(root)), Path(os.path.realpath(cwd))
    factory = real_root / ".factory"
    if real == factory or factory not in real.parents:
        return None
    for top in (real, *real.parents):
        if top.parent == factory:
            break
    admin = admin_dir(real_root, top)
    return {
        "GIT_DIR": str(admin) if admin else str(factory / UNRESOLVED),
        "GIT_COMMON_DIR": str(real_root / ".git"),
        "GIT_WORK_TREE": str(top),
    }


def env(root: Path | None, cwd: Path | str | None, base: Mapping[str, str] | None = None) -> dict[str, str]:
    """Environment for one of Factory's own git (or gh) commands run in `cwd`."""
    out = strip(os.environ if base is None else base)
    out.update(HARDENED)
    if root is not None and cwd is not None and (paths := pinned(Path(root), Path(cwd))):
        out.update(paths)
    return out


def strip(base: Mapping[str, str]) -> dict[str, str]:
    """`base` without the variables `env` sets."""
    return {k: v for k, v in base.items() if k not in HARDENED and k not in PINNED}
