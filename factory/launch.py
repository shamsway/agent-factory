"""Trusted `factory` child processes started from directories a worker can write.

`python -m factory` puts the working directory first on `sys.path`, so from a
ticket worktree a worker-written `factory.py` or `factory/` package would run in
place of the installed engine, outside `check_wrap` and with the dispatcher's
environment. `factory_argv` starts the same interpreter isolated (`-I`: no
working-directory or script-directory path entry, no `PYTHON*` environment
overrides such as `PYTHONPATH`/`PYTHONSTARTUP`, no user site-packages) and puts
the directory this package was imported from first, so the child runs exactly
the engine the parent is running, installed runtime or source checkout.
"""

from __future__ import annotations

import sys
from pathlib import Path

PACKAGE_PARENT = Path(__file__).resolve().parent.parent
BOOT = ("import sys; sys.path.insert(0, sys.argv.pop(1)); "
        "from factory.cli import main; raise SystemExit(main(sys.argv[1:]))")


def factory_argv(*args: str) -> list[str]:
    """argv for `factory <args>` under this interpreter and this package only."""
    return [sys.executable, "-I", "-c", BOOT, str(PACKAGE_PARENT), *args]
