"""Apply's GitHub identity guard: one verified, pinned account for every apply GitHub call.

`factory apply` (scheduled or by hand) and `factory incidents --deliver/--retry` build
the environment the apply unit carries -- the caller's environment without gh's
credential selectors, then `[install].env`, then `[install].dispatch_env` -- so a
manual run selects the same account as the scheduled one. The guard reads that
account's token once (`gh auth token`), resolves `gh api user` with only that token,
and refuses unless the login is in host-owned `[apply].github_logins`.

While an identity is pinned, every `gh` run through `dispatch.run` and the incident
transport carries the same token, so `gh auth switch`, an edited gh config or a new
`GH_TOKEN` in the caller cannot change who authors apply's comments or incidents
between the check and the call. Only login names and statuses leave this module.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field

# Variables that choose gh's account. Ambient values are dropped: only host config selects it.
TOKEN_KEYS = ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN")
SELECTORS = (*TOKEN_KEYS, "GH_CONFIG_DIR")
LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
TOKEN = re.compile(r"[\x21-\x7e]{1,1024}")
TIMEOUT_SEC = 20
STATUSES = ("verified", "unconfigured", "mismatch", "malformed", "unavailable")


class IdentityRefused(RuntimeError):
    """Apply's GitHub calls are refused; the message carries login names only."""


@dataclass(frozen=True)
class Identity:
    status: str  # one of STATUSES
    login: str
    allowed: tuple[str, ...]
    reason: str
    token: str = field(default="", repr=False, compare=False)

    @property
    def verified(self) -> bool:
        return self.status == "verified" and bool(self.token)

    def metadata(self) -> dict:
        """What may be shown or logged: never the token or an environment."""
        return {"status": self.status, "login": self.login or None, "allowed": list(self.allowed),
                "reason": self.reason}


def allowed_logins(cfg) -> tuple[str, ...]:
    return tuple(getattr(cfg, "apply_github_logins", ()) or ())


def identity_env(cfg, base: Mapping[str, str] | None = None) -> dict[str, str]:
    """The apply unit's GitHub environment: `base` (the process) without gh's account
    selectors, then `[install].env`, then `[install].dispatch_env`."""
    env = {k: v for k, v in (os.environ if base is None else base).items() if k not in SELECTORS}
    install = getattr(cfg, "install", None) or {}
    return {**env, **install.get("env", {}), **install.get("dispatch_env", {})}


def with_token(base: Mapping[str, str], token: str) -> dict[str, str]:
    """`base` whose only gh credential is `token`."""
    return {k: v for k, v in base.items() if k not in TOKEN_KEYS} | {"GH_TOKEN": token}


def _gh(argv: list[str], env: dict[str, str], runner: Callable) -> str | None:
    try:
        proc = runner(["gh", *argv], env=env, capture_output=True, text=True, timeout=TIMEOUT_SEC,
                      stdin=subprocess.DEVNULL, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    # Provider output stays here: it can quote the token or the environment.
    return proc.stdout if proc.returncode == 0 and isinstance(proc.stdout, str) else None


def resolve(cfg, *, base: Mapping[str, str] | None = None, runner: Callable | None = None) -> Identity:
    """Resolve the account apply would act as, pinning the token the login came from."""
    runner = runner or subprocess.run
    allowed = allowed_logins(cfg)
    env = identity_env(cfg, base)
    out = _gh(["auth", "token"], env, runner)
    if out is None:
        return Identity("unavailable", "", allowed, "gh has no usable token for the dispatcher identity")
    token = out.strip()
    if not TOKEN.fullmatch(token):
        return Identity("malformed", "", allowed, "gh returned a malformed token")
    out = _gh(["api", "user"], with_token(env, token), runner)
    if out is None:
        return Identity("unavailable", "", allowed, "gh api user failed for the dispatcher identity")
    try:
        user = json.loads(out)
    except ValueError:
        user = None
    login = user.get("login") if isinstance(user, dict) else None
    if not isinstance(login, str) or not LOGIN.fullmatch(login):
        return Identity("malformed", "", allowed, "gh api user returned no valid login")
    if not allowed:
        return Identity("unconfigured", login, allowed,
                        f"[apply].github_logins is unset (gh authenticates as {login})")
    if login.casefold() not in {name.casefold() for name in allowed}:
        return Identity("mismatch", login, allowed,
                        f"gh authenticates as {login}, not an approved login ({', '.join(allowed)})")
    return Identity("verified", login, allowed, f"authenticated as {login}", token)


def require(cfg, **kwargs) -> Identity:
    identity = resolve(cfg, **kwargs)
    if not identity.verified:
        raise IdentityRefused(f"apply GitHub identity {identity.status}: {identity.reason}")
    return identity


_pinned: Identity | None = None


def current() -> Identity | None:
    return _pinned


@contextmanager
def pinned(identity: Identity) -> Iterator[Identity]:
    """Every gh call made through `gh_env` inside this block uses `identity`'s token."""
    global _pinned
    if not identity.verified:
        raise IdentityRefused(f"apply GitHub identity {identity.status}: {identity.reason}")
    prior, _pinned = _pinned, identity
    try:
        yield identity
    finally:
        _pinned = prior


def require_pinned(what: str) -> Identity:
    if _pinned is None:
        raise IdentityRefused(f"{what} needs a verified apply GitHub identity")
    return _pinned


def gh_env(env: Mapping[str, str] | None) -> dict[str, str] | None:
    """The environment for one gh subprocess: unchanged (None inherits) unless an identity
    is pinned, then the same variables with only the pinned token."""
    if _pinned is None:
        return None if env is None else dict(env)
    return with_token(os.environ if env is None else env, _pinned.token)
