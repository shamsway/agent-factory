"""`factory verify-secrets`: confirm [install].env credentials are live and match what's
actually baked into this repo's installed systemd units.

`factory install` copies [install].env into every unit's Environment= lines *at install time*;
editing the host config alone does not touch a unit that is already running (see SHA-182: a
`factory install` rerun silently propagated an unscoped GH_TOKEN into the dispatcher unit for
the first time, breaking automated merge with no loud error). Comparing values by hand
(`cat`/grep on the host config, or `systemctl --user cat`) is fragile through nested shell
quoting and, worse, prints live secret values into whatever transcript is doing the comparing.
Use this instead.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

from . import config

ENV_LINE = re.compile(r"^Environment=([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.MULTILINE)


def parse_environment_lines(unit_text: str) -> dict[str, str]:
    """Pull `Environment=KEY=value` pairs out of `systemctl --user cat` output."""
    return dict(ENV_LINE.findall(unit_text))


def unit_env(unit: str) -> dict[str, str] | None:
    """Env baked into an installed systemd user unit; None if the unit isn't installed."""
    r = subprocess.run(["systemctl", "--user", "cat", unit], capture_output=True, text=True)
    return None if r.returncode != 0 else parse_environment_lines(r.stdout)


def units_for(cfg: config.Config) -> list[str]:
    return [f"{cfg.unit}.service", f"{cfg.unit}-triage.service", f"{cfg.unit}-dashboard.service"]


def sync_rows(cfg: config.Config, unit_env_fn=None) -> list[tuple[str, str, str]]:
    """(unit, key, status) for every [install].env key, one row per unit that's actually installed."""
    unit_env_fn = unit_env_fn or unit_env  # looked up at call time so tests can mock the module-level default
    rows: list[tuple[str, str, str]] = []
    for unit in units_for(cfg):
        installed = unit_env_fn(unit)
        if installed is None:
            rows.append((unit, "*", "not installed"))
            continue
        for key, want in cfg.install["env"].items():
            got = installed.get(key)
            if got is None:
                status = "missing from unit"
            elif got == want:
                status = "in sync"
            else:
                status = "STALE -- rerun `factory install`"
            rows.append((unit, key, status))
    return rows


def check_gh_token(token: str) -> str:
    r = subprocess.run(
        ["gh", "api", "-i", "user"],
        env={"GH_TOKEN": token, "PATH": os.environ.get("PATH", "")},
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        return "auth FAILED"
    m = re.search(r"^x-oauth-scopes:\s*(.*)$", r.stdout, re.IGNORECASE | re.MULTILINE)
    return f"OK, scopes: {m.group(1).strip()}" if m else "OK (no scopes header -- fine-grained or app token)"


def check_op_token(token: str) -> str:
    r = subprocess.run(
        ["op", "vault", "list", "--format=json"],
        env={"OP_SERVICE_ACCOUNT_TOKEN": token, "PATH": os.environ.get("PATH", "")},
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        last_line = r.stderr.strip().splitlines()[-1] if r.stderr.strip() else "unknown error"
        return f"FAILED: {last_line}"
    try:
        return f"OK, {len(json.loads(r.stdout))} vault(s) visible"
    except json.JSONDecodeError:
        return "OK (unexpected output shape)"


# Keyed by exact env-var name; add more as new credential types earn a real incident.
LIVE_CHECKS = {
    "GH_TOKEN": check_gh_token,
    "OP_SERVICE_ACCOUNT_TOKEN": check_op_token,
}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="factory verify-secrets",
        description="Check [install].env credentials match what's baked into this repo's "
        "systemd units, and optionally spot-check well-known credential types live.",
    )
    parser.add_argument(
        "--live", action="store_true",
        help="also validate known credential types (GH_TOKEN, OP_SERVICE_ACCOUNT_TOKEN) against the real service",
    )
    args = parser.parse_args(argv)

    cfg = config.load()
    print(f"factory verify-secrets: {cfg.repo}")

    rows = sync_rows(cfg)
    for unit, key, status in rows:
        print(f"  {unit}: {key}: {status}")

    if args.live:
        print()
        for key, checker in LIVE_CHECKS.items():
            if key in cfg.install["env"]:
                print(f"  live check {key}: {checker(cfg.install['env'][key])}")

    stale = any(status not in ("in sync", "not installed") for _, _, status in rows)
    return 1 if stale else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
