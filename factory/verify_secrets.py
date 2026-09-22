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
import shlex
import subprocess
import sys

from . import config

ENV_LINE = re.compile(r"^Environment=([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.MULTILINE)


def parse_environment_lines(unit_text: str) -> dict[str, str]:
    """Pull `Environment=KEY=value` pairs out of `systemctl --user cat` output."""
    return dict(ENV_LINE.findall(unit_text))


def unit_env(unit: str) -> dict[str, str] | None:
    """Loaded unit environment (including drop-ins), never print property values."""
    r = subprocess.run(
        ["systemctl", "--user", "show", "--property=LoadState,Environment,EnvironmentFiles,UnsetEnvironment", "--", unit],
        capture_output=True, text=True, timeout=10,
    )
    if r.returncode:
        raise OSError("unit inspection unavailable")
    props = dict(line.split("=", 1) for line in r.stdout.splitlines() if "=" in line)
    if props.get("LoadState") == "not-found":
        return None
    if props.get("LoadState") != "loaded" or props.get("EnvironmentFiles") or props.get("UnsetEnvironment"):
        raise OSError("unit environment unavailable")
    try:
        pairs = [item.partition("=") for item in shlex.split(props.get("Environment", ""))]
        if any(not sep or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) for key, sep, _ in pairs):
            raise ValueError
        return {key: value for key, _, value in pairs}
    except ValueError:
        raise OSError("unit environment unavailable") from None


def units_for(cfg: config.Config) -> list[str]:
    # Triage is retired as a standalone unit: the unified `{cfg.unit}.service`'s
    # `-` prefixed ExecStart runs it, one pass ahead of dispatch (see onboard.units()).
    return [f"{cfg.unit}.service", f"{cfg.unit}-dashboard.service"]


def required_units(cfg: config.Config) -> set[str]:
    """Units whose absence is itself a failure, not a benign "not installed" row.

    The dispatcher unit is always required. The dashboard unit is required only
    when `[install].dashboard` is enabled -- a disabled dashboard is expected to
    be absent, same as `onboard.install()` treats it.
    """
    units = {f"{cfg.unit}.service"}
    if cfg.install.get("dashboard"):
        units.add(f"{cfg.unit}-dashboard.service")
    return units


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
        capture_output=True, text=True, timeout=10,
    )
    if r.returncode != 0:
        return "auth FAILED"
    m = re.search(r"^x-oauth-scopes:\s*(.*)$", r.stdout, re.IGNORECASE | re.MULTILINE)
    return f"OK, scopes: {m.group(1).strip()}" if m else "OK (no scopes header -- fine-grained or app token)"


def check_op_token(token: str) -> str:
    r = subprocess.run(
        ["op", "vault", "list", "--format=json"],
        env={"OP_SERVICE_ACCOUNT_TOKEN": token, "PATH": os.environ.get("PATH", "")},
        capture_output=True, text=True, timeout=10,
    )
    if r.returncode != 0:
        return "FAILED: authentication check rejected"
    try:
        return f"OK, {len(json.loads(r.stdout))} vault(s) visible"
    except json.JSONDecodeError:
        return "FAILED: invalid response"


# Keyed by exact env-var name; add more as new credential types earn a real incident.
LIVE_CHECKS = {
    "GH_TOKEN": check_gh_token,
    "OP_SERVICE_ACCOUNT_TOKEN": check_op_token,
}


def credential_rows(cfg: config.Config, scope: str, live: bool) -> list[dict]:
    """Only names/statuses escape this boundary; values and provider diagnostics never do."""
    scopes = {"install": cfg.install["env"], "apply": cfg.apply_env}
    rows = []
    for name, env in scopes.items():
        if scope not in ("all", name):
            continue
        for key, value in sorted(env.items()):
            status = "configured" if value else "empty"
            if live and key in LIVE_CHECKS and value:
                try:
                    result = LIVE_CHECKS[key](str(value))
                    status = "valid" if result.startswith("OK") else "invalid"
                except (OSError, subprocess.SubprocessError, ValueError):
                    status = "unavailable"
            elif live and key not in LIVE_CHECKS:
                status = "not_checked"
            rows.append({"scope": name, "key": key, "status": status})
    return rows


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="factory verify-secrets",
        description="Compare installed unit credentials and optionally validate scoped credentials; values are never printed.",
    )
    parser.add_argument("--live", action="store_true", help="validate configured GH/1Password credentials in isolated subprocesses")
    parser.add_argument("--scope", choices=("install", "apply", "all"), default="install")
    parser.add_argument("--json", action="store_true", help="emit names/statuses as JSON")
    args = parser.parse_args(argv)
    try:
        cfg = config.load()
    except (config.ConfigError, OSError, ValueError):
        print(json.dumps({"ok": False, "error": "configuration_unavailable"}))
        return 1
    try:
        rows = sync_rows(cfg) if args.scope != "apply" else []
        sync_error = None
    except (OSError, subprocess.SubprocessError):
        rows, sync_error = [], "unit_inspection_unavailable"
    required = required_units(cfg)
    bad = bool(sync_error) or any(
        status not in ("in sync", "not installed") or (status == "not installed" and unit in required)
        for unit, _, status in rows
    )
    credentials = credential_rows(cfg, args.scope, args.live)
    bad |= any(row["status"] in ("empty", "invalid", "unavailable") for row in credentials)
    # Compare configured roles only: the caller shell is not the dispatcher.
    # Actual unit/process boundaries are checked by `factory inspect`.
    # Shared variable names are legitimate when credentials differ.
    isolation = [{"key": key, "status": "leaked"}
                 for key, value in cfg.apply_env.items()
                 if value and cfg.install["env"].get(key) == value]
    if args.scope != "install":
        bad |= bool(isolation)
    report = {"ok": not bad, "repo": cfg.repo, "scope": args.scope,
              "units": [{"unit": u, "key": k, "status": v} for u, k, v in rows],
              "credentials": credentials, "apply_isolation": isolation, "error": sync_error}
    if args.json:
        print(json.dumps(report))
    else:
        print(f"factory verify-secrets: {cfg.repo} ({args.scope})")
        for row in report["units"]:
            print(f"  {row['unit']}: {row['key']}: {row['status']}")
        for row in credentials:
            print(f"  {row['scope']}: {row['key']}: {row['status']}")
        for row in isolation:
            print(f"  apply isolation: {row['key']}: {row['status']}")
        if sync_error:
            print(f"  {sync_error}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
