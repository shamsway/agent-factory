"""Read-only migration observations. No unit changes, lock-file creation, Git fetch,
ledger writes, or raw credential/command-output rendering. Unknown is not healthy.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys

from . import config, deploy, verify_secrets

LIMIT = 8 * 1024 * 1024
PROPERTIES = "LoadState,ActiveState,SubState,UnitFileState,MainPID,ExecMainStartTimestampMonotonic,Environment,EnvironmentFiles,PassEnvironment,UnsetEnvironment,ExecStart,WorkingDirectory,InvocationID"


class Unavailable(Exception):
    """Fixed diagnostic code only; never include raw provider output."""


def read(path: Path, limit: int = LIMIT) -> bytes:
    try:
        with path.open("rb") as handle:
            data = handle.read(limit + 1)
        if len(data) > limit:
            raise Unavailable("size_limit")
        return data
    except OSError:
        raise Unavailable("unreadable") from None


def command(argv: list[str], *, cwd: Path | None = None, env: dict | None = None) -> str:
    try:
        result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        raise Unavailable("command_unavailable") from None
    if result.returncode or len(result.stdout) > LIMIT:
        raise Unavailable("command_failed")
    try:
        return result.stdout.decode("utf-8")
    except UnicodeError:
        raise Unavailable("invalid_output") from None


def assignments(text: str) -> dict[str, str]:
    """Parse systemd's quoted Environment property without returning it to users."""
    result = {}
    try:
        for item in shlex.split(text):
            key, sep, value = item.partition("=")
            if not sep or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
                raise ValueError
            result[key] = value
    except ValueError:
        raise Unavailable("environment_unparseable") from None
    return result


def boundary(cfg: config.Config, env: dict) -> list[dict]:
    rows = []
    for key, value in sorted(cfg.install["env"].items()):
        rows.append({"scope": "install", "key": key,
                     "status": "match" if env.get(key) == str(value) else "missing_or_stale"})
    for key, value in sorted(cfg.apply_env.items()):
        # A scoped GH_TOKEN may exist in both roles, but must not be the apply value.
        # An empty selector (for example TF_VAR_onepassword_account) is not
        # a credential. A nonempty unexpected value still violates isolation.
        leak = bool(env.get(key)) and (key not in cfg.install["env"] or env[key] == str(value))
        rows.append({"scope": "apply", "key": key, "status": "leaked" if leak else "isolated"})
    return rows


PROBE = r'''
import hashlib, importlib, importlib.metadata, json, pathlib, sys
rows = {}
try:
    importlib.import_module("factory")
    package = "factory"
except ModuleNotFoundError:
    package = "agent_factory"
for name in ('factory', 'factory.cli', 'factory.apply', 'factory.deploy', 'factory.tf_plan_check', 'factory.verify_secrets'):
    module = importlib.import_module(package + name[len("factory"):])
    path = pathlib.Path(module.__file__)
    rows[name] = {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
versions = {}
for name in ('factory', 'agent-factory'):
    try: versions[name] = importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError: pass
print(json.dumps({'package': package, 'python': sys.executable, 'prefix': sys.prefix, 'version': sys.version.split()[0], 'modules': rows, 'distributions': versions}))
'''


def runtime_probe(python: str, cwd: Path, env: dict) -> dict:
    try:
        result = json.loads(command([python, "-P", "-c", PROBE], cwd=cwd, env=env))
        # Output from a failing import or startup hook is never forwarded.
        modules = result["modules"]
        if set(modules) != {"factory", "factory.cli", "factory.apply", "factory.deploy",
                            "factory.tf_plan_check", "factory.verify_secrets"}:
            raise ValueError
        return {"status": "observed", "python": str(result["python"]),
                "prefix": str(result["prefix"]), "version": str(result["version"]),
                "package": str(result["package"]),
                "modules": {name: {"path": str(row["path"]), "sha256": str(row["sha256"])}
                            for name, row in modules.items()},
                "distributions": {name: str(version) for name, version in result["distributions"].items()
                                  if name in ("factory", "agent-factory")}}
    except (Unavailable, ValueError, KeyError, TypeError, AttributeError):
        return {"status": "unavailable"}


def process_snapshot(pid: int, cfg: config.Config, expected_python: str) -> dict:
    """Compare /proc startup identity and environment without emitting argv/env.

    Python's loaded module bytes cannot be recovered reliably from /proc; a fresh
    interpreter probe is separate evidence, never represented as live module proof.
    """
    base = Path("/proc") / str(pid)
    try:
        before = read(base / "stat", 65536)
        argv = read(base / "cmdline", 65536).decode().split("\0")
        env = dict(item.split("=", 1) for item in read(base / "environ").decode().split("\0") if "=" in item)
        executable = os.readlink(base / "exe")
        after = read(base / "stat", 65536)
        # Field 22 (starttime) follows the potentially spaced/parenthesized comm.
        if before.rsplit(b")", 1)[1].split()[19] != after.rsplit(b")", 1)[1].split()[19]:
            raise Unavailable("process_changed")
        expected = Path(expected_python)
        matches = Path(executable).resolve() == expected.resolve()
        invoked = bool(argv and argv[0] == expected_python)
        return {"status": "observed", "pid": pid, "executable": executable,
                "executable_matches": matches, "invocation_matches": invoked,
                "environment": boundary(cfg, env),
                "backend_lock_directory": str(deploy.preferred_lock_dir(env)),
                "loaded_module_identity": "not_observable; correlate invocation with immutable artifact"}
    except (Unavailable, OSError, ValueError, UnicodeError, IndexError):
        return {"status": "unavailable", "pid": pid}


def unit_snapshot(cfg: config.Config, unit: str, manager_env: dict | None, worker_cwd: Path | None = None) -> dict:
    try:
        text = command(["systemctl", "--user", "show", f"--property={PROPERTIES}", "--", unit])
        props = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
        if props.get("LoadState") != "loaded":
            return {"unit": unit, "status": "not_loaded"}
        output = {"unit": unit, "status": "observed", "load_state": props["LoadState"],
                  "active_state": props.get("ActiveState", "unknown"),
                  "enabled_state": props.get("UnitFileState", "unknown"),
                  "invocation_id": props.get("InvocationID", ""),
                  "start_monotonic": props.get("ExecMainStartTimestampMonotonic", "")}
        if unit.endswith(".timer"):
            return output
        unit_env = assignments(props.get("Environment", ""))
        output["configured_environment"] = boundary(cfg, unit_env)
        # ExecStart is systemd's structured property, not a shell command to run.
        paths = re.findall(r"(?:^|\{ )path=([^;]+?)\s*;", props.get("ExecStart", ""))
        output["configured_executables"] = paths
        inferred = paths[0] if paths and "python" in Path(paths[0]).name else sys.executable
        wanted = str(Path(cfg.install.get("python") or inferred).expanduser())
        if not Path(wanted).is_absolute():
            wanted = str(cfg.root / wanted)
        output["selected_python"] = wanted
        output["configured_interpreter_matches"] = bool(paths) and all(path == wanted for path in paths)
        # EnvironmentFiles and UnsetEnvironment require systemd semantics; do not
        # invent effective values or probe under a guessed environment.
        if manager_env is None or any(props.get(k) for k in ("EnvironmentFiles", "UnsetEnvironment")):
            output["runtime"] = {"status": "unavailable", "reason": "effective_environment_unknown"}
        else:
            effective = {**manager_env, **unit_env}
            output["effective_environment"] = boundary(cfg, effective)
            output["backend_lock_directory"] = str(deploy.preferred_lock_dir(effective))
            output["runtime"] = runtime_probe(wanted, Path(props.get("WorkingDirectory") or cfg.root), effective)
            import shutil
            gate_python = shutil.which("python3", path=effective.get("PATH", ""))
            output["gate_python"] = gate_python
            output["gate_runtime"] = runtime_probe(gate_python, worker_cwd or cfg.root, effective) if gate_python else {"status": "unavailable"}
            output["gate_cwd"] = str(worker_cwd or cfg.root)
            service, gate = output["runtime"], output["gate_runtime"]
            output["gate_matches_service"] = (service.get("status") == gate.get("status") == "observed"
                                              and service.get("prefix") == gate.get("prefix")
                                              and service.get("modules") == gate.get("modules"))
        pid = int(props.get("MainPID", "0"))
        output["process"] = process_snapshot(pid, cfg, wanted) if pid > 0 else {"status": "not_running"}
        if pid > 0:
            again = command(["systemctl", "--user", "show", "--property=MainPID,InvocationID", "--", unit])
            identity = dict(line.split("=", 1) for line in again.splitlines() if "=" in line)
            if identity.get("MainPID") != str(pid) or identity.get("InvocationID") != props.get("InvocationID"):
                output["process"] = {"status": "changed", "pid": pid}
        return output
    except (Unavailable, ValueError):
        return {"unit": unit, "status": "unavailable"}


def lock_snapshot(path: Path) -> dict:
    """Probe existing inode only, never create/unlink/truncate a lock file."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    except FileNotFoundError:
        return {"path": str(path), "status": "absent"}
    except OSError:
        return {"path": str(path), "status": "unavailable"}
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return {"path": str(path), "status": "unavailable"}
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            status = "held"
        else:
            fcntl.flock(fd, fcntl.LOCK_UN)
            status = "free"
        if os.fstat(fd).st_ino != path.stat().st_ino:
            status = "changed"
        return {"path": str(path), "status": status}
    except OSError:
        return {"path": str(path), "status": "unavailable"}
    finally:
        os.close(fd)


def locks(cfg: config.Config, extra_directories: list[Path] = ()) -> list[dict]:
    # Inspect fallback as well as preferred: an earlier permission failure may
    # have put an active backend lock there. Do not call the creating resolver.
    primary = deploy.preferred_lock_dir()
    directories = {cfg.factory / "locks", primary, Path("/tmp/agent-factory-locks"), *extra_directories}
    paths = {cfg.lock, cfg.factory / "locks" / "apply.lock"}
    errors = []
    for directory in sorted(directories):
        try:
            if not directory.exists():
                continue
            for index, path in enumerate(directory.iterdir()):
                if index >= 1024:
                    raise Unavailable("entry_limit")
                if path.name.endswith(".lock"):
                    paths.add(path)
        except (OSError, Unavailable):
            errors.append({"path": str(directory), "status": "unavailable"})
    return [lock_snapshot(path) for path in sorted(paths)] + errors


def deployment_snapshot(cfg: config.Config) -> dict:
    path = cfg.factory / "events.jsonl"
    try:
        try:
            with path.open("rb") as handle:
                fcntl.flock(handle, fcntl.LOCK_SH | fcntl.LOCK_NB)
                data = handle.read(LIMIT + 1)
                if len(data) > LIMIT:
                    raise Unavailable("size_limit")
        except FileNotFoundError:
            if not path.exists():
                return {"status": "absent", "targets": []}
            raise
        if data and not data.endswith(b"\n"):
            raise Unavailable("incomplete_tail")
        rows = []
        for line in data.splitlines():
            if not line.strip():
                continue
            if b"\x00" in line:
                continue  # lifecycle.append explicitly quarantines interrupted tails
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError
            if row.get("event") == "deploy_run":
                deploy.DeployRun.from_dict(row)  # malformed deployment state is not a clean ledger
            rows.append(row)
        state = deploy.replay_rows(rows)
        targets = []
        for name in sorted(set(cfg.targets) | set(state)):
            target = state.get(name)
            targets.append({"target": name,
                            "runs": [{"run_id": run.run_id, "ticket": run.ticket,
                                      "commit": run.commit, "status": run.status.value}
                                     for run in target.runs] if target else [],
                            "unresolved_runs": [run.run_id for run in target.interrupted_runs] if target else [],
                            "terminal_tickets": sorted(target.terminal_tickets) if target else [],
                            "unacknowledged_failed_tickets": sorted(target.unacknowledged_failed_tickets) if target else []})
        return {"status": "observed", "sha256": hashlib.sha256(data).hexdigest(), "targets": targets}
    except (Unavailable, OSError, ValueError, KeyError, TypeError, AttributeError):
        return {"status": "unavailable", "targets": []}


def before_baseline(cfg: config.Config, number: int, commit: str) -> bool:
    baseline = cfg.apply_baseline
    if not baseline:
        return False
    if baseline.isdigit():
        return number <= int(baseline)
    if not re.fullmatch(r"[a-fA-F0-9]{7,40}", baseline):
        raise Unavailable("baseline_invalid")
    ancestors = command(["git", "--no-optional-locks", "rev-list", baseline], cwd=cfg.root).splitlines()
    return commit in ancestors


def candidate_snapshot(cfg: config.Config, ledger: dict) -> dict:
    """Bounded discovery preview, never deployment authorization or Git refresh."""
    try:
        env = {k: v for k, v in os.environ.items() if k not in cfg.apply_env}
        env.update({k: str(v) for k, v in cfg.install["env"].items()})
        prs = json.loads(command(["gh", "pr", "list", "--repo", cfg.repo, "--state", "merged",
                                 "--limit", "1000", "--json", "number,headRefName,mergeCommit"], env=env))
        if not isinstance(prs, list) or ledger["status"] not in ("observed", "absent"):
            raise ValueError
        output = []
        for name, target in cfg.targets.items():
            if not target.enabled:
                continue
            recorded = next((t for t in ledger["targets"] if t["target"] == name), {})
            terminal = set(recorded.get("terminal_tickets", []))
            for pr in prs:
                match = re.fullmatch(r"agent/(\d+)", pr["headRefName"])
                if not match or not pr.get("mergeCommit"):
                    continue
                ticket, commit = int(match[1]), pr["mergeCommit"]["oid"]
                if not re.fullmatch(r"[a-fA-F0-9]{40}", commit):
                    raise ValueError
                if ticket in terminal or before_baseline(cfg, pr["number"], commit):
                    continue
                files = command(["git", "--no-optional-locks", "diff-tree", "--root", "--no-commit-id", "--name-only", "-r", "-m", commit, "--", target.dir], cwd=cfg.root)
                if files.strip():
                    output.append({"target": name, "ticket": ticket, "pr": pr["number"], "commit": commit})
        return {"status": "observed", "coverage": "truncated" if len(prs) >= 1000 else "complete_query",
                "authorization": "not_evaluated", "git_fetched": False, "candidates": output}
    except (Unavailable, ValueError, TypeError, KeyError, config.ConfigError):
        return {"status": "unavailable", "candidates": []}


def inspect(cfg: config.Config, *, live: bool = False, candidates: bool = False, worker_cwd: Path | None = None) -> dict:
    try:
        manager_env = assignments(command(["systemctl", "--user", "show-environment"]))
    except Unavailable:
        manager_env = None
    units = [unit_snapshot(cfg, u, manager_env, worker_cwd) for u in verify_secrets.units_for(cfg) + [cfg.unit + ".timer"]]
    ledger = deployment_snapshot(cfg)
    lock_dirs = [Path(row["backend_lock_directory"]) for unit in units for row in (unit, unit.get("process", {}))
                 if row.get("backend_lock_directory")]
    result = {"schema_version": 1, "repo": cfg.repo, "config_path": str(config.host_config_path()),
              "observer_python": sys.executable, "required_units": sorted(verify_secrets.required_units(cfg)),
              "configured_targets": [{"target": name, "enabled": target.enabled,
                                      "directory": target.dir, "adapter": target.adapter}
                                     for name, target in sorted(cfg.targets.items())],
              "units": units, "credentials": verify_secrets.credential_rows(cfg, "all", live),
              "deployment": ledger, "locks": locks(cfg, lock_dirs),
              "candidates": candidate_snapshot(cfg, ledger) if candidates else {"status": "not_requested"},
              "limits": ["Point-in-time observations; keep scheduling paused for drain checks.",
                         "Live module bytes are not observable; correlate process invocation with immutable artifact.",
                         "Candidate preview uses local Git objects and does not authorize deployment."]}
    required = set(result["required_units"]) | {cfg.unit + ".timer"}
    result["complete"] = all(u["status"] == "observed" for u in units if u["unit"] in required)
    result["complete"] &= ledger["status"] != "unavailable" and all(l["status"] not in ("unavailable", "changed") for l in result["locks"])
    if candidates:
        result["complete"] &= result["candidates"]["status"] == "observed" and result["candidates"].get("coverage") != "truncated"
    result["ok"] = bool(result["complete"] and not any(c["status"] in ("empty", "invalid", "unavailable") for c in result["credentials"]))
    for unit in units:
        if (unit["unit"] not in required and unit["status"] != "observed") or unit["unit"].endswith(".timer"):
            continue
        result["ok"] &= unit.get("configured_interpreter_matches", False)
        result["ok"] &= unit.get("runtime", {}).get("status") == "observed"
        result["ok"] &= unit.get("gate_matches_service", False)
        for group in (unit.get("configured_environment", []), unit.get("effective_environment", []), unit.get("process", {}).get("environment", [])):
            result["ok"] &= not any(row["status"] in ("missing_or_stale", "leaked") for row in group)
        if unit.get("active_state") in ("active", "activating"):
            proc = unit.get("process", {})
            result["ok"] &= proc.get("status") == "observed" and proc.get("executable_matches", False) and proc.get("invocation_matches", False)
    result["quiescent"] = bool(result["complete"]
        and all(u.get("active_state") == "inactive" for u in units if u["status"] == "observed")
        and all(l["status"] in ("free", "absent") for l in result["locks"])
        and not any(t["unresolved_runs"] or t["unacknowledged_failed_tickets"] for t in ledger["targets"]))
    result["limits"].append("Quiescent covers inventoried units/locks only; separately inventory cron, custom apply units and external triggers.")
    return result


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, prog="factory inspect")
    parser.add_argument("--json", action="store_true", help="JSON is also the default output")
    parser.add_argument("--live", action="store_true", help="validate scoped credentials with read-only provider requests")
    parser.add_argument("--candidates", action="store_true", help="query up to 1000 merged PRs; uses existing local Git objects only")
    parser.add_argument("--worker-cwd", type=Path, help="existing worker worktree for gate interpreter probe")
    args = parser.parse_args(argv)
    try:
        result = inspect(config.load(), live=args.live, candidates=args.candidates, worker_cwd=args.worker_cwd)
    except (config.ConfigError, OSError, ValueError, TypeError):
        result = {"schema_version": 1, "ok": False, "complete": False, "error": "inspection_unavailable"}
    print(json.dumps(result))
    return 0 if result["ok"] else 1
