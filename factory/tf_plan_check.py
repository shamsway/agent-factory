"""Gate check: fail on a Terraform plan that destroys or replaces a resource
unless the ticket explicitly allow-lists it.

A clean `terraform plan` exit code says nothing about whether the plan is
*safe* — a forced-new attribute change plans cleanly but still destroys the
resource. This is an ordinary `[[gate.check]]` (arbitrary argv; no gate.py
change needed): it runs its own `terraform plan`, parses
`terraform show -json` for destroy/replace actions, and fails on anything
not explicitly expected.

    [[gate.check]]
    name = "tf-plan-safety"
    run = ["python", "-m", "factory.tf_plan_check"]
    timeout = 600

The binary plan holds every value the plan read, sensitive ones included.
Cleanup boundary, honestly:

- Default: the plan goes in a fresh 0700 directory under `$TMPDIR`, removed on
  return, on an exception and on SIGTERM/SIGINT/SIGHUP (the terraform child is
  killed first). The gate gives an unwrapped check its own `$TMPDIR` and removes
  it after the check, so a timeout's SIGKILL of the whole check leaves nothing; a
  later gate removes the scratch of a gate that was itself killed. Inside
  `scripts/bwrap-sandbox.sh` the check's /tmp is a private tmpfs that disappears
  with the sandbox, SIGKILL included.
- `--plan-out PATH` (relative to `--dir`): created 0600 in a directory created
  0700, never through a symlink; removed on the same exits. A plan left there by
  a killed run is removed, with a notice, before the next run of the check plans.
- Not covered: SIGKILL of the check outside a gate (explicit path, or the default
  directory outside the sandbox), and host crashes or power loss. `factory
  doctor` reports what it can find within its bounded scan: legacy
  `.factory/tfplan` files in the checkout and worktrees, and abandoned
  `factory-tfplan-*`/`factory-check-*` directories in the system temp directory.

Failure output is bounded and sanitized: terraform's error summaries and
source locations, never its detail bodies (provider responses can carry
secrets) or plan contents.

Allow a specific destroy/replace by adding a line to the ticket body (the
dispatcher writes the full ticket into `.factory-prompt.md` in the
worktree before the worker runs; that file is still on disk, just
gitignored, when the gate runs — this reads it by default):

    AllowedDestroy: aws_instance.foo
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

ALLOW_RE = re.compile(r"(?im)^AllowedDestroy:\s*(\S+)\s*$")


def allowed_addresses(ticket_text: str) -> set[str]:
    """Resource addresses explicitly allow-listed via `AllowedDestroy:` lines."""
    return set(ALLOW_RE.findall(ticket_text or ""))


def destructive_changes(plan_json: dict) -> list[tuple[str, list[str]]]:
    """[(address, actions)] for every resource_change whose actions include delete.

    Covers a plain delete (`["delete"]`) and both replace orderings
    (`["delete","create"]` / `["create","delete"]`) — anything that removes
    the existing resource, forced-new attribute changes included.
    """
    out = []
    for rc in plan_json.get("resource_changes", []):
        actions = rc.get("change", {}).get("actions", [])
        if "delete" in actions:
            out.append((rc["address"], actions))
    return out


def unexpected_changes(
    plan_json: dict, ticket_text: str
) -> list[tuple[str, list[str]]]:
    allowed = allowed_addresses(ticket_text)
    return [
        (addr, actions)
        for addr, actions in destructive_changes(plan_json)
        if addr not in allowed
    ]


def run_plan(cwd: Path, planfile: Path, env: dict | None = None) -> subprocess.CompletedProcess:
    """`env=None` inherits the calling process's environment (the gate's own
    CLI use: install.env is already baked into that process by the
    dispatcher's systemd unit). `factory apply`'s fresh re-plan needs
    apply.env explicitly instead -- confirmed live, that plan 401'd against
    1Password's desktop-app flow because apply_env()'s credentials were
    computed but never actually passed to this subprocess."""
    init = subprocess.run(  # noqa: PLW1510 - returncode is checked; test fakes reject check=
        ["terraform", "init", "-input=false", "-no-color"], cwd=cwd, capture_output=True, text=True, env=env
    )
    if init.returncode != 0:
        return init
    return subprocess.run(  # noqa: PLW1510 - caller checks returncode; test fakes reject check=
        ["terraform", "plan", "-input=false", "-no-color", "-out", str(planfile)],
        cwd=cwd,
        capture_output=True,
        text=True,
        env=env,
    )


DIAG_LINES = 12
DIAG_WIDTH = 200
# terraform's human diagnostics: `Error: <summary>` (bare, or inside the `│` box)
# and `on <file> line <n>` locations. Detail paragraphs are never echoed.
DIAG_RE = re.compile(r"^[\s│╷╵|]*((?:Error|Warning): .*|on \S+ line \d+.*)$")


def diagnostics(text: str) -> str:
    """At most DIAG_LINES summary/location lines of terraform output, each clipped."""
    kept = [m.group(1)[:DIAG_WIDTH] for line in (text or "").splitlines() if (m := DIAG_RE.match(line))]
    more = f"\n... {len(kept) - DIAG_LINES} more" if len(kept) > DIAG_LINES else ""
    return "\n".join(kept[:DIAG_LINES]) + more


def failed(step: str, proc: subprocess.CompletedProcess) -> int:
    print(f"tf-plan-safety: terraform {step} failed (exit {proc.returncode})")
    summary = diagnostics(proc.stdout + "\n" + (proc.stderr or ""))
    if summary:
        print(summary)
    print("(details withheld: terraform output can carry provider responses and planned values;"
          " re-run it locally to see them)")
    return proc.returncode or 1


class Terminated(Exception):
    """A termination signal arrived; unwinds through `finally` so the plan is removed."""


def _terminate(signum, _frame) -> None:
    raise Terminated(signum)


def show_json(cwd: Path, planfile: Path) -> dict:
    proc = subprocess.run(
        ["terraform", "show", "-json", str(planfile)],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(proc.stdout)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m factory.tf_plan_check",
        description="Fail if a terraform plan destroys/replaces a resource "
        "not allow-listed in the ticket.",
    )
    parser.add_argument("--dir", default=".", help="terraform root (default: cwd)")
    parser.add_argument(
        "--plan-out", default=None,
        help="path for the plan file, relative to --dir; deleted when the check ends "
        "(default: a private temp directory)",
    )
    parser.add_argument(
        "--ticket-file",
        default=".factory-prompt.md",
        help="file containing the ticket text, scanned for `AllowedDestroy:` "
        "lines (default: the dispatcher's prompt file, still on disk though "
        "gitignored when the gate runs)",
    )
    args = parser.parse_args(argv)

    cwd = Path(args.dir)
    previous = {sig: signal.signal(sig, _terminate) for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
    private = planfile = None
    try:
        if args.plan_out:
            planfile = Path(args.plan_out)
            explicit_target(cwd / planfile)
        else:
            private = Path(tempfile.mkdtemp(prefix=f"factory-tfplan-{os.getpid()}-"))
            planfile = private / "tfplan"
        return check(cwd, planfile, Path(args.ticket_file))
    except Terminated as exc:
        print(f"tf-plan-safety: terminated by signal {exc.args[0]}; plan removed")
        return 128 + exc.args[0]
    finally:
        if private:
            shutil.rmtree(private, ignore_errors=True)
        elif planfile is not None:
            target = cwd / planfile
            if target.is_file() and not target.is_symlink():
                target.unlink()
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def explicit_target(path: Path) -> None:
    """Make `--plan-out`'s directory (0700 when created here) and clear a plan a killed
    run left there. Never follows a symlink at the path or creates through one."""
    if path.is_symlink():
        raise SystemExit(f"tf-plan-safety: --plan-out {path} is a symlink; refusing")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists():
        if not path.is_file():
            raise SystemExit(f"tf-plan-safety: --plan-out {path} is not a regular file; refusing")
        path.unlink()
        print(f"tf-plan-safety: removed a plan an interrupted earlier run left at {path}")


def check(cwd: Path, planfile: Path, ticket_path: Path) -> int:
    umask = os.umask(0o077)  # the plan terraform writes is 0600, wherever it goes
    try:
        proc = run_plan(cwd, planfile)
    finally:
        os.umask(umask)
    if proc.returncode != 0:
        return failed("init/plan", proc)

    try:
        plan = show_json(cwd, planfile)
    except subprocess.CalledProcessError as exc:
        return failed("show", subprocess.CompletedProcess(exc.cmd, exc.returncode, exc.stdout or "", exc.stderr or ""))
    except json.JSONDecodeError:
        print("tf-plan-safety: terraform show -json output was not JSON (content withheld)")
        return 1
    ticket_text = ticket_path.read_text() if ticket_path.exists() else ""
    changes = destructive_changes(plan)
    if not changes:
        print("tf-plan-safety: no destroy/replace actions")
        return 0

    unexpected = unexpected_changes(plan, ticket_text)
    if not unexpected:
        print(f"tf-plan-safety: {len(changes)} destroy/replace action(s), all allow-listed")
        return 0

    print("tf-plan-safety: FAIL -- plan destroys/replaces resources not allow-listed:")
    for addr, actions in unexpected:
        print(f"  {addr}: {'/'.join(actions)}")
    print("\nAdd `AllowedDestroy: <address>` to the ticket body if this is expected.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
