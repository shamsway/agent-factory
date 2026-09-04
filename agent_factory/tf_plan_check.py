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
    run = ["python", "-m", "agent_factory.tf_plan_check"]
    timeout = 600

Allow a specific destroy/replace by adding a line to the ticket body (the
dispatcher writes the full ticket into `.factory-prompt.md` in the
worktree before the worker runs; that file is still on disk, just
gitignored, when the gate runs — this reads it by default):

    AllowedDestroy: aws_instance.foo
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
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


def run_plan(cwd: Path, planfile: Path) -> subprocess.CompletedProcess:
    init = subprocess.run(
        ["terraform", "init", "-input=false"], cwd=cwd, capture_output=True, text=True
    )
    if init.returncode != 0:
        return init
    return subprocess.run(
        ["terraform", "plan", "-input=false", "-out", str(planfile)],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


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
        prog="python -m agent_factory.tf_plan_check",
        description="Fail if a terraform plan destroys/replaces a resource "
        "not allow-listed in the ticket.",
    )
    parser.add_argument("--dir", default=".", help="terraform root (default: cwd)")
    parser.add_argument(
        "--plan-out", default=".factory/tfplan", help="path to write the plan file"
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
    planfile = Path(args.plan_out)
    planfile.parent.mkdir(parents=True, exist_ok=True)

    proc = run_plan(cwd, planfile)
    if proc.returncode != 0:
        print(proc.stdout + proc.stderr)
        return proc.returncode

    plan = show_json(cwd, planfile)
    ticket_path = Path(args.ticket_file)
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
