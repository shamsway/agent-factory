"""Small, deterministic PR-description contract for Terraform changes."""

from __future__ import annotations

import re

INSTRUCTIONS = """
## Terraform PR evidence

When an apply-enabled repository changes Terraform files, include a
`## Terraform plan summary` section in the PR description. State the target,
planned resource addresses/actions and `Plan: N to add, N to change, N to destroy`.
For a no-op, state `No changes` and explain why. Include the plan command and
validation context; do not paste secrets or the raw plan. The summary must
reflect the current PR head. Update the PR description after revisions.
Before the first PR exists, write the section to
`.factory/terraform-plan-summary-{n}.md` (gitignored) after committing, including
`Revision: <full HEAD SHA>`. The dispatcher copies it into the PR description.
Update this file after revisions; the dispatcher refreshes only this PR section.
The reviewer will reject a missing or incomplete summary before approval.
"""


def terraform_paths(paths: str) -> bool:
    return any(
        p.endswith((".tf", ".tf.json", ".terraform.lock.hcl"))
        for p in paths.splitlines()
    )


def validate(body: str, head: str | None = None) -> str | None:
    section = re.search(
        r"(?im)^## Terraform plan summary\s*$\n([\s\S]*?)(?=^##\s|\Z)", body or ""
    )
    if not section:
        return "PR description requires a ## Terraform plan summary section"
    text = section[1]
    if head and not re.search(r"(?im)^Revision:\s*" + re.escape(head) + r"\s*$", text):
        return "Terraform plan summary Revision must match the full gated HEAD SHA"
    if not re.search(
        r"(?i)Plan:\s*\d+ to add,\s*\d+ to change,\s*\d+ to destroy|\bNo changes\b",
        text,
    ):
        return "Terraform plan summary requires add/change/destroy counts or No changes with rationale"
    # Format is enforced here; truth and scope of the evidence are reviewed.
    if (
        len(
            re.sub(
                r"(?i)Plan:\s*\d+ to add,\s*\d+ to change,\s*\d+ to destroy|No changes",
                "",
                text,
            ).strip()
        )
        < 20
    ):
        return "Terraform plan summary requires target, actions/rationale and validation context"
    return None


def section(body: str) -> str:
    match = re.search(
        r"(?im)^## Terraform plan summary\s*$\n[\s\S]*?(?=^##\s|\Z)", body or ""
    )
    return match[0].strip() if match else ""


def replace_section(body: str, summary: str) -> str:
    clean = re.sub(
        r"(?im)^## Terraform plan summary\s*$\n[\s\S]*?(?=^##\s|\Z)", "", body or ""
    ).rstrip()
    return clean + "\n\n" + section(summary) + "\n"
