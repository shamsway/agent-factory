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
If the repository's guidance says not to plan a root yourself, say so and leave
the counts to Factory: it appends the counts, addresses and actions from its own
gate plan check at the same revision.
Update this file after revisions; the dispatcher refreshes only this PR section.
The reviewer will reject a missing or incomplete summary before approval.
"""


def terraform_paths(paths: str) -> bool:
    return any(
        p.endswith((".tf", ".tf.json", ".terraform.lock.hcl"))
        for p in paths.splitlines()
    )


COUNTS = r"Plan:\s*\d+ to add,\s*\d+ to change,\s*\d+ to destroy"
# A no-op is a result line of its own ("No changes", "- Plan: No changes."), never the
# phrase inside prose such as "no changes to the image".
NO_CHANGES = r"^[ \t]*(?:[-*][ \t]*)?(?:Plan:[ \t]*)?No changes\b"


def validate(body: str, head: str | None = None) -> str | None:
    section = re.search(
        r"(?im)^## Terraform plan summary\s*$\n([\s\S]*?)(?=^##\s|\Z)", body or ""
    )
    if not section:
        return "PR description requires a ## Terraform plan summary section"
    text = section[1]
    if head and not re.search(r"(?im)^Revision:\s*" + re.escape(head) + r"\s*$", text):
        return "Terraform plan summary Revision must match the full gated HEAD SHA"
    if not re.search(rf"(?im){COUNTS}|{NO_CHANGES}", text):
        return "Terraform plan summary requires add/change/destroy counts or No changes with rationale"
    # Format is enforced here; truth and scope of the evidence are reviewed.
    if len(re.sub(rf"(?im){COUNTS}|{NO_CHANGES}", "", text).strip()) < 20:
        return "Terraform plan summary requires target, actions/rationale and validation context"
    return None


EVIDENCE_RE = re.compile(
    r"(?m)^factory-evidence: terraform-(?P<kind>plan|change) dir=(?P<dir>\S+) (?P<rest>.*)$"
)
PLAN_RE = re.compile(r"add=(\d+) change=(\d+) destroy=(\d+)$")
CHANGE_RE = re.compile(r"action=(\S+) address=(.+)$|more=(\d+)$")


EVIDENCE_HEADER = ("Plan evidence from the gate's own plan check at this revision, stamped by "
                   "Factory (counts, actions and addresses only):")


def evidence_block(report: str) -> str:
    """Markdown lines for the gate's own plan evidence in `report`, or "" when it has none.

    Only counts, actions and addresses: the plan check never prints values."""
    roots: dict[str, dict] = {}
    for match in EVIDENCE_RE.finditer(report or ""):
        root = roots.setdefault(match["dir"], {"plan": None, "changes": [], "more": 0})
        if match["kind"] == "plan" and (counts := PLAN_RE.fullmatch(match["rest"])):
            root["plan"] = tuple(int(n) for n in counts.groups())
        elif match["kind"] == "change" and (change := CHANGE_RE.fullmatch(match["rest"])):
            if change[3]:
                root["more"] = int(change[3])
            else:
                root["changes"].append((change[1], change[2]))
    lines = []
    for where, root in roots.items():
        if root["plan"] is None:
            continue
        add, change, destroy = root["plan"]
        lines.append(f"- `{where}`: Plan: {add} to add, {change} to change, {destroy} to destroy")
        lines += [f"  - {action} `{address}`" for action, address in root["changes"]]
        if root["more"]:
            lines.append(f"  - ... and {root['more']} more")
    if not lines:
        return ""
    return EVIDENCE_HEADER + "\n" + "\n".join(lines)


def compose(worker: str, evidence: str, head: str) -> str:
    """The PR's plan summary: the worker's section (if any) plus the gate's evidence.

    With evidence and no worker section, Factory writes a minimal section of its own;
    with neither, there is nothing to publish."""
    worker = section(worker)
    if EVIDENCE_HEADER in worker:  # only Factory writes this block; a copy in worker text is dropped
        worker = worker[: worker.index(EVIDENCE_HEADER)].rstrip()
    if not evidence:
        return worker
    if not worker:
        worker = ("## Terraform plan summary\n\n"
                  f"Revision: {head}\n\n"
                  "The worker wrote no plan summary; the evidence below is the gate's.")
    return worker.rstrip() + "\n\n" + evidence


def normalize_patch(diff: str) -> str:
    """A diff without blob ids or hunk line numbers, for comparing one patch
    across a rebase: identical content changes compare equal even when main
    moved the surrounding lines."""
    out = []
    for line in diff.splitlines():
        if line.startswith("index "):
            continue
        out.append(re.sub(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@", "@@", line))
    return "\n".join(out)


def restamp(body: str, old_head: str, new_head: str, note: str) -> str | None:
    """The body with the summary's `Revision: <old_head>` line moved to
    `new_head` (plus `note`), or None when the section does not name old_head."""
    match = re.search(
        r"(?im)^## Terraform plan summary\s*$\n[\s\S]*?(?=^##\s|\Z)", body or ""
    )
    if not match:
        return None
    line = re.compile(r"(?im)^Revision:\s*" + re.escape(old_head) + r"\s*$")
    if not line.search(match[0]):
        return None
    text = re.sub(r"(?m)^\n?Revision restamped by Factory .*\n?", "", match[0])
    updated = line.sub(lambda _: f"Revision: {new_head}\n\n{note}", text, count=1)
    return body[: match.start()] + updated + body[match.end():]


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
