import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from factory import dispatch, plan_summary

SUMMARY = """## Terraform plan summary
Target: collectors
Revision: head
Plan: 0 to add, 1 to change, 0 to destroy
Actions: nomad_job.collector updated in place
Validation: terraform plan against the reviewed target at this head
"""


class PlanSummaryTest(unittest.TestCase):
    def test_counts_and_context_are_required(self):
        self.assertIsNone(plan_summary.validate(SUMMARY))
        self.assertIsNotNone(plan_summary.validate(""))
        self.assertIsNotNone(
            plan_summary.validate(
                "## Terraform plan summary\nPlan: 0 to add, 1 to change, 0 to destroy"
            )
        )
        self.assertIsNotNone(
            plan_summary.validate(
                "## Terraform plan summary\nTarget: collectors; ran terraform plan"
            )
        )

    def test_noop_has_rationale(self):
        self.assertIsNone(
            plan_summary.validate(
                "## Terraform plan summary\nNo changes\nTarget: collectors. Rationale: metadata-only update has no resource diff."
            )
        )
        self.assertIsNotNone(
            plan_summary.validate("## Terraform plan summary\nNo changes")
        )

    def test_only_terraform_paths_require_summary(self):
        self.assertTrue(plan_summary.terraform_paths("terraform/main.tf\nREADME.md"))
        self.assertTrue(plan_summary.terraform_paths("root/.terraform.lock.hcl"))
        self.assertFalse(plan_summary.terraform_paths("README.md\nfactory/apply.py"))

    def review(self, body, head="head", apply_enabled=True):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        called = []
        cfg = SimpleNamespace(
            main="main",
            apply_enabled=apply_enabled,
            review_cmd=lambda p: ["reviewer", p],
        )

        def fake_run(cmd, **kwargs):
            if cmd[:3] == ["git", "diff", "--name-only"]:
                output = "terraform/main.tf\n"
            elif cmd[0] == "git":
                output = "head\n"
            else:
                called.append(cmd)
                output = "VERDICT: APPROVE"
            return subprocess.CompletedProcess(cmd, 0, stdout=output, stderr="")

        responses = [
            dict(title="Terraform update", body="Include the plan summary"),
            dict(body=body, headRefOid=head),
        ]
        with (
            mock.patch.object(dispatch, "cfg", cfg, create=True),
            mock.patch.object(dispatch, "REPO", "fixture/repo", create=True),
            mock.patch.object(dispatch, "EVENTS", root / "events.jsonl", create=True),
            mock.patch.object(dispatch, "gh_json", side_effect=responses),
            mock.patch.object(dispatch, "run", side_effect=fake_run),
        ):
            verdict, findings = dispatch.review(root, 1, "PASS", "head")
        return verdict, findings, called

    def test_missing_summary_rejects_before_model_can_approve(self):
        verdict, _, called = self.review("No plan summary here")
        self.assertEqual(verdict, "REVISE")
        self.assertEqual(called, [])

    def test_pr_head_must_match_gate(self):
        verdict, _, called = self.review(SUMMARY, head="changed")
        self.assertEqual(verdict, "REVISE")
        self.assertEqual(called, [])

    def test_summary_is_supplied_to_reviewer(self):
        verdict, _, called = self.review(SUMMARY)
        self.assertEqual(verdict, "APPROVE")
        self.assertIn(SUMMARY, called[0][-1])

    def test_summary_revision_is_bound_and_replacement_preserves_other_sections(self):
        self.assertIsNone(plan_summary.validate(SUMMARY, "head"))
        self.assertIsNotNone(plan_summary.validate(SUMMARY, "different"))
        updated = plan_summary.replace_section(
            "Closes #1\n\n" + SUMMARY + "\n## Gate report\nPASS", SUMMARY
        )
        self.assertEqual(updated.count("## Terraform plan summary"), 1)
        self.assertIn("## Gate report\nPASS", updated)
        self.assertIn("Closes #1", updated)

    def test_worker_summary_is_sanitized_before_pr_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".factory").mkdir()
            path = root / ".factory/terraform-plan-summary-1.md"
            path.write_text(SUMMARY + "credential-fixture-secret")
            cfg = SimpleNamespace(
                apply_enabled=True,
                apply_env={"KEY": "credential-fixture-secret"},
                install={},
            )
            process = subprocess.CompletedProcess([], 0, stdout="head\n", stderr="")
            with (
                mock.patch.object(dispatch, "cfg", cfg, create=True),
                mock.patch.object(dispatch, "run", return_value=process),
            ):
                summary = dispatch.worker_plan_summary(root, 1)
            self.assertIn("[REDACTED]", summary)
            self.assertNotIn("credential-fixture-secret", summary)

    def test_stale_worker_summary_cannot_be_published(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".factory").mkdir()
            (root / ".factory/terraform-plan-summary-1.md").write_text(SUMMARY)
            cfg = SimpleNamespace(apply_enabled=True)
            process = subprocess.CompletedProcess([], 0, stdout="new-head\n", stderr="")
            with (
                mock.patch.object(dispatch, "cfg", cfg, create=True),
                mock.patch.object(dispatch, "run", return_value=process),
            ):
                self.assertEqual(dispatch.worker_plan_summary(root, 1), "")

    def test_software_only_workflow_does_not_require_terraform_description(self):
        verdict, _, called = self.review("", apply_enabled=False)
        self.assertEqual(verdict, "APPROVE")
        self.assertEqual(len(called), 1)


if __name__ == "__main__":
    unittest.main()
