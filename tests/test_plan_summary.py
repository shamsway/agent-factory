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
    def test_restamp_moves_only_the_summary_revision(self):
        body = "Intro Revision: aaa\n\n" + SUMMARY.replace("Revision: head", "Revision: aaa") + "\n## Other\nRevision: aaa\n"
        out = plan_summary.restamp(body, "aaa", "bbb", "Revision restamped by Factory from aaa.")
        self.assertIsNone(plan_summary.validate(out, "bbb"))
        self.assertIn("Revision restamped by Factory from aaa.", plan_summary.section(out))
        self.assertTrue(out.startswith("Intro Revision: aaa"))
        self.assertTrue(out.rstrip().endswith("## Other\nRevision: aaa"))
        again = plan_summary.restamp(out, "bbb", "ccc", "Revision restamped by Factory from bbb.")
        self.assertIsNone(plan_summary.validate(again, "ccc"))
        self.assertEqual(plan_summary.section(again).count("Revision restamped by Factory"), 1)

    def test_restamp_refuses_a_summary_naming_another_revision(self):
        body = SUMMARY.replace("Revision: head", "Revision: zzz")
        self.assertIsNone(plan_summary.restamp(body, "aaa", "bbb", "note"))
        self.assertIsNone(plan_summary.restamp("no summary", "aaa", "bbb", "note"))

    def test_normalize_patch_ignores_blob_ids_and_line_numbers_only(self):
        a = "diff --git a/x b/x\nindex 111..222 100644\n@@ -3,2 +3,2 @@ ctx\n-old\n+new\n"
        b = "diff --git a/x b/x\nindex 333..444 100644\n@@ -9,2 +9,2 @@ ctx\n-old\n+new\n"
        self.assertEqual(plan_summary.normalize_patch(a), plan_summary.normalize_patch(b))
        self.assertNotEqual(plan_summary.normalize_patch(a),
                            plan_summary.normalize_patch(b.replace("+new", "+newer")))

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
            review_policy="REVIEW.md",
            main="main",
            apply_enabled=apply_enabled,
            review_cmd=lambda p: ["reviewer", p],
            reviewer_json_mode=None,
        )

        def fake_run(cmd, **kwargs):
            if cmd[:3] == ["git", "diff", "--name-only"]:
                output = "terraform/main.tf\n"
            elif cmd[0] == "git":
                output = "head\n"
            else:
                called.append(cmd)
                output = '```json\n{"verdict":"APPROVE","findings":[]}\n```\nVERDICT: APPROVE'
            return subprocess.CompletedProcess(cmd, 0, stdout=output, stderr="")

        responses = [
            {"title": "Terraform update", "body": "Include the plan summary"},
            {"body": body, "headRefOid": head},
        ]
        with (
            mock.patch.object(dispatch, "cfg", cfg, create=True),
            mock.patch.object(dispatch, "REPO", "fixture/repo", create=True),
            mock.patch.object(dispatch, "EVENTS", root / "events.jsonl", create=True),
            mock.patch.object(dispatch, "gh_json", side_effect=responses),
            mock.patch.object(dispatch, "run", side_effect=fake_run),
            # The launch boundary (snapshot, neutral cwd) is test_review_isolation's subject.
            mock.patch.object(dispatch, "_run_reviewer", side_effect=lambda command, *_: dispatch.run(command)),
        ):
            verdict, findings = dispatch.review(root, 1, "PASS", "head")
        return verdict, findings, called

    def test_missing_summary_rejects_before_model_can_approve(self):
        verdict, _, called = self.review("No plan summary here")
        self.assertEqual(verdict, "REVISE")
        self.assertEqual(called, [])

    def test_pr_head_must_match_gate(self):
        with mock.patch.object(dispatch.time, "monotonic", side_effect=[0, 11]):
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
                review_policy="REVIEW.md",
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


class GitHubHeadWaitTest(unittest.TestCase):
    def test_old_head_is_retried_until_current_body_arrives(self):
        rows = [
            {"headRefOid": "old", "body": "old body"},
            {"headRefOid": "new", "body": "new body"},
        ]
        with (
            mock.patch.object(dispatch, "REPO", "fixture/repo", create=True),
            mock.patch.object(dispatch, "gh_json", side_effect=rows) as read,
            mock.patch.object(dispatch.time, "sleep") as sleep,
        ):
            current = dispatch.wait_for_pr_head("agent/1", "new")
        self.assertEqual(current["body"], "new body")
        self.assertEqual(read.call_count, 2)
        sleep.assert_called_once()

    def test_wait_is_bounded_and_does_not_accept_different_head(self):
        with (
            mock.patch.object(dispatch, "REPO", "fixture/repo", create=True),
            mock.patch.object(dispatch, "gh_json", return_value={"headRefOid": "old"}),
            mock.patch.object(dispatch.time, "monotonic", side_effect=[0, 0, 11]),
            mock.patch.object(dispatch.time, "sleep") as sleep,
            self.assertRaises(RuntimeError),
        ):
            dispatch.wait_for_pr_head("agent/1", "new")
        sleep.assert_called_once_with(0.5)

    def test_transient_api_failure_can_recover(self):
        with (
            mock.patch.object(dispatch, "REPO", "fixture/repo", create=True),
            mock.patch.object(
                dispatch,
                "gh_json",
                side_effect=[RuntimeError("temporary"), {"headRefOid": "new"}],
            ),
            mock.patch.object(dispatch.time, "sleep"),
        ):
            self.assertEqual(
                dispatch.wait_for_pr_head("agent/1", "new")["headRefOid"], "new"
            )


if __name__ == "__main__":
    unittest.main()
