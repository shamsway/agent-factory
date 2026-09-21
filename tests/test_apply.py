"""Apply config parsing and terraform-apply lifecycle behavior.

Run: python -m unittest discover -s tests
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from factory import config

from tests.test_factory import make_repo


class ApplyConfigTest(unittest.TestCase):
    def test_apply_table_parses(self) -> None:
        toml = '[apply]\nenabled = true\ndir = "terraform/prod"\n[apply.env]\nAWS_PROFILE = "infra-apply"\n'
        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), toml)
            cfg = config.load(repo)
            self.assertEqual((cfg.apply_enabled, cfg.apply_dir), (True, "terraform/prod"))
            self.assertEqual(cfg.apply_env, {"AWS_PROFILE": "infra-apply"})

    def test_apply_env_is_host_owned_dir_and_enabled_are_not(self) -> None:
        # Matches the dashboard.port split: [apply].env is credential-shaped
        # and host-owned (never in the committed repo file); enabled/dir are
        # policy about this repo and stay repo-owned.
        self.assertEqual(config.HOST_KEYS["apply"], ("env",))
        self.assertNotIn("apply", config.HOST_TABLES)


class ApplyTest(unittest.TestCase):
    def test_applied_tickets_from_events(self) -> None:
        from factory import apply, dispatch

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d))
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            dispatch.record("applied", ticket=7, pr=1, ok=True)
            dispatch.record("claimed", ticket=8, title="x")
            self.assertEqual(apply.applied_tickets(), {7})

    def test_merged_tickets_parses_agent_branch_prs_only(self) -> None:
        from unittest import mock

        from factory import apply, dispatch

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d))
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            prs = [
                {"number": 5, "headRefName": "agent/9", "mergeCommit": {"oid": "abc123"}},
                {"number": 6, "headRefName": "not-agent-branch", "mergeCommit": {"oid": "def456"}},
                {"number": 7, "headRefName": "agent/10", "mergeCommit": None},
            ]
            with mock.patch.object(dispatch, "gh_json", return_value=prs):
                tickets = apply.merged_tickets()
            self.assertEqual(tickets, [{"pr": 5, "ticket": 9, "commit": "abc123"}])

    def test_apply_fetches_main_before_scanning_merged_tickets(self) -> None:
        """touches_apply_dir() diffs {commit}~1..commit locally; if main
        hasn't independently fetched since the merge (`factory apply`
        invoked standalone, not right after a dispatch pass), the merge
        commit doesn't exist locally yet, the diff silently fails
        (check=False), and touches_apply_dir wrongly reports False.
        Confirmed live on ticket #45: a real apply-dir-touching merge was
        skipped as "doesn't touch ...; nothing to apply". The fetch must
        happen unconditionally, before merged_tickets/touches_apply_dir
        ever run -- not only inside fresh_checkout(), which runs after."""
        from unittest import mock

        from factory import apply, dispatch

        with tempfile.TemporaryDirectory() as d:
            toml = "[apply]\nenabled = true\n"
            repo = make_repo(Path(d), toml)
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            calls: list[tuple] = []

            def fake_run(cmd, cwd=None, check=True):
                calls.append(("run", cmd))
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            def fake_gh_json(args):
                calls.append(("gh_json", args))
                return []

            with mock.patch.object(config, "load", return_value=cfg), \
                 mock.patch.object(dispatch, "run", side_effect=fake_run), \
                 mock.patch.object(dispatch, "gh_json", side_effect=fake_gh_json):
                self.assertEqual(apply.main([]), 0)

            fetch_idx = next(
                i for i, c in enumerate(calls) if c[0] == "run" and c[1][:3] == ["git", "fetch", "origin"]
            )
            prlist_idx = next(i for i, c in enumerate(calls) if c[0] == "gh_json")
            self.assertLess(fetch_idx, prlist_idx)

    def test_merge_stage_waits_for_human_review_when_apply_enabled(self) -> None:
        """A PR that otherwise clears every other candidate filter (correct base,
        not draft, factory-approved label, no changes-requested) must still be
        held back by the apply-enabled human-review gate specifically -- not by
        an unrelated filter such as a missing/mismatched baseRefName."""
        from unittest import mock

        from factory import dispatch

        toml = "[apply]\nenabled = true\n"
        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), toml)
            cfg = config.load(repo)
            dispatch.configure(cfg)
            prs = [
                {
                    "number": 3,
                    "headRefName": "agent/9",
                    "headRefOid": "c0ffee",
                    "baseRefName": cfg.main,
                    "isDraft": False,
                    "labels": [{"name": config.LABEL_APPROVED}],
                    "reviewDecision": "REVIEW_REQUIRED",
                }
            ]
            with mock.patch.object(dispatch, "gh_json", return_value=prs), \
                 mock.patch.object(dispatch, "pr_checks") as checks, \
                 mock.patch.object(dispatch, "log") as log_mock:
                dispatch.merge_pass_locked(dry_run=True)
            # No candidates survive the human-review gate, so the CI-check
            # stage (and anything past it) is never reached.
            checks.assert_not_called()
            message = " ".join(str(c) for c in log_mock.call_args_list)
            self.assertIn("apply-eligible repo needs a human-approved review; waiting", message)

    def test_merge_stage_proceeds_past_human_review_gate_when_approved(self) -> None:
        """The positive counterpart: an identical PR with a real GitHub `APPROVED`
        review clears the human-review gate and reaches the CI-check stage."""
        from unittest import mock

        from factory import dispatch

        toml = "[apply]\nenabled = true\n"
        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), toml)
            cfg = config.load(repo)
            dispatch.configure(cfg)
            prs = [
                {
                    "number": 3,
                    "headRefName": "agent/9",
                    "headRefOid": "c0ffee",
                    "baseRefName": cfg.main,
                    "isDraft": False,
                    "labels": [{"name": config.LABEL_APPROVED}],
                    "reviewDecision": "APPROVED",
                }
            ]
            with mock.patch.object(dispatch, "gh_json", return_value=prs), \
                 mock.patch.object(dispatch, "initiative_kind", return_value=False), \
                 mock.patch.object(dispatch, "pr_checks") as checks:
                dispatch.merge_pass_locked(dry_run=True)
            checks.assert_called_once_with(3)

    def test_merge_stage_proceeds_when_apply_disabled_and_only_llm_approved(self) -> None:
        from unittest import mock

        from factory import dispatch

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d))
            cfg = config.load(repo)
            self.assertFalse(cfg.apply_enabled)
            dispatch.configure(cfg)
            prs = [
                {
                    "number": 3,
                    "headRefName": "agent/9",
                    "baseRefName": cfg.main,
                    "headRefOid": "c0ffee",
                    "isDraft": False,
                    "labels": [{"name": config.LABEL_APPROVED}],
                    "reviewDecision": "REVIEW_REQUIRED",
                }
            ]
            with mock.patch.object(dispatch, "gh_json", return_value=prs), \
                 mock.patch.object(dispatch, "initiative_kind", return_value=False), \
                 mock.patch.object(dispatch, "pr_checks", return_value=[]) as checks:
                dispatch.merge_pass_locked(dry_run=True)
            # apply.enabled is unset for this (software) repo, so the LLM's
            # factory-approved label is still enough to reach the CI-check
            # stage even without a human review yet.
            checks.assert_called_once_with(3)

    def test_apply_one_posts_to_issue_and_pr_on_success(self) -> None:
        from unittest import mock

        from factory import apply, dispatch, tf_plan_check

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), "[apply]\nenabled = true\n")
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            cfg.factory.mkdir(parents=True, exist_ok=True)
            wt = Path(d) / "checkout"
            (wt / cfg.apply_dir).mkdir(parents=True, exist_ok=True)

            calls: list[list[str]] = []

            def fake_run(cmd, cwd=None, check=True):
                calls.append(cmd)
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            apply_output = "Apply complete! Resources: 1 added, 0 changed, 0 destroyed."

            def fake_subproc_run(cmd, **kwargs):
                if cmd[:2] == ["terraform", "apply"]:
                    return subprocess.CompletedProcess(cmd, 0, stdout=apply_output, stderr="")
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            ticket = {"ticket": 42, "pr": 10, "commit": "c0ffee"}

            with mock.patch.object(apply, "touches_apply_dir", return_value=True), \
                 mock.patch.object(apply, "fresh_checkout", return_value=wt), \
                 mock.patch.object(tf_plan_check, "run_plan", return_value=subprocess.CompletedProcess([], 0, stdout="", stderr="")), \
                 mock.patch.object(dispatch, "gh_json", return_value={"body": ""}), \
                 mock.patch.object(tf_plan_check, "show_json", return_value={}), \
                 mock.patch.object(tf_plan_check, "unexpected_changes", return_value=[]), \
                 mock.patch("subprocess.run", side_effect=fake_subproc_run), \
                 mock.patch.object(dispatch, "run", side_effect=fake_run), \
                 mock.patch.object(dispatch, "pr_comment", wraps=dispatch.pr_comment) as mock_pr_comment:
                apply.apply_one(ticket, dry_run=False)

            # Issue comment
            issue_calls = [c for c in calls if c[:3] == ["gh", "issue", "comment"]]
            self.assertEqual(len(issue_calls), 1)
            self.assertEqual(issue_calls[0][3], "42")
            summary = issue_calls[0][issue_calls[0].index("--body") + 1]
            self.assertIn("`terraform apply` succeeded for the merged change:", summary)
            self.assertIn(apply_output, summary)

            # PR comment via dispatch.pr_comment
            mock_pr_comment.assert_called_once_with(42, summary)

            # PR comment via gh pr comment call
            pr_calls = [c for c in calls if c[:3] == ["gh", "pr", "comment"]]
            self.assertEqual(len(pr_calls), 1)
            self.assertEqual(pr_calls[0][3], "agent/42")
            body_file = Path(pr_calls[0][pr_calls[0].index("--body-file") + 1])
            self.assertEqual(body_file.read_text().strip(), summary.strip())

    def test_apply_one_posts_to_issue_and_pr_on_failure(self) -> None:
        from unittest import mock

        from factory import apply, dispatch, tf_plan_check

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), "[apply]\nenabled = true\n")
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            cfg.factory.mkdir(parents=True, exist_ok=True)
            wt = Path(d) / "checkout"
            (wt / cfg.apply_dir).mkdir(parents=True, exist_ok=True)

            calls: list[list[str]] = []

            def fake_run(cmd, cwd=None, check=True):
                calls.append(cmd)
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            error_output = "Error: provider failed to apply changes"

            def fake_subproc_run(cmd, **kwargs):
                if cmd[:2] == ["terraform", "apply"]:
                    return subprocess.CompletedProcess(cmd, 1, stdout="", stderr=error_output)
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            ticket = {"ticket": 42, "pr": 10, "commit": "c0ffee"}

            with mock.patch.object(apply, "touches_apply_dir", return_value=True), \
                 mock.patch.object(apply, "fresh_checkout", return_value=wt), \
                 mock.patch.object(tf_plan_check, "run_plan", return_value=subprocess.CompletedProcess([], 0, stdout="", stderr="")), \
                 mock.patch.object(dispatch, "gh_json", return_value={"body": ""}), \
                 mock.patch.object(tf_plan_check, "show_json", return_value={}), \
                 mock.patch.object(tf_plan_check, "unexpected_changes", return_value=[]), \
                 mock.patch("subprocess.run", side_effect=fake_subproc_run), \
                 mock.patch.object(dispatch, "run", side_effect=fake_run), \
                 mock.patch.object(dispatch, "pr_comment", wraps=dispatch.pr_comment) as mock_pr_comment:
                apply.apply_one(ticket, dry_run=False)

            # Issue comments: 1 for apply result (FAILED), 1 for escalation
            issue_calls = [c for c in calls if c[:3] == ["gh", "issue", "comment"]]
            self.assertEqual(len(issue_calls), 2)
            self.assertEqual(issue_calls[0][3], "42")
            summary = issue_calls[0][issue_calls[0].index("--body") + 1]
            self.assertIn("`terraform apply` FAILED for the merged change:", summary)
            self.assertIn(error_output, summary)

            self.assertEqual(issue_calls[1][3], "42")
            escalate_body = issue_calls[1][issue_calls[1].index("--body") + 1]
            self.assertEqual(escalate_body, "`factory apply` did not proceed: terraform apply failed.")

            # Both comments were also posted to the PR
            self.assertEqual(mock_pr_comment.call_count, 2)
            mock_pr_comment.assert_has_calls([
                mock.call(42, summary),
                mock.call(42, escalate_body),
            ])

            pr_calls = [c for c in calls if c[:3] == ["gh", "pr", "comment"]]
            self.assertEqual(len(pr_calls), 2)
            self.assertEqual(pr_calls[0][3], "agent/42")
            self.assertEqual(pr_calls[1][3], "agent/42")

    def test_apply_escalate_posts_to_issue_and_pr_when_called_directly(self) -> None:
        from unittest import mock

        from factory import apply, dispatch

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), "[apply]\nenabled = true\n")
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            cfg.factory.mkdir(parents=True, exist_ok=True)

            calls: list[list[str]] = []

            def fake_run(cmd, cwd=None, check=True):
                calls.append(cmd)
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            with mock.patch.object(dispatch, "run", side_effect=fake_run), \
                 mock.patch.object(dispatch, "pr_comment", wraps=dispatch.pr_comment) as mock_pr_comment:
                apply.apply_escalate(42, 10, "fresh plan failed: syntax error")

            expected_body = "`factory apply` did not proceed: fresh plan failed: syntax error."

            issue_calls = [c for c in calls if c[:3] == ["gh", "issue", "comment"]]
            self.assertEqual(len(issue_calls), 1)
            self.assertEqual(issue_calls[0][3], "42")
            self.assertEqual(issue_calls[0][issue_calls[0].index("--body") + 1], expected_body)

            mock_pr_comment.assert_called_once_with(42, expected_body)

            pr_calls = [c for c in calls if c[:3] == ["gh", "pr", "comment"]]
            self.assertEqual(len(pr_calls), 1)
            self.assertEqual(pr_calls[0][3], "agent/42")
            body_file = Path(pr_calls[0][pr_calls[0].index("--body-file") + 1])
            self.assertEqual(body_file.read_text().strip(), expected_body.strip())

    def test_apply_one_posts_to_issue_and_pr_on_fresh_plan_failure(self) -> None:
        from unittest import mock

        from factory import apply, dispatch, tf_plan_check

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), "[apply]\nenabled = true\n")
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            cfg.factory.mkdir(parents=True, exist_ok=True)
            wt = Path(d) / "checkout"
            (wt / cfg.apply_dir).mkdir(parents=True, exist_ok=True)

            calls: list[list[str]] = []

            def fake_run(cmd, cwd=None, check=True):
                calls.append(cmd)
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            ticket = {"ticket": 42, "pr": 10, "commit": "c0ffee"}
            plan_proc = subprocess.CompletedProcess([], 1, stdout="Error: invalid configuration", stderr="")

            with mock.patch.object(apply, "touches_apply_dir", return_value=True), \
                 mock.patch.object(apply, "fresh_checkout", return_value=wt), \
                 mock.patch.object(tf_plan_check, "run_plan", return_value=plan_proc), \
                 mock.patch.object(dispatch, "run", side_effect=fake_run), \
                 mock.patch.object(dispatch, "pr_comment", wraps=dispatch.pr_comment) as mock_pr_comment, \
                 mock.patch("subprocess.run") as mock_subproc_run:
                apply.apply_one(ticket, dry_run=False)

            # terraform apply should NOT have been reached
            mock_subproc_run.assert_not_called()

            # Escalation should have been posted to both issue and PR
            issue_calls = [c for c in calls if c[:3] == ["gh", "issue", "comment"]]
            self.assertEqual(len(issue_calls), 1)
            self.assertIn("fresh terraform plan failed", issue_calls[0][issue_calls[0].index("--body") + 1])

            self.assertEqual(mock_pr_comment.call_count, 1)
            self.assertIn("fresh terraform plan failed", mock_pr_comment.call_args[0][1])

            pr_calls = [c for c in calls if c[:3] == ["gh", "pr", "comment"]]
            self.assertEqual(len(pr_calls), 1)

    def test_apply_one_posts_to_issue_and_pr_on_unexpected_destroy(self) -> None:
        from unittest import mock

        from factory import apply, dispatch, tf_plan_check

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), "[apply]\nenabled = true\n")
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            cfg.factory.mkdir(parents=True, exist_ok=True)
            wt = Path(d) / "checkout"
            (wt / cfg.apply_dir).mkdir(parents=True, exist_ok=True)

            calls: list[list[str]] = []

            def fake_run(cmd, cwd=None, check=True):
                calls.append(cmd)
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            ticket = {"ticket": 42, "pr": 10, "commit": "c0ffee"}

            with mock.patch.object(apply, "touches_apply_dir", return_value=True), \
                 mock.patch.object(apply, "fresh_checkout", return_value=wt), \
                 mock.patch.object(tf_plan_check, "run_plan", return_value=subprocess.CompletedProcess([], 0, stdout="", stderr="")), \
                 mock.patch.object(dispatch, "gh_json", return_value={"body": ""}), \
                 mock.patch.object(tf_plan_check, "show_json", return_value={}), \
                 mock.patch.object(tf_plan_check, "unexpected_changes", return_value=[("aws_s3_bucket.logs", ["delete"])]), \
                 mock.patch.object(dispatch, "run", side_effect=fake_run), \
                 mock.patch.object(dispatch, "pr_comment", wraps=dispatch.pr_comment) as mock_pr_comment, \
                 mock.patch("subprocess.run") as mock_subproc_run:
                apply.apply_one(ticket, dry_run=False)

            # terraform apply should NOT have been reached
            mock_subproc_run.assert_not_called()

            # Escalation should have been posted to both issue and PR
            issue_calls = [c for c in calls if c[:3] == ["gh", "issue", "comment"]]
            self.assertEqual(len(issue_calls), 1)
            self.assertIn("fresh plan destroys/replaces aws_s3_bucket.logs (delete)", issue_calls[0][issue_calls[0].index("--body") + 1])

            self.assertEqual(mock_pr_comment.call_count, 1)
            self.assertIn("fresh plan destroys/replaces aws_s3_bucket.logs (delete)", mock_pr_comment.call_args[0][1])

            pr_calls = [c for c in calls if c[:3] == ["gh", "pr", "comment"]]
            self.assertEqual(len(pr_calls), 1)


if __name__ == "__main__":
    unittest.main()
