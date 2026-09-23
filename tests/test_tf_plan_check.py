"""tf_plan_check pure-function and CLI checks.

Run: python -m unittest discover -s tests
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class TfPlanCheckTest(unittest.TestCase):
    """Pure-function checks against a canned `terraform show -json` shape;
    no terraform binary needed."""

    def test_run_plan_passes_env_to_both_subprocess_calls(self) -> None:
        """apply_env()'s credentials (e.g. OP_SERVICE_ACCOUNT_TOKEN) were
        computed but never actually passed to the plan subprocess -- run_plan
        had no env parameter at all, always inheriting the calling process's
        plain environment. Confirmed live: factory apply's fresh re-plan
        401'd against 1Password's interactive desktop-app flow because of
        this, even with apply_env() correctly populated. env=None (the
        gate's own CLI use, which already has install.env baked into its
        process by the dispatcher's systemd unit) must keep inheriting."""
        from unittest import mock

        from factory import tf_plan_check

        calls = []

        def fake_run(cmd, cwd=None, capture_output=None, text=None, env=None):
            calls.append(env)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        with mock.patch("subprocess.run", side_effect=fake_run):
            tf_plan_check.run_plan(Path("/tmp"), Path("/tmp/plan"), env={"FAKE": "1"})
        self.assertEqual(calls, [{"FAKE": "1"}, {"FAKE": "1"}])

        calls.clear()
        with mock.patch("subprocess.run", side_effect=fake_run):
            tf_plan_check.run_plan(Path("/tmp"), Path("/tmp/plan"))
        self.assertEqual(calls, [None, None])

    CLEAN_PLAN = {
        "resource_changes": [
            {"address": "aws_instance.foo", "change": {"actions": ["no-op"]}},
            {"address": "aws_s3_bucket.logs", "change": {"actions": ["create"]}},
        ]
    }
    DESTRUCTIVE_PLAN = {
        "resource_changes": [
            {"address": "aws_instance.foo", "change": {"actions": ["no-op"]}},
            {"address": "aws_instance.bar", "change": {"actions": ["delete", "create"]}},
            {"address": "aws_db_instance.main", "change": {"actions": ["delete"]}},
        ]
    }

    def test_clean_plan_has_no_destructive_changes(self) -> None:
        from factory import tf_plan_check

        self.assertEqual(tf_plan_check.destructive_changes(self.CLEAN_PLAN), [])
        self.assertEqual(tf_plan_check.unexpected_changes(self.CLEAN_PLAN, ""), [])

    def test_destructive_plan_flags_delete_and_replace(self) -> None:
        from factory import tf_plan_check

        changes = tf_plan_check.destructive_changes(self.DESTRUCTIVE_PLAN)
        self.assertEqual(
            {addr for addr, _ in changes}, {"aws_instance.bar", "aws_db_instance.main"}
        )

    def test_allowed_destroy_line_exempts_one_address(self) -> None:
        from factory import tf_plan_check

        ticket = "Upgrade the DB.\n\nAllowedDestroy: aws_db_instance.main\n"
        unexpected = tf_plan_check.unexpected_changes(self.DESTRUCTIVE_PLAN, ticket)
        self.assertEqual([addr for addr, _ in unexpected], ["aws_instance.bar"])

    def test_no_allow_list_flags_everything_destructive(self) -> None:
        from factory import tf_plan_check

        unexpected = tf_plan_check.unexpected_changes(self.DESTRUCTIVE_PLAN, "no allow lines here")
        self.assertEqual(
            {addr for addr, _ in unexpected}, {"aws_instance.bar", "aws_db_instance.main"}
        )

    def test_plan_out_directory_created_under_dir_not_invocation_cwd(self) -> None:
        """--plan-out is a path relative to --dir (that's what run_plan's
        subprocess, cwd=--dir, actually resolves it against), so the mkdir
        must create it there too -- not relative to wherever the check
        itself happens to be invoked from (the worktree root)."""
        from unittest import mock

        from factory import tf_plan_check

        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d).resolve()
            tf_root = tmp / "terraform" / "homelab-collectors"
            tf_root.mkdir(parents=True)
            invocation_cwd = tmp / "worktree-root"
            invocation_cwd.mkdir()

            original_cwd = Path.cwd()
            os.chdir(invocation_cwd)
            self.addCleanup(os.chdir, original_cwd)

            clean_proc = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
            with mock.patch.object(tf_plan_check, "run_plan", return_value=clean_proc) as run_plan, \
                 mock.patch.object(tf_plan_check, "show_json", return_value=self.CLEAN_PLAN):
                rc = tf_plan_check.main(
                    ["--dir", str(tf_root), "--plan-out", ".factory/tfplan"]
                )

            self.assertEqual(rc, 0)
            self.assertTrue((tf_root / ".factory").is_dir())
            self.assertFalse((invocation_cwd / ".factory").exists())
            run_plan.assert_called_once_with(Path(str(tf_root)), Path(".factory/tfplan"))


if __name__ == "__main__":
    unittest.main()
