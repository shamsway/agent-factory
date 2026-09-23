"""Unit and contract tests for deployment lifecycle, target configuration,
run persistence, and legacy event replay (SHA-186).
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from unittest import mock

from factory import apply, config, deploy, dispatch
from tests.test_factory import make_repo


def detached_from(fake_run):
    """Adapt a `subprocess.run` fake for `terraform apply` to the
    `deploy.run_terraform_detached` signature."""
    def run(cmd, cwd, env, timeout, log_path):
        result = fake_run(cmd)
        return result.returncode, (result.stdout or "") + (result.stderr or ""), False
    return run


class DeployTargetConfigTest(unittest.TestCase):
    """Test target configuration loading and backward compatibility."""

    def test_single_apply_table_maps_to_default_target(self) -> None:
        toml = '[apply]\nenabled = true\ndir = "terraform/homelab-collectors"\n'
        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), toml)
            cfg = config.load(repo)
            self.assertTrue(cfg.apply_enabled)
            self.assertEqual(cfg.apply_dir, "terraform/homelab-collectors")
            self.assertIn("default", cfg.targets)
            default_t = cfg.targets["default"]
            self.assertEqual(default_t.name, "default")
            self.assertEqual(default_t.dir, "terraform/homelab-collectors")
            self.assertTrue(default_t.enabled)

    def test_explicit_multi_targets_list_syntax(self) -> None:
        toml = """
[apply]
enabled = true

[[apply.targets]]
name = "collectors"
dir = "terraform/homelab-collectors"
backend_key = "homelab/collectors.tfstate"

[[apply.targets]]
name = "network"
dir = "terraform/network"
enabled = false
backend_key = "homelab/network.tfstate"
"""
        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), toml)
            cfg = config.load(repo)
            self.assertIn("collectors", cfg.targets)
            self.assertIn("network", cfg.targets)
            c = cfg.targets["collectors"]
            self.assertEqual(c.dir, "terraform/homelab-collectors")
            self.assertTrue(c.enabled)
            self.assertEqual(c.backend_key, "homelab/collectors.tfstate")
            n = cfg.targets["network"]
            self.assertEqual(n.dir, "terraform/network")
            self.assertFalse(n.enabled)
            self.assertEqual(n.backend_key, "homelab/network.tfstate")

    def test_explicit_multi_targets_dict_syntax(self) -> None:
        toml = """
[apply]
enabled = true

[apply.targets.collectors]
dir = "terraform/homelab-collectors"
enabled = true

[apply.targets.monitoring]
dir = "terraform/monitoring"
enabled = true
"""
        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), toml)
            cfg = config.load(repo)
            self.assertIn("collectors", cfg.targets)
            self.assertIn("monitoring", cfg.targets)
            self.assertEqual(cfg.targets["collectors"].dir, "terraform/homelab-collectors")
            self.assertEqual(cfg.targets["monitoring"].dir, "terraform/monitoring")


class DeployContractTest(unittest.TestCase):
    """Test versioned DeployRun contract and terminal state handling."""

    def test_versioned_contract_roundtrip(self) -> None:
        run = deploy.DeployRun(
            run_id="deploy-default-c0ffee12-1",
            target="default",
            commit="c0ffee1234567890",
            ticket=42,
            attempt=1,
            status=deploy.DeployStatus.SUCCEEDED,
            started_at="2026-09-14T01:00:00Z",
            completed_at="2026-09-14T01:00:15Z",
            duration_sec=15.2,
            pr=10,
            output="Apply complete! Resources: 1 added, 0 changed, 0 destroyed.",
            error=None,
            version=1,
        )
        as_dict = run.to_dict()
        self.assertEqual(as_dict["version"], 1)
        self.assertEqual(as_dict["status"], "succeeded")
        self.assertTrue(run.is_terminal())

        reconstructed = deploy.DeployRun.from_dict(as_dict)
        self.assertEqual(reconstructed.run_id, run.run_id)
        self.assertEqual(reconstructed.status, deploy.DeployStatus.SUCCEEDED)
        self.assertEqual(reconstructed.duration_sec, 15.2)
        self.assertEqual(reconstructed.ticket, 42)
        self.assertEqual(reconstructed.pr, 10)

    def test_terminal_state_classification(self) -> None:
        for status in (
            deploy.DeployStatus.SUCCEEDED,
            deploy.DeployStatus.FAILED,
            deploy.DeployStatus.SKIPPED,
            deploy.DeployStatus.CANCELLED,
        ):
            run = deploy.DeployRun(
                run_id="test",
                target="default",
                commit="abc",
                ticket=1,
                attempt=1,
                status=status,
                started_at="2026-09-14T01:00:00Z",
            )
            self.assertTrue(run.is_terminal(), f"{status} should be terminal")

        for status in (deploy.DeployStatus.PENDING, deploy.DeployStatus.RUNNING):
            run = deploy.DeployRun(
                run_id="test",
                target="default",
                commit="abc",
                ticket=1,
                attempt=1,
                status=status,
                started_at="2026-09-14T01:00:00Z",
            )
            self.assertFalse(run.is_terminal(), f"{status} should not be terminal")


class DeployMigrationAndReplayTest(unittest.TestCase):
    """Replay and migration tests verifying failed, skipped, and successful histories."""

    def test_replay_preserves_legacy_successful_failed_and_skipped_histories(self) -> None:
        lines = [
            # Legacy successful apply
            json.dumps({"at": "2026-09-14T00:01:00Z", "event": "applied", "ticket": 10, "pr": 1, "commit": "commit1", "ok": True, "output": "Apply complete!"}),
            # Legacy skipped apply (no changes under apply dir)
            json.dumps({"at": "2026-09-14T00:02:00Z", "event": "applied", "ticket": 11, "pr": 2, "commit": "commit2", "ok": True, "note": "no changes under apply dir"}),
            # Legacy failed apply (ok=False)
            json.dumps({"at": "2026-09-14T00:03:00Z", "event": "applied", "ticket": 12, "pr": 3, "commit": "commit3", "ok": False, "output": "Error: provider failed"}),
            # Legacy apply-escalate
            json.dumps({"at": "2026-09-14T00:04:00Z", "event": "apply-escalate", "ticket": 13, "pr": 4, "reason": "fresh terraform plan failed"}),
        ]
        with tempfile.TemporaryDirectory() as d:
            events_file = Path(d) / "events.jsonl"
            events_file.write_text("\n".join(lines) + "\n")

            states = deploy.replay_events(events_file)
            self.assertIn("default", states)
            target = states["default"]

            # Verify runs count
            self.assertEqual(len(target.runs), 4)

            # Ticket 10 was successful
            r10 = target.runs_by_ticket[10][0]
            self.assertEqual(r10.status, deploy.DeployStatus.SUCCEEDED)
            self.assertIn(10, target.succeeded_tickets)
            self.assertIn(10, target.terminal_tickets)
            self.assertNotIn(10, target.failed_tickets)

            # Ticket 11 was skipped
            r11 = target.runs_by_ticket[11][0]
            self.assertEqual(r11.status, deploy.DeployStatus.SKIPPED)
            self.assertIn(11, target.skipped_tickets)
            self.assertIn(11, target.terminal_tickets)
            self.assertNotIn(11, target.succeeded_tickets)

            # Ticket 12 failed (ok=False) - MUST NOT become success
            r12 = target.runs_by_ticket[12][0]
            self.assertEqual(r12.status, deploy.DeployStatus.FAILED)
            self.assertIn(12, target.failed_tickets)
            self.assertNotIn(12, target.succeeded_tickets)
            self.assertEqual(r12.error, "Error: provider failed")

            # Ticket 13 failed (apply-escalate) - MUST NOT become success
            r13 = target.runs_by_ticket[13][0]
            self.assertEqual(r13.status, deploy.DeployStatus.FAILED)
            self.assertIn(13, target.failed_tickets)
            self.assertNotIn(13, target.succeeded_tickets)
            self.assertEqual(r13.error, "fresh terraform plan failed")

            # Crucial requirement: failed legacy events MUST NOT silently auto-retry
            # Both 12 and 13 are in terminal_tickets so they are excluded from pending applies
            self.assertIn(12, target.terminal_tickets)
            self.assertIn(13, target.terminal_tickets)
            terminals = deploy.terminal_tickets(target="default", events_path=events_file)
            self.assertEqual(terminals, {10, 11, 12, 13})

            # Latest succeeded commit is commit1 (commit3 was failed, commit2 was skipped)
            self.assertEqual(target.latest_succeeded_commit, "commit1")

    def test_modern_deploy_run_replay_and_attempt_tracking(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            events_file = Path(d) / "events.jsonl"

            # Attempt 1 for ticket 50 fails
            run1 = deploy.DeployRun(
                run_id="deploy-default-commitA-1",
                target="default",
                commit="commitA",
                ticket=50,
                attempt=1,
                status=deploy.DeployStatus.FAILED,
                started_at="2026-09-14T00:10:00Z",
                completed_at="2026-09-14T00:10:05Z",
                duration_sec=5.0,
                error="syntax error in configuration",
            )
            deploy.record_deploy_run(run1, events_path=events_file)

            # Check next attempt calculation
            next_att = deploy.next_attempt("default", 50, "commitA", events_path=events_file)
            self.assertEqual(next_att, 2)

            # Target state after attempt 1
            state = deploy.get_target_state("default", events_path=events_file)
            self.assertIn(50, state.failed_tickets)
            self.assertNotIn(50, state.succeeded_tickets)

            # Attempt 2 for ticket 50 succeeds
            run2 = deploy.DeployRun(
                run_id="deploy-default-commitA-2",
                target="default",
                commit="commitA",
                ticket=50,
                attempt=2,
                status=deploy.DeployStatus.SUCCEEDED,
                started_at="2026-09-14T00:15:00Z",
                completed_at="2026-09-14T00:15:10Z",
                duration_sec=10.0,
                output="Apply complete!",
            )
            deploy.record_deploy_run(run2, events_path=events_file)

            # Target state after attempt 2
            state2 = deploy.get_target_state("default", events_path=events_file)
            self.assertEqual(len(state2.runs_by_ticket[50]), 2)
            self.assertIn(50, state2.succeeded_tickets)
            self.assertNotIn(50, state2.failed_tickets)
            self.assertEqual(state2.latest_run.run_id, "deploy-default-commitA-2")
            self.assertEqual(state2.latest_succeeded_commit, "commitA")

    def test_interrupted_run_detection(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            events_file = Path(d) / "events.jsonl"

            # Run starts in RUNNING state but crashes before terminal completion
            in_flight = deploy.DeployRun(
                run_id="deploy-default-commitX-1",
                target="default",
                commit="commitX",
                ticket=99,
                attempt=1,
                status=deploy.DeployStatus.RUNNING,
                started_at="2026-09-14T00:20:00Z",
            )
            deploy.record_deploy_run(in_flight, events_path=events_file)

            state = deploy.get_target_state("default", events_path=events_file)
            self.assertTrue(state.has_interrupted_run)
            self.assertNotIn(99, state.terminal_tickets)

            # Completing the run reconciles the interrupted state
            completed = deploy.DeployRun(
                run_id="deploy-default-commitX-1",
                target="default",
                commit="commitX",
                ticket=99,
                attempt=1,
                status=deploy.DeployStatus.SUCCEEDED,
                started_at="2026-09-14T00:20:00Z",
                completed_at="2026-09-14T00:20:30Z",
                output="Success after recovery",
            )
            deploy.record_deploy_run(completed, events_path=events_file)

            state2 = deploy.get_target_state("default", events_path=events_file)
            self.assertFalse(state2.has_interrupted_run)
            self.assertIn(99, state2.terminal_tickets)
            self.assertIn(99, state2.succeeded_tickets)


class DeployApplyIntegrationTest(unittest.TestCase):
    """Integration tests verifying apply.py uses deploy lifecycle and contracts."""

    def test_apply_one_records_versioned_deploy_run_on_success(self) -> None:
        import subprocess
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

            ticket = {"ticket": 77, "pr": 12, "commit": "deadbeef1234"}
            apply_output = "Apply complete! Resources: 1 added, 0 changed, 0 destroyed."

            def fake_subproc_run(cmd, **kwargs):
                if cmd[:2] == ["terraform", "apply"]:
                    return subprocess.CompletedProcess(cmd, 0, stdout=apply_output, stderr="")
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            with mock.patch.object(apply, "touches_apply_dir", return_value=True), \
                 mock.patch.object(apply, "fresh_checkout", return_value=wt), \
                 mock.patch.object(tf_plan_check, "run_plan", return_value=subprocess.CompletedProcess([], 0, stdout="", stderr="")), \
                 mock.patch.object(dispatch, "gh_json", return_value={"body": ""}), \
                 mock.patch.object(tf_plan_check, "show_json", return_value={}), \
                 mock.patch.object(tf_plan_check, "unexpected_changes", return_value=[]), \
                 mock.patch("subprocess.run", side_effect=fake_subproc_run), \
                 mock.patch("factory.deploy.run_terraform_detached", side_effect=detached_from(fake_subproc_run)), \
                 mock.patch.object(dispatch, "run", return_value=subprocess.CompletedProcess([], 0, stdout="", stderr="")), \
                 mock.patch.object(dispatch, "pr_comment"):
                apply.apply_one(ticket, dry_run=False)

            # Check that deploy_run event was recorded to events.jsonl
            state = deploy.get_target_state("default", events_path=dispatch.EVENTS)
            self.assertEqual(len(state.runs), 1)
            run = state.runs[0]
            self.assertEqual(run.ticket, 77)
            self.assertEqual(run.commit, "deadbeef1234")
            self.assertEqual(run.pr, 12)
            self.assertEqual(run.attempt, 1)
            self.assertEqual(run.status, deploy.DeployStatus.SUCCEEDED)
            self.assertEqual(run.version, deploy.CONTRACT_VERSION)
            self.assertIn(apply_output, run.output)
            self.assertEqual(state.latest_succeeded_commit, "deadbeef1234")
            self.assertIn(77, apply.applied_tickets())

    def test_apply_one_records_failed_deploy_run_and_prevents_silent_retry(self) -> None:
        import subprocess
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

            ticket = {"ticket": 88, "pr": 15, "commit": "badf00d1234"}
            err_msg = "Error: target failed to apply"

            def fake_subproc_run(cmd, **kwargs):
                if cmd[:2] == ["terraform", "apply"]:
                    return subprocess.CompletedProcess(cmd, 1, stdout="", stderr=err_msg)
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            with mock.patch.object(apply, "touches_apply_dir", return_value=True), \
                 mock.patch.object(apply, "fresh_checkout", return_value=wt), \
                 mock.patch.object(tf_plan_check, "run_plan", return_value=subprocess.CompletedProcess([], 0, stdout="", stderr="")), \
                 mock.patch.object(dispatch, "gh_json", return_value={"body": ""}), \
                 mock.patch.object(tf_plan_check, "show_json", return_value={}), \
                 mock.patch.object(tf_plan_check, "unexpected_changes", return_value=[]), \
                 mock.patch("subprocess.run", side_effect=fake_subproc_run), \
                 mock.patch("factory.deploy.run_terraform_detached", side_effect=detached_from(fake_subproc_run)), \
                 mock.patch.object(dispatch, "run", return_value=subprocess.CompletedProcess([], 0, stdout="", stderr="")), \
                 mock.patch.object(dispatch, "pr_comment"):
                apply.apply_one(ticket, dry_run=False)

            state = deploy.get_target_state("default", events_path=dispatch.EVENTS)
            self.assertIn(88, state.failed_tickets)
            self.assertNotIn(88, state.succeeded_tickets)

            # Crucial: 88 must be recognized as terminal in applied_tickets
            # so the next apply pass never silently auto-retries it without coordination
            done = apply.applied_tickets()
            self.assertIn(88, done)


class DeploySelectionAndAuthorizationTest(unittest.TestCase):
    """Regression and contract tests for SHA-187:
    overlapping passes, direct merges, old revisions, and multiple targets.
    """

    def test_overlapping_passes_prevented_by_locks(self) -> None:
        """Target and backend locks prevent concurrent overlapping passes."""
        from unittest import mock
        from factory import apply, dispatch

        with tempfile.TemporaryDirectory() as d:
            toml = '[apply]\nenabled = true\nbackend = "homelab/shared.tfstate"\n'
            repo = make_repo(Path(d), toml)
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            cfg.factory.mkdir(parents=True, exist_ok=True)

            # Lock target 'default'
            ok, lock_fd = deploy.acquire_target_lock(cfg.factory, "default")
            self.assertTrue(ok)

            with mock.patch.object(config, "load", return_value=cfg), \
                 mock.patch.object(dispatch, "run"), \
                 mock.patch.object(apply, "fetch_all_merged_prs", return_value=[{"pr": 1, "ticket": 10, "commit": "c1"}]), \
                 mock.patch.object(apply, "apply_one") as mock_apply_one:
                ret = apply.main([])
                self.assertEqual(ret, 0)
                # apply_one must NOT have been called because target was locked
                mock_apply_one.assert_not_called()

            deploy.release_lock(lock_fd)

    def test_direct_merges_on_main_detected_and_execution_refused(self) -> None:
        """Direct pushes/merges to main touching a target dir are flagged as unauthorized."""
        from unittest import mock
        from factory import apply, dispatch
        from tests.test_factory import git

        with tempfile.TemporaryDirectory() as d:
            toml = '[apply]\nenabled = true\ndir = "terraform"\n'
            repo = make_repo(Path(d), toml)
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            cfg.factory.mkdir(parents=True, exist_ok=True)

            # Create an unauthorized direct merge directly on main touching terraform/
            tf_dir = repo / "terraform"
            tf_dir.mkdir()
            (tf_dir / "main.tf").write_text("resource aws_s3_bucket direct {}\n")
            git(repo, "add", "-A")
            git(repo, "commit", "-q", "-m", "unauthorized direct commit")
            direct_sha = git(repo, "rev-parse", "HEAD")

            approved_pr = {
                "pr": 20,
                "ticket": 30,
                "commit": "other_commit_123",
                "head_commit": "other_commit_123",
                "reviewDecision": "APPROVED",
                "latestReviews": [
                    {"state": "APPROVED", "commit": {"oid": "other_commit_123"}}
                ],
            }

            with mock.patch.object(config, "load", return_value=cfg), \
                 mock.patch.object(dispatch, "run"), \
                 mock.patch.object(apply, "fetch_all_merged_prs", return_value=[approved_pr]), \
                 mock.patch.object(apply, "apply_one") as mock_apply_one:
                apply.main([])
                # Direct merge must block execution on target
                mock_apply_one.assert_not_called()

            # Check that deploy_unauthorized was recorded
            events = (cfg.factory / "events.jsonl").read_text()
            self.assertIn("deploy_unauthorized", events)
            self.assertIn(direct_sha[:8], events)

    def test_old_revisions_and_stale_reviews_rejected(self) -> None:
        """Revision-bound checks reject unapproved or stale approvals."""
        from unittest import mock
        from factory import apply, dispatch

        # Case 1: reviewDecision is not APPROVED
        pr_unapproved = {
            "pr": 21,
            "ticket": 31,
            "commit": "c_unapproved",
            "head_commit": "c_unapproved",
            "reviewDecision": "CHANGES_REQUESTED",
        }
        ok, reason = deploy.verify_revision_authorization(pr_unapproved)
        self.assertFalse(ok)
        self.assertIn("CHANGES_REQUESTED", reason)

        # Case 2: review approved on commit A, but commit B was merged
        pr_stale = {
            "pr": 22,
            "ticket": 32,
            "commit": "merge_commit_oid",
            "head_commit": "rev_b_head_oid",
            "reviewDecision": "APPROVED",
            "latestReviews": [
                {"state": "APPROVED", "author": {"login": "human"}, "authorAssociation": "MEMBER", "commit": {"oid": "rev_a_old_oid"}}
            ],
        }
        ok, reason = deploy.verify_revision_authorization(pr_stale)
        self.assertFalse(ok)
        self.assertIn("stale review", reason)

        # Case 3: review approved on matching commit B
        pr_valid = {
            "pr": 23,
            "ticket": 33,
            "commit": "merge_commit_oid",
            "head_commit": "rev_b_head_oid",
            "reviewDecision": "APPROVED",
            "latestReviews": [
                {"state": "APPROVED", "author": {"login": "human"}, "authorAssociation": "MEMBER", "commit": {"oid": "rev_b_head_oid"}}
            ],
        }
        ok, reason = deploy.verify_revision_authorization(pr_valid)
        self.assertTrue(ok)
        self.assertEqual(reason, "")

        # Test in apply.main(): stale review causes apply_escalate and aborts apply_one
        with tempfile.TemporaryDirectory() as d:
            toml = '[apply]\nenabled = true\n'
            repo = make_repo(Path(d), toml)
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            cfg.factory.mkdir(parents=True, exist_ok=True)

            with mock.patch.object(config, "load", return_value=cfg), \
                 mock.patch.object(dispatch, "run"), \
                 mock.patch.object(apply, "fetch_all_merged_prs", return_value=[pr_stale]), \
                 mock.patch.object(apply, "touches_apply_dir", return_value=True), \
                 mock.patch.object(apply, "apply_escalate") as mock_escalate, \
                 mock.patch.object(apply, "apply_one") as mock_apply_one:
                apply.main([])
                mock_escalate.assert_called_once()
                mock_apply_one.assert_not_called()

    def test_per_target_ordering_and_sequential_failure_blocking(self) -> None:
        """Candidates are ordered topologically, and sequential mode halts on failure."""
        from unittest import mock
        from factory import apply, dispatch
        from tests.test_factory import git

        with tempfile.TemporaryDirectory() as d:
            toml = '[apply]\nenabled = true\ndir = "terraform"\n'
            repo = make_repo(Path(d), toml)
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            cfg.factory.mkdir(parents=True, exist_ok=True)

            tf_dir = repo / "terraform"
            tf_dir.mkdir()

            # Commit 1 on main
            (tf_dir / "a.tf").write_text("# A\n")
            git(repo, "add", "-A")
            git(repo, "commit", "-q", "-m", "commit A")
            c_a = git(repo, "rev-parse", "HEAD")

            # Commit 2 on main
            (tf_dir / "b.tf").write_text("# B\n")
            git(repo, "add", "-A")
            git(repo, "commit", "-q", "-m", "commit B")
            c_b = git(repo, "rev-parse", "HEAD")

            # Feed PR list in REVERSE order: B before A
            pr_b = {
                "pr": 2, "ticket": 12, "commit": c_b, "head_commit": c_b, "reviewDecision": "APPROVED",
                "latestReviews": [{"state": "APPROVED", "author": {"login": "human"}, "authorAssociation": "MEMBER", "commit": {"oid": c_b}}],
            }
            pr_a = {
                "pr": 1, "ticket": 11, "commit": c_a, "head_commit": c_a, "reviewDecision": "APPROVED",
                "latestReviews": [{"state": "APPROVED", "author": {"login": "human"}, "authorAssociation": "MEMBER", "commit": {"oid": c_a}}],
            }
            all_prs = [pr_b, pr_a]

            candidates, unauth = deploy.select_candidates_for_target(
                target_name="default",
                target_dir="terraform",
                all_prs=all_prs,
                root=repo,
                main_branch="main",
            )
            self.assertEqual(unauth, [])
            # Must be ordered topologically: PR 1 (c_a) before PR 2 (c_b)
            self.assertEqual([c["pr"] for c in candidates], [1, 2])

            # Now test sequential failure blocking: if ticket 11 fails, ticket 12 must not run
            def fake_apply_one(candidate, dry_run, target="default"):
                # Mark ticket 11 as failed
                run = deploy.DeployRun(
                    run_id=f"deploy-{target}-{candidate['commit'][:8]}-1",
                    target=target,
                    commit=candidate["commit"],
                    ticket=candidate["ticket"],
                    attempt=1,
                    status=deploy.DeployStatus.FAILED if candidate["ticket"] == 11 else deploy.DeployStatus.SUCCEEDED,
                    started_at="2026-09-14T01:00:00Z",
                )
                deploy.record_deploy_run(run)

            with mock.patch.object(config, "load", return_value=cfg), \
                 mock.patch.object(dispatch, "run"), \
                 mock.patch.object(apply, "fetch_all_merged_prs", return_value=all_prs), \
                 mock.patch.object(apply, "apply_one", side_effect=fake_apply_one) as mock_apply:
                apply.main([])
                # Only ticket 11 should have run; ticket 12 blocked due to ticket 11's failure
                self.assertEqual(mock_apply.call_count, 1)
                self.assertEqual(mock_apply.call_args[0][0]["ticket"], 11)

    def test_adoption_baseline_filtering(self) -> None:
        """PRs or commits at or before adoption baseline are excluded from selection."""
        from tests.test_factory import git

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d))
            # PR number baseline: baseline = 50
            self.assertTrue(deploy.is_before_baseline(pr_number=50, commit="abc", baseline="50", root=repo))
            self.assertTrue(deploy.is_before_baseline(pr_number=49, commit="abc", baseline="50", root=repo))
            self.assertFalse(deploy.is_before_baseline(pr_number=51, commit="abc", baseline="50", root=repo))

            # Commit SHA baseline: baseline = commit A
            base_sha = git(repo, "rev-parse", "HEAD")
            self.assertTrue(deploy.is_before_baseline(pr_number=99, commit=base_sha, baseline=base_sha[:8], root=repo))

            # New commit after baseline
            (repo / "new.txt").write_text("after baseline\n")
            git(repo, "add", "-A")
            git(repo, "commit", "-q", "-m", "new commit")
            new_sha = git(repo, "rev-parse", "HEAD")
            self.assertFalse(deploy.is_before_baseline(pr_number=99, commit=new_sha, baseline=base_sha, root=repo))

    def test_multiple_targets_isolation_and_shared_backend(self) -> None:
        """Targets only process changes to their own dir, and shared backends serialize."""
        from unittest import mock
        from factory import apply, dispatch

        with tempfile.TemporaryDirectory() as d:
            toml = """
[apply]
enabled = true

[[apply.targets]]
name = "collectors"
dir = "terraform/collectors"
backend_key = "shared_homelab"

[[apply.targets]]
name = "monitoring"
dir = "terraform/monitoring"
backend_key = "shared_homelab"
"""
            repo = make_repo(Path(d), toml)
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            cfg.factory.mkdir(parents=True, exist_ok=True)

            self.assertEqual(cfg.targets["collectors"].backend_key, "shared_homelab")
            self.assertEqual(cfg.targets["monitoring"].backend_key, "shared_homelab")

            # Holding backend lock for 'shared_homelab' prevents both targets from running
            b_ok, b_fd = deploy.acquire_backend_lock(cfg.factory, "shared_homelab")
            self.assertTrue(b_ok)

            with mock.patch.object(config, "load", return_value=cfg), \
                 mock.patch.object(dispatch, "run"), \
                 mock.patch.object(apply, "fetch_all_merged_prs", return_value=[]), \
                 mock.patch.object(apply, "apply_one") as mock_apply_one:
                apply.main([])
                mock_apply_one.assert_not_called()

            deploy.release_lock(b_fd)


class DeployAdapterAndRecoveryTest(unittest.TestCase):
    """Regression and contract tests for SHA-188:
    - DeployAdapter prepare/check/execute/verify lifecycle hooks
    - Fake second adapter proving pluggability without external platform
    - Interrupted run recovery and reconciliation requirement
    - Durable persistence prior to notification failure preventing re-execution
    - Bounded subprocess execution with truthful exit codes and dry-run behavior
    """

    def test_fake_adapter_lifecycle_hooks_and_pluggability(self) -> None:
        """Fake adapter executes all hooks in sequence and writes versioned runs."""
        with tempfile.TemporaryDirectory() as d:
            toml = """
[apply]
enabled = true

[apply.targets.custom]
dir = "services/app"
adapter = "fake"
"""
            repo = make_repo(Path(d), toml)
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            cfg.factory.mkdir(parents=True, exist_ok=True)

            fake_adapter = deploy.FakeDeployAdapter(name="fake", output="custom service deployed successfully")
            deploy.register_adapter("fake", lambda: fake_adapter)

            ticket = {"ticket": 50, "pr": 15, "commit": "commit50"}

            with mock.patch.object(apply, "touches_target_dir", return_value=True), \
                 mock.patch.object(dispatch, "run"), \
                 mock.patch.object(dispatch, "pr_comment"):
                success = apply.apply_one(ticket, dry_run=False, target="custom", adapter=fake_adapter)
                self.assertTrue(success)

            # Assert all lifecycle hooks were called in order
            self.assertEqual(fake_adapter.calls, ["prepare", "check", "execute", "verify", "cleanup"])

            # Verify durable state
            state = deploy.get_target_state("custom", events_path=cfg.factory / "events.jsonl")
            self.assertEqual(len(state.runs), 1)
            run = state.latest_run
            self.assertIsNotNone(run)
            self.assertEqual(run.status, deploy.DeployStatus.SUCCEEDED)
            self.assertEqual(run.ticket, 50)
            self.assertIn("custom service deployed successfully", run.output)

    def test_fake_adapter_dry_run_executes_no_mutations(self) -> None:
        """Dry-run invokes execute with dry_run=True and records no mutations."""
        with tempfile.TemporaryDirectory() as d:
            toml = """
[apply]
enabled = true

[apply.targets.custom]
dir = "services/app"
adapter = "fake"
"""
            repo = make_repo(Path(d), toml)
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            cfg.factory.mkdir(parents=True, exist_ok=True)

            fake_adapter = deploy.FakeDeployAdapter(name="fake")
            deploy.register_adapter("fake", lambda: fake_adapter)

            ticket = {"ticket": 51, "pr": 16, "commit": "commit51"}

            with mock.patch.object(apply, "touches_target_dir", return_value=True), \
                 mock.patch.object(dispatch, "run"), \
                 mock.patch.object(dispatch, "pr_comment"):
                success = apply.apply_one(ticket, dry_run=True, target="custom", adapter=fake_adapter)
                self.assertTrue(success)

            # Only prepare, check, execute, cleanup called; verify skipped on dry-run
            self.assertEqual(fake_adapter.calls, ["prepare", "check", "execute", "cleanup"])

            # No runs recorded on dry-run
            state = deploy.get_target_state("custom", events_path=cfg.factory / "events.jsonl")
            self.assertEqual(len(state.runs), 0)

    def test_partial_apply_or_crash_requires_reconciliation(self) -> None:
        """A crashed or interrupted run halts subsequent deploys until reconciled."""
        with tempfile.TemporaryDirectory() as d:
            toml = """
[apply]
enabled = true

[apply.targets.collectors]
dir = "terraform/collectors"
adapter = "terraform"
"""
            repo = make_repo(Path(d), toml)
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            cfg.factory.mkdir(parents=True, exist_ok=True)

            events_file = cfg.factory / "events.jsonl"
            # Simulate an interrupted run (started mid-flight, process crashed/killed before completion)
            interrupted_run = deploy.DeployRun(
                run_id="deploy-collectors-c1a2b3c4-1",
                target="collectors",
                commit="c1a2b3c4",
                ticket=60,
                attempt=1,
                status=deploy.DeployStatus.RUNNING,
                started_at="2026-09-14T01:00:00Z",
                completed_at=None,
                pr=25,
                version=deploy.CONTRACT_VERSION,
            )
            deploy.record_deploy_run(interrupted_run, events_path=events_file)

            tstate = deploy.get_target_state("collectors", events_path=events_file)
            self.assertTrue(tstate.has_interrupted_run)
            self.assertEqual(len(tstate.interrupted_runs), 1)

            # Attempting factory apply must refuse execution because interrupted run requires reconciliation
            candidate_pr = {
                "pr": 26,
                "ticket": 61,
                "commit": "commit61",
                "head_commit": "commit61",
                "reviewDecision": "APPROVED",
                "latestReviews": [{"state": "APPROVED", "commit": {"oid": "commit61"}}],
            }
            with mock.patch.object(config, "load", return_value=cfg), \
                 mock.patch.object(dispatch, "run"), \
                 mock.patch.object(apply, "fetch_all_merged_prs", return_value=[candidate_pr]), \
                 mock.patch.object(apply, "apply_one") as mock_apply_one:
                ret = apply.main([])
                # Exit code must be 1 indicating reconciliation is required
                self.assertEqual(ret, 1)
                mock_apply_one.assert_not_called()

            # Now perform explicit operator reconciliation via CLI
            with mock.patch.object(config, "load", return_value=cfg):
                rec_ret = apply.main([
                    "--target", "collectors",
                    "--reconcile-run", "deploy-collectors-c1a2b3c4-1",
                    "--reconcile-status", "succeeded",
                    "--reconcile-note", "operator verified resources in state",
                ])
                self.assertEqual(rec_ret, 0)

            # Check target state after reconciliation: interrupted run is cleared
            reconciled_state = deploy.get_target_state("collectors", events_path=events_file)
            self.assertFalse(reconciled_state.has_interrupted_run)
            self.assertEqual(reconciled_state.latest_run.status, deploy.DeployStatus.SUCCEEDED)

    def test_notification_failure_never_reexecutes_terraform(self) -> None:
        """Durable persistence occurs before notifications; notification errors never re-execute."""
        with tempfile.TemporaryDirectory() as d:
            toml = '[apply]\nenabled = true\ndir = "terraform"\n'
            repo = make_repo(Path(d), toml)
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            cfg.factory.mkdir(parents=True, exist_ok=True)

            tf_call_count = 0

            class TrackedAdapter(deploy.DeployAdapter):
                def execute(self, ctx, dry_run=False):
                    nonlocal tf_call_count
                    tf_call_count += 1
                    return deploy.DeployExecutionResult(ok=True, output="Apply complete!")

            tracked_adapter = TrackedAdapter()
            ticket = {"ticket": 70, "pr": 30, "commit": "commit70"}

            # First run: GitHub notification fails with an unhandled network error
            def fail_notify(*args, **kwargs):
                cmd = args[0] if args else []
                if isinstance(cmd, list) and cmd[:2] == ["gh", "issue"]:
                    raise RuntimeError("GitHub API 500 Internal Server Error")
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            with mock.patch.object(apply, "touches_apply_dir", return_value=True), \
                 mock.patch.object(dispatch, "run", side_effect=fail_notify), \
                 mock.patch.object(dispatch, "pr_comment", side_effect=RuntimeError("PR comment error")):
                # Must not raise an exception because notification errors are safely handled
                success = apply.apply_one(ticket, dry_run=False, target="default", adapter=tracked_adapter)
                self.assertTrue(success)

            self.assertEqual(tf_call_count, 1)

            # Verify durable state was saved BEFORE notification failed
            events = (cfg.factory / "events.jsonl").read_text()
            self.assertIn("deploy_run", events)
            self.assertIn("commit70", events)
            self.assertIn(70, deploy.terminal_tickets("default", events_path=cfg.factory / "events.jsonl"))

            # Second pass: candidate is terminal, so apply_one is NEVER called again
            candidate_pr = {
                "pr": 30,
                "ticket": 70,
                "commit": "commit70",
                "head_commit": "commit70",
                "reviewDecision": "APPROVED",
                "latestReviews": [{"state": "APPROVED", "commit": {"oid": "commit70"}}],
            }
            with mock.patch.object(config, "load", return_value=cfg), \
                 mock.patch.object(dispatch, "run"), \
                 mock.patch.object(apply, "fetch_all_merged_prs", return_value=[candidate_pr]), \
                 mock.patch.object(apply, "touches_apply_dir", return_value=True):
                apply.main([])

            # Execution count MUST remain 1 -- no duplicate apply!
            self.assertEqual(tf_call_count, 1)

    def test_truthful_exit_codes(self) -> None:
        """Exit code is 0 on success/dry-run, and 1 on error/reconciliation required."""
        with tempfile.TemporaryDirectory() as d:
            toml = '[apply]\nenabled = true\ndir = "terraform"\n'
            repo = make_repo(Path(d), toml)
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            cfg.factory.mkdir(parents=True, exist_ok=True)

            # Case 1: Nothing to apply -> 0
            with mock.patch.object(config, "load", return_value=cfg), \
                 mock.patch.object(dispatch, "run"), \
                 mock.patch.object(apply, "fetch_all_merged_prs", return_value=[]):
                self.assertEqual(apply.main([]), 0)

            # Case 2: Candidate failed -> 1
            failing_pr = {
                "pr": 40,
                "ticket": 90,
                "commit": "c90",
                "head_commit": "c90",
                "reviewDecision": "APPROVED",
                "latestReviews": [{"state": "APPROVED", "commit": {"oid": "c90"}}],
            }
            with mock.patch.object(config, "load", return_value=cfg), \
                 mock.patch.object(dispatch, "run"), \
                 mock.patch.object(apply, "fetch_all_merged_prs", return_value=[failing_pr]), \
                 mock.patch.object(apply, "touches_apply_dir", return_value=True), \
                 mock.patch.object(apply, "apply_one", return_value=False):
                self.assertEqual(apply.main([]), 1)

            # Case 3: Dry run on candidate -> 0
            with mock.patch.object(config, "load", return_value=cfg), \
                 mock.patch.object(dispatch, "run"), \
                 mock.patch.object(apply, "fetch_all_merged_prs", return_value=[failing_pr]), \
                 mock.patch.object(apply, "touches_apply_dir", return_value=True), \
                 mock.patch.object(apply, "apply_one", return_value=True):
                self.assertEqual(apply.main(["--dry-run"]), 0)


class ReviewDefectsRegressionTest(unittest.TestCase):
    """Targeted regression tests for 8 defects identified in delivery phase 1 review."""

    def test_defect_1_missing_approval_evidence_blocks_execution(self) -> None:
        """[P1] Authorization requires complete review evidence, trusted human review, and exact head SHA."""
        # 1. Missing reviewDecision
        pr_missing_decision = {
            "pr": 1, "ticket": 10, "head_commit": "sha_1234567890",
            "latestReviews": [{"state": "APPROVED", "commit": {"oid": "sha_1234567890"}}],
        }
        ok, reason = deploy.verify_revision_authorization(pr_missing_decision)
        self.assertFalse(ok)
        self.assertIn("missing reviewDecision", reason)

        # 2. Missing latestReviews
        pr_missing_reviews = {
            "pr": 1, "ticket": 10, "head_commit": "sha_1234567890",
            "reviewDecision": "APPROVED",
        }
        ok, reason = deploy.verify_revision_authorization(pr_missing_reviews)
        self.assertFalse(ok)
        self.assertIn("missing review details", reason)

        # 3. Bot approval only
        pr_bot_review = {
            "pr": 1, "ticket": 10, "head_commit": "sha_1234567890",
            "reviewDecision": "APPROVED",
            "latestReviews": [
                {"state": "APPROVED", "authorAssociation": "BOT", "commit": {"oid": "sha_1234567890"}}
            ],
        }
        ok, reason = deploy.verify_revision_authorization(pr_bot_review)
        self.assertFalse(ok)
        self.assertIn("no trusted human APPROVED reviews found", reason)

        # 4. Prefix match (different full head SHA) must be rejected
        pr_prefix_mismatch = {
            "pr": 1, "ticket": 10, "head_commit": "sha_prefix_11111111",
            "reviewDecision": "APPROVED",
            "latestReviews": [
                {"state": "APPROVED", "author": {"login": "human"}, "authorAssociation": "MEMBER", "commit": {"oid": "sha_prefix_22222222"}}
            ],
        }
        ok, reason = deploy.verify_revision_authorization(pr_prefix_mismatch)
        self.assertFalse(ok)
        self.assertIn("stale review on unapproved revision", reason)

        # 5. Trusted human approval on exact full head SHA succeeds
        pr_valid = {
            "pr": 1, "ticket": 10, "head_commit": "sha_exact_full_head_1234567890",
            "reviewDecision": "APPROVED",
            "latestReviews": [
                {"state": "APPROVED", "author": {"login": "human"}, "authorAssociation": "MEMBER", "commit": {"oid": "sha_exact_full_head_1234567890"}}
            ],
        }
        ok, reason = deploy.verify_revision_authorization(pr_valid)
        self.assertTrue(ok)
        self.assertEqual(reason, "")

    def test_defect_2_named_target_events_do_not_mask_default_interrupted_runs(self) -> None:
        """[P1] Compatibility events with custom targets do not overwrite default.latest_run or mask interrupted runs."""
        with tempfile.TemporaryDirectory() as d:
            events_file = Path(d) / "events.jsonl"
            # 1. Default target has an interrupted RUNNING run
            default_running = deploy.DeployRun(
                run_id="deploy-default-11111111-1",
                target="default",
                commit="11111111",
                ticket=1,
                attempt=1,
                status=deploy.DeployStatus.RUNNING,
                started_at="2026-09-14T00:00:00Z",
            )
            deploy.record_deploy_run(default_running, events_path=events_file)

            # 2. Custom target 'collectors' succeeds and emits modern run + legacy applied row without target
            collectors_run = deploy.DeployRun(
                run_id="deploy-collectors-22222222-1",
                target="collectors",
                commit="22222222",
                ticket=2,
                attempt=1,
                status=deploy.DeployStatus.SUCCEEDED,
                started_at="2026-09-14T00:05:00Z",
            )
            deploy.record_deploy_run(collectors_run, events_path=events_file)

            # Compatibility row reusing collectors run_id but omitting target
            legacy_entry = {
                "event": "applied",
                "ticket": 2,
                "commit": "22222222",
                "ok": True,
                "run_id": "deploy-collectors-22222222-1",
            }
            with events_file.open("a") as f:
                f.write(json.dumps(legacy_entry) + "\n")

            states = deploy.replay_events(events_file)
            # Default target MUST still have interrupted run detected
            self.assertTrue(states["default"].has_interrupted_run)
            self.assertEqual(len(states["default"].interrupted_runs), 1)
            self.assertEqual(states["default"].interrupted_runs[0].run_id, "deploy-default-11111111-1")
            # Collectors target latest run is preserved
            self.assertEqual(states["collectors"].latest_run.status, deploy.DeployStatus.SUCCEEDED)

    def test_defect_3_failed_run_recovery_unblocks_repair_prs(self) -> None:
        """[P1] Acknowledged failures unblock sequential candidate selection for repair PRs while preserving audit history."""
        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d))
            events_file = Path(d) / "events.jsonl"

            # Ticket 11 failed
            failed_run = deploy.DeployRun(
                run_id="deploy-default-c11-1",
                target="default",
                commit="c11",
                ticket=11,
                attempt=1,
                status=deploy.DeployStatus.FAILED,
                started_at="2026-09-14T01:00:00Z",
            )
            deploy.record_deploy_run(failed_run, events_path=events_file)

            tstate = deploy.get_target_state("default", events_path=events_file)
            self.assertIn(11, tstate.failed_tickets)
            self.assertIn(11, tstate.unacknowledged_failed_tickets)

            repair_pr = {
                "pr": 2, "ticket": 12, "commit": "c12", "head_commit": "c12",
                "reviewDecision": "APPROVED",
                "latestReviews": [{"state": "APPROVED", "commit": {"oid": "c12"}}],
            }

            # Under sequential supersession, unacknowledged failure blocks selection
            cands, _ = deploy.select_candidates_for_target(
                "default", "terraform", [repair_pr], repo,
                events_path=events_file, touches_fn=lambda c: True, supersession="sequential",
            )
            self.assertEqual(cands, [])

            # Under supersession = "none", selection does not block
            cands_none, _ = deploy.select_candidates_for_target(
                "default", "terraform", [repair_pr], repo,
                events_path=events_file, touches_fn=lambda c: True, supersession="none",
            )
            self.assertEqual(len(cands_none), 1)

            # Explicitly acknowledge failure to authorize repair
            deploy.acknowledge_failure("default", 11, note="acknowledged to authorize fix PR 12", events_path=events_file)
            tstate_ack = deploy.get_target_state("default", events_path=events_file)
            # Failure is preserved in history
            self.assertIn(11, tstate_ack.failed_tickets)
            # But no longer in unacknowledged failed tickets
            self.assertNotIn(11, tstate_ack.unacknowledged_failed_tickets)

            # Repair PR is now selected under sequential mode
            cands_ack, _ = deploy.select_candidates_for_target(
                "default", "terraform", [repair_pr], repo,
                events_path=events_file, touches_fn=lambda c: True, supersession="sequential",
            )
            self.assertEqual(len(cands_ack), 1)
            self.assertEqual(cands_ack[0]["ticket"], 12)

    def test_defect_4_dry_run_is_strictly_side_effect_free(self) -> None:
        """[P1] Dry-run never records events, never posts comments, even on skipped, unauthorized, or prepare failure paths."""
        from unittest import mock
        from factory import apply, dispatch

        with tempfile.TemporaryDirectory() as d:
            toml = '[apply]\nenabled = true\ndir = "terraform"\n'
            repo = make_repo(Path(d), toml)
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            cfg.factory.mkdir(parents=True, exist_ok=True)
            events_file = cfg.factory / "events.jsonl"

            # Candidate that doesn't touch target
            pr_skip = {
                "pr": 1, "ticket": 10, "commit": "c10", "head_commit": "c10",
                "reviewDecision": "APPROVED",
                "latestReviews": [{"state": "APPROVED", "commit": {"oid": "c10"}}],
            }
            # Candidate that fails adapter check/prepare
            pr_fail = {
                "pr": 2, "ticket": 11, "commit": "c11", "head_commit": "c11",
                "reviewDecision": "APPROVED",
                "latestReviews": [{"state": "APPROVED", "commit": {"oid": "c11"}}],
            }

            fake_adapter = mock.Mock()
            fake_adapter.prepare.return_value = (False, "prepare failed in dry-run test")
            fake_adapter.cleanup = mock.Mock()

            pr_comment_mock = mock.Mock()
            run_mock = mock.Mock()

            with mock.patch.object(config, "load", return_value=cfg), \
                 mock.patch.object(dispatch, "run", run_mock), \
                 mock.patch.object(dispatch, "pr_comment", pr_comment_mock), \
                 mock.patch.object(apply, "fetch_all_merged_prs", return_value=[pr_skip, pr_fail]), \
                 mock.patch.object(apply, "touches_apply_dir", side_effect=lambda c: c == "c11"), \
                 mock.patch.object(deploy, "get_adapter", return_value=fake_adapter):
                apply.main(["--dry-run"])

            # 1. Zero events written to events.jsonl
            if events_file.exists():
                self.assertEqual(events_file.read_text().strip(), "")

            # 2. Zero issue or PR comments posted
            pr_comment_mock.assert_not_called()
            for call in run_mock.call_args_list:
                args = call[0][0]
                self.assertNotIn("comment", args)

    def test_defect_5_pagination_stops_at_raw_boundary_not_matching_count(self) -> None:
        """[P2] Pagination stops only when raw results are exhausted, not based on factory branch matches."""
        from unittest import mock
        from factory import apply, dispatch

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d))
            cfg = config.load(repo)
            apply.configure(cfg)

            # GraphQL responses:
            # Page 1: 2 PRs, none are agent/* (non-factory PRs), hasNextPage=True
            page1_response = {
                "data": {
                    "repository": {
                        "pullRequests": {
                            "pageInfo": {"hasNextPage": True, "endCursor": "cursor_page1"},
                            "nodes": [
                                {"number": 101, "headRefName": "dependabot/foo", "mergeCommit": {"oid": "m1"}},
                                {"number": 102, "headRefName": "feature/bar", "mergeCommit": {"oid": "m2"}},
                            ],
                        }
                    }
                }
            }
            # Page 2: 1 PR matching agent/55, hasNextPage=False
            page2_response = {
                "data": {
                    "repository": {
                        "pullRequests": {
                            "pageInfo": {"hasNextPage": False, "endCursor": "cursor_page2"},
                            "nodes": [
                                {
                                    "number": 103,
                                    "headRefName": "agent/55",
                                    "headRefOid": "head55",
                                    "mergeCommit": {"oid": "m55"},
                                    "reviewDecision": "APPROVED",
                                    "latestReviews": [{"state": "APPROVED", "commit": {"oid": "head55"}}],
                                }
                            ],
                        }
                    }
                }
            }

            responses = [page1_response, page2_response]
            with mock.patch.object(dispatch, "gh_json", side_effect=responses):
                prs = apply.fetch_all_merged_prs(page_size=2, max_pages=5)

            # Page 2 PR must be discovered despite page 1 having 0 matching factory PRs
            self.assertEqual(len(prs), 1)
            self.assertEqual(prs[0]["pr"], 103)
            self.assertEqual(prs[0]["ticket"], 55)

    def test_defect_6_approved_multi_commit_merges_not_flagged_unauthorized(self) -> None:
        """[P2] Multi-commit approved mainline merges cover their entire internal branch history."""
        from tests.test_factory import git

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d))
            (repo / "terraform").mkdir(exist_ok=True)
            (repo / "terraform" / "main.tf").write_text("v1")
            git(repo, "add", "terraform/main.tf")
            git(repo, "commit", "-q", "-m", "init")
            init_commit = git(repo, "rev-parse", "HEAD")

            # Create branch agent/20 with 2 commits
            git(repo, "checkout", "-b", "agent/20")
            (repo / "terraform" / "main.tf").write_text("v2")
            git(repo, "commit", "-q", "-am", "commit 1 of PR")
            c1 = git(repo, "rev-parse", "HEAD")

            (repo / "terraform" / "main.tf").write_text("v3")
            git(repo, "commit", "-q", "-am", "commit 2 of PR")
            c2 = git(repo, "rev-parse", "HEAD")

            # Merge to main with --no-ff
            git(repo, "checkout", "main")
            git(repo, "merge", "--no-ff", "agent/20", "-m", "Merge PR #20")
            merge_commit = git(repo, "rev-parse", "HEAD")

            # Allowlist only has merge commit and head commit (c2)
            authorized = {merge_commit, c2}

            # Internal commit c1 must NOT be flagged as unauthorized
            unauth = deploy.find_unauthorized_direct_merges("terraform", authorized, repo, since_commit=init_commit)
            self.assertEqual(unauth, [])

            # A real direct push to main without a PR MUST be detected
            (repo / "terraform" / "main.tf").write_text("v4 direct push")
            git(repo, "commit", "-q", "-am", "direct commit on main")
            direct_sha = git(repo, "rev-parse", "HEAD")

            unauth_direct = deploy.find_unauthorized_direct_merges("terraform", authorized, repo, since_commit=init_commit)
            self.assertIn(direct_sha, unauth_direct)

    def test_defect_7_backend_locks_serialize_across_distinct_checkouts(self) -> None:
        """[P2] Backend locks serialize across two independent checkouts using a host-shared lock namespace."""
        with tempfile.TemporaryDirectory() as d:
            shared_lock_dir = Path(d) / "shared_locks"
            checkout_a = Path(d) / "checkout_a" / ".factory"
            checkout_b = Path(d) / "checkout_b" / ".factory"
            checkout_a.mkdir(parents=True)
            checkout_b.mkdir(parents=True)

            with mock.patch.dict(os.environ, {"AGENT_FACTORY_LOCK_DIR": str(shared_lock_dir)}):
                # Checkout A acquires backend lock
                ok_a, fd_a = deploy.acquire_backend_lock(checkout_a, "shared_backend_key")
                self.assertTrue(ok_a)
                self.assertIsNotNone(fd_a)

                # Checkout B attempting to acquire the SAME backend lock must fail
                ok_b, fd_b = deploy.acquire_backend_lock(checkout_b, "shared_backend_key")
                self.assertFalse(ok_b)
                self.assertIsNone(fd_b)

                # After Checkout A releases, Checkout B succeeds
                deploy.release_lock(fd_a)
                ok_b2, fd_b2 = deploy.acquire_backend_lock(checkout_b, "shared_backend_key")
                self.assertTrue(ok_b2)
                deploy.release_lock(fd_b2)

    def test_followup_1_affirmative_reviewer_identity_and_permission_required(self) -> None:
        """[P1] Reviews without affirmative identity or without repository permission are rejected."""
        # 1. Identity-free review (matching commit but no author or authorAssociation)
        pr_identity_free = {
            "pr": 1, "ticket": 10, "head_commit": "sha_head_commit_1",
            "reviewDecision": "APPROVED",
            "latestReviews": [
                {"state": "APPROVED", "commit": {"oid": "sha_head_commit_1"}}
            ],
        }
        ok, reason = deploy.verify_revision_authorization(pr_identity_free)
        self.assertFalse(ok)
        self.assertIn("no trusted human APPROVED reviews found", reason)

        # 2. Reviewer with untrusted association (NONE)
        pr_untrusted_assoc = {
            "pr": 1, "ticket": 10, "head_commit": "sha_head_commit_1",
            "reviewDecision": "APPROVED",
            "latestReviews": [
                {
                    "state": "APPROVED",
                    "author": {"login": "stranger"},
                    "authorAssociation": "NONE",
                    "commit": {"oid": "sha_head_commit_1"},
                }
            ],
        }
        ok, reason = deploy.verify_revision_authorization(pr_untrusted_assoc)
        self.assertFalse(ok)
        self.assertIn("no trusted human APPROVED reviews found", reason)

        # 3. Reviewer with FIRST_TIME_CONTRIBUTOR association
        pr_contributor = {
            "pr": 1, "ticket": 10, "head_commit": "sha_head_commit_1",
            "reviewDecision": "APPROVED",
            "latestReviews": [
                {
                    "state": "APPROVED",
                    "author": {"login": "first_timer"},
                    "authorAssociation": "FIRST_TIME_CONTRIBUTOR",
                    "commit": {"oid": "sha_head_commit_1"},
                }
            ],
        }
        ok, reason = deploy.verify_revision_authorization(pr_contributor)
        self.assertFalse(ok)
        self.assertIn("no trusted human APPROVED reviews found", reason)

        # 4. Reviewer with MEMBER association passes
        pr_member = {
            "pr": 1, "ticket": 10, "head_commit": "sha_head_commit_1",
            "reviewDecision": "APPROVED",
            "latestReviews": [
                {
                    "state": "APPROVED",
                    "author": {"login": "team_member"},
                    "authorAssociation": "MEMBER",
                    "commit": {"oid": "sha_head_commit_1"},
                }
            ],
        }
        ok, reason = deploy.verify_revision_authorization(pr_member)
        self.assertTrue(ok)
        self.assertEqual(reason, "")

        # 5. Reviewer in explicit allowlist passes even if association is CONTRIBUTOR
        ok, reason = deploy.verify_revision_authorization(
            pr_contributor, trusted_reviewers={"first_timer"}
        )
        self.assertTrue(ok)
        self.assertEqual(reason, "")

    def test_followup_2_reconciliation_verifies_execution_ownership_and_locks(self) -> None:
        """[P1] Reconciliation cannot alter an actively executing run while locks are held."""
        from factory import apply, dispatch

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), '[apply]\nenabled = true\n')
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            cfg.factory.mkdir(parents=True, exist_ok=True)
            events_file = cfg.factory / "events.jsonl"

            # Create an active RUNNING run
            running_run = deploy.DeployRun(
                run_id="deploy-default-c1111111-1",
                target="default",
                commit="c1111111",
                ticket=50,
                attempt=1,
                status=deploy.DeployStatus.RUNNING,
                started_at="2026-09-14T00:00:00Z",
                version=deploy.CONTRACT_VERSION,
            )
            deploy.record_deploy_run(running_run, events_path=events_file)

            # 1. When apply.lock is held by an active apply process:
            a_ok, a_fd = deploy.acquire_apply_lock(cfg.factory)
            self.assertTrue(a_ok)
            try:
                with mock.patch.object(config, "load", return_value=cfg):
                    ret = apply.main([
                        "--reconcile-run", "deploy-default-c1111111-1",
                        "--reconcile-status", "succeeded",
                    ])
                    # Must fail with exit code 1 because apply.lock is held
                    self.assertEqual(ret, 1)

                # State must NOT have changed
                tstate = deploy.get_target_state("default", events_path=events_file)
                self.assertTrue(tstate.has_interrupted_run)
                self.assertEqual(tstate.runs[-1].status, deploy.DeployStatus.RUNNING)
            finally:
                deploy.release_lock(a_fd)

            # 2. When target lock is held:
            t_ok, t_fd = deploy.acquire_target_lock(cfg.factory, "default")
            self.assertTrue(t_ok)
            try:
                with mock.patch.object(config, "load", return_value=cfg):
                    ret = apply.main([
                        "--reconcile-run", "deploy-default-c1111111-1",
                        "--reconcile-status", "succeeded",
                    ])
                    # Must fail with exit code 1 because target lock is held
                    self.assertEqual(ret, 1)

                tstate = deploy.get_target_state("default", events_path=events_file)
                self.assertTrue(tstate.has_interrupted_run)
                self.assertEqual(tstate.runs[-1].status, deploy.DeployStatus.RUNNING)
            finally:
                deploy.release_lock(t_fd)

            # 3. When no locks are held: reconciliation succeeds
            with mock.patch.object(config, "load", return_value=cfg):
                ret = apply.main([
                    "--reconcile-run", "deploy-default-c1111111-1",
                    "--reconcile-status", "succeeded",
                    "--reconcile-note", "operator reconciled",
                ])
                self.assertEqual(ret, 0)

            tstate = deploy.get_target_state("default", events_path=events_file)
            self.assertFalse(tstate.has_interrupted_run)
            self.assertEqual(tstate.runs[-1].status, deploy.DeployStatus.SUCCEEDED)

    def test_followup_3_recovery_commands_strictly_honor_dry_run(self) -> None:
        """[P2] Recovery commands (--dry-run) perform zero mutations on events.jsonl."""
        from factory import apply, dispatch

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), '[apply]\nenabled = true\n')
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            cfg.factory.mkdir(parents=True, exist_ok=True)
            events_file = cfg.factory / "events.jsonl"

            # Create a RUNNING run
            running_run = deploy.DeployRun(
                run_id="deploy-default-c2222222-1",
                target="default",
                commit="c2222222",
                ticket=51,
                attempt=1,
                status=deploy.DeployStatus.RUNNING,
                started_at="2026-09-14T00:00:00Z",
                version=deploy.CONTRACT_VERSION,
            )
            deploy.record_deploy_run(running_run, events_path=events_file)

            # Create a FAILED run
            failed_run = deploy.DeployRun(
                run_id="deploy-default-c3333333-1",
                target="default",
                commit="c3333333",
                ticket=52,
                attempt=1,
                status=deploy.DeployStatus.FAILED,
                started_at="2026-09-14T00:00:00Z",
                completed_at="2026-09-14T00:01:00Z",
                version=deploy.CONTRACT_VERSION,
            )
            deploy.record_deploy_run(failed_run, events_path=events_file)
            size_before = events_file.stat().st_size

            # Dry-run reconciliation on RUNNING run
            with mock.patch.object(config, "load", return_value=cfg):
                ret = apply.main([
                    "--dry-run",
                    "--reconcile-run", "deploy-default-c2222222-1",
                    "--reconcile-status", "succeeded",
                ])
                self.assertEqual(ret, 0)
                self.assertEqual(events_file.stat().st_size, size_before)

            # Dry-run acknowledge failure on FAILED run
            with mock.patch.object(config, "load", return_value=cfg):
                ret = apply.main([
                    "--dry-run",
                    "--acknowledge-failure", "52",
                ])
                self.assertEqual(ret, 0)
                self.assertEqual(events_file.stat().st_size, size_before)

            # Dry-run acknowledge failure on RUNNING run fails validation
            with mock.patch.object(config, "load", return_value=cfg):
                ret = apply.main([
                    "--dry-run",
                    "--acknowledge-failure", "51",
                ])
                self.assertEqual(ret, 1)
                self.assertEqual(events_file.stat().st_size, size_before)

            # Dry-run acknowledge failure on nonexistent ticket fails validation
            with mock.patch.object(config, "load", return_value=cfg):
                ret = apply.main([
                    "--dry-run",
                    "--acknowledge-failure", "999",
                ])
                self.assertEqual(ret, 1)
                self.assertEqual(events_file.stat().st_size, size_before)

            # Dry-run with nonexistent run fails validation
            with mock.patch.object(config, "load", return_value=cfg):
                ret = apply.main([
                    "--dry-run",
                    "--reconcile-run", "nonexistent-run-id",
                ])
                self.assertEqual(ret, 1)
                self.assertEqual(events_file.stat().st_size, size_before)

    def test_followup_5_cannot_preauthorize_future_failures(self) -> None:
        """[P2] Acknowledgment cannot pre-authorize future failures for nonexistent or unfailed tickets."""
        from factory import apply, dispatch

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), '[apply]\nenabled = true\n')
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            cfg.factory.mkdir(parents=True, exist_ok=True)
            events_file = cfg.factory / "events.jsonl"

            # 1. Attempting to acknowledge nonexistent ticket 999 fails
            with mock.patch.object(config, "load", return_value=cfg):
                ret = apply.main(["--acknowledge-failure", "999"])
                self.assertEqual(ret, 1)

            # Zero events recorded
            tstate = deploy.get_target_state("default", events_path=events_file)
            self.assertEqual(len(tstate.acknowledged_failures), 0)

            # 2. Ticket 999 later runs and fails
            run_1 = deploy.DeployRun(
                run_id="deploy-default-c999a-1",
                target="default",
                commit="c999a",
                ticket=999,
                attempt=1,
                status=deploy.DeployStatus.FAILED,
                started_at="2026-09-14T01:00:00Z",
                completed_at="2026-09-14T01:01:00Z",
                version=deploy.CONTRACT_VERSION,
            )
            deploy.record_deploy_run(run_1, events_path=events_file)

            # Ticket 999 MUST be in unacknowledged_failed_tickets (it was not pre-authorized!)
            tstate = deploy.get_target_state("default", events_path=events_file)
            self.assertIn(999, tstate.unacknowledged_failed_tickets)

            # 3. Now acknowledge ticket 999 (or run_1.run_id)
            with mock.patch.object(config, "load", return_value=cfg):
                ret = apply.main(["--acknowledge-failure", "999"])
                self.assertEqual(ret, 0)

            # It is now acknowledged and bound to deploy-default-c999a-1
            tstate_ack = deploy.get_target_state("default", events_path=events_file)
            self.assertNotIn(999, tstate_ack.unacknowledged_failed_tickets)
            self.assertIn("deploy-default-c999a-1", tstate_ack.acknowledged_failures)

            # 4. Ticket 999 later runs again (attempt 2) and fails again
            run_2 = deploy.DeployRun(
                run_id="deploy-default-c999b-2",
                target="default",
                commit="c999b",
                ticket=999,
                attempt=2,
                status=deploy.DeployStatus.FAILED,
                started_at="2026-09-14T02:00:00Z",
                completed_at="2026-09-14T02:01:00Z",
                version=deploy.CONTRACT_VERSION,
            )
            deploy.record_deploy_run(run_2, events_path=events_file)

            # Ticket 999 MUST be in unacknowledged_failed_tickets! Acknowledging attempt 1 does not pre-authorize attempt 2
            tstate_new = deploy.get_target_state("default", events_path=events_file)
            self.assertIn(999, tstate_new.unacknowledged_failed_tickets)

    def test_followup_4_failed_execution_does_not_create_synthetic_duplicate_attempt(self) -> None:
        """[P2] Failed adapter execution attaches escalation to the existing run without creating attempt N+1."""
        from factory import apply, dispatch

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), '[apply]\nenabled = true\n')
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            cfg.factory.mkdir(parents=True, exist_ok=True)
            events_file = cfg.factory / "events.jsonl"

            fake_adapter = mock.Mock()
            fake_adapter.prepare.return_value = (True, "")
            fake_adapter.check.return_value = (True, "")
            fake_adapter.execute.return_value = deploy.DeployExecutionResult(
                ok=False,
                error="execution failed in test",
                output="error trace",
            )
            fake_adapter.cleanup = mock.Mock()

            ticket = {"ticket": 60, "pr": 15, "commit": "c6060606"}

            with mock.patch.object(apply, "fresh_checkout", return_value=Path(d)), \
                 mock.patch.object(apply, "touches_apply_dir", return_value=True), \
                 mock.patch.object(dispatch, "run"), \
                 mock.patch.object(dispatch, "pr_comment"):
                success = apply.apply_one(ticket, dry_run=False, adapter=fake_adapter)
                self.assertFalse(success)

            tstate = deploy.get_target_state("default", events_path=events_file)
            # Must have EXACTLY 1 run recorded, not a duplicate attempt 2!
            self.assertEqual(len(tstate.runs), 1)
            self.assertEqual(tstate.runs[0].attempt, 1)
            self.assertEqual(tstate.runs[0].status, deploy.DeployStatus.FAILED)
            self.assertIn(60, tstate.unacknowledged_failed_tickets)

            # Acknowledging the run unblocks the target completely
            deploy.acknowledge_failure("default", tstate.runs[0].run_id, events_path=events_file)
            tstate_ack = deploy.get_target_state("default", events_path=events_file)
            self.assertEqual(len(tstate_ack.unacknowledged_failed_tickets), 0)

    def test_followup_6_interrupted_tail_does_not_swallow_the_next_deploy_write(self) -> None:
        """[P1] An events.jsonl left with an unterminated (interrupted-append) trailing
        line must not corrupt the *next* write. deploy.py's writers must go through
        `lifecycle.append`, which detects the missing newline and isolates the broken
        tail with a null-byte sentinel before writing the new row on its own line --
        a raw `open('a').write(...)` instead concatenates onto the broken bytes and
        makes both the old partial line and the new row unparseable."""
        from factory import lifecycle

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), '[apply]\nenabled = true\n')
            cfg = config.load(repo)
            cfg.factory.mkdir(parents=True, exist_ok=True)
            events_file = cfg.factory / "events.jsonl"
            # Simulate a process killed mid-write: a syntactically complete JSON
            # object with no trailing newline.
            events_file.write_text('{"event": "claimed", "ticket": 70, "at": "2026-09-20T00:00:00Z"}')

            run = deploy.DeployRun(
                run_id="deploy-default-c7070707-1",
                target="default",
                commit="c7070707",
                ticket=70,
                attempt=1,
                status=deploy.DeployStatus.FAILED,
                started_at="2026-09-20T00:01:00Z",
                completed_at="2026-09-20T00:02:00Z",
                version=deploy.CONTRACT_VERSION,
            )
            deploy.record_deploy_run(run, events_path=events_file)

            rows = lifecycle.read_events(events_file)
            self.assertEqual(len(rows), 1, rows)
            self.assertEqual(rows[0]["event"], "deploy_run")
            self.assertEqual(rows[0]["run_id"], "deploy-default-c7070707-1")

            tstate = deploy.get_target_state("default", events_path=events_file)
            self.assertEqual(len(tstate.runs), 1)
            self.assertIn(70, tstate.unacknowledged_failed_tickets)

            # A second interrupted-tail scenario against acknowledge_failure's writer.
            events_file.write_bytes(events_file.read_bytes() + b'{"broken tail, no newline')
            deploy.acknowledge_failure("default", run.run_id, events_path=events_file)
            tstate2 = deploy.get_target_state("default", events_path=events_file)
            self.assertIn(run.run_id, tstate2.acknowledged_failures)
            self.assertNotIn(70, tstate2.unacknowledged_failed_tickets)


if __name__ == "__main__":
    unittest.main()


FAKE_TERRAFORM = """\
import os, signal, sys, time
# Behave like a Go binary: a write to a broken stdout pipe kills the process.
signal.signal(signal.SIGPIPE, signal.SIG_DFL)
mode = os.environ.get("FAKE_TF_MODE", "normal")
if mode == "graceful":
    def stop(*_):
        print("Interrupt received. Gracefully shutting down; releasing state lock.", flush=True)
        sys.exit(1)
    signal.signal(signal.SIGINT, stop)
elif mode == "stubborn":
    signal.signal(signal.SIGINT, signal.SIG_IGN)
with open(os.environ["FAKE_TF_ARGV"], "w") as f:
    f.write(" ".join(sys.argv[1:]))
sys.stdout.buffer.write(b"\\xff\\xfe non-utf8 provider bytes\\n")
for i in range(int(os.environ.get("FAKE_TF_TICKS", "10"))):
    print(f"Still creating... [{i}]", flush=True)
    time.sleep(0.1)
if os.environ.get("FAKE_TF_MARKER"):
    open(os.environ["FAKE_TF_MARKER"], "w").write("state written")
print("Apply complete! Resources: 1 added, 0 changed, 0 destroyed.", flush=True)
"""


class TerraformProcessIsolationTest(unittest.TestCase):
    """`terraform apply` must outlive an abrupt Factory exit and stop gracefully on timeout."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        fake = bin_dir / "terraform"
        fake.write_text("#!" + sys.executable + "\n" + FAKE_TERRAFORM)
        fake.chmod(0o755)
        self.marker = self.root / "state-written"
        self.argv_file = self.root / "argv"
        self.env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "FAKE_TF_ARGV": str(self.argv_file),
                    "FAKE_TF_MARKER": str(self.marker)}

    def ctx(self, **env) -> deploy.DeployContext:
        ctx = deploy.DeployContext(
            target=config.DeployTarget(name="default", dir="."),
            ticket={"ticket": 90, "pr": 91, "commit": "c90"},
            root=self.root, factory_dir=self.root / ".factory",
            worktree=self.root, planfile=self.root / "plan", env={**self.env, **env})
        ctx.planfile.touch()
        return ctx

    def logs(self) -> list[Path]:
        return sorted((self.root / ".factory" / "logs").glob("terraform-apply-default-90-*.log"))

    def wait_for(self, path: Path, seconds: float = 15.0) -> bool:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if path.exists():
                return True
            time.sleep(0.05)
        return path.exists()

    def test_success_uses_no_color_and_keeps_a_private_log(self) -> None:
        res = deploy.TerraformDeployAdapter(timeout_sec=30).execute(self.ctx(FAKE_TF_TICKS="2"))
        self.assertTrue(res.ok, res.output)
        self.assertIn("-no-color", self.argv_file.read_text().split())
        self.assertIn("Apply complete!", res.output)
        self.assertIn("non-utf8 provider bytes", res.output)  # undecodable bytes replaced, no exception
        [log] = self.logs()
        self.assertEqual(log.stat().st_mode & 0o777, 0o600)
        self.assertIn(b"Apply complete!", log.read_bytes())

    def test_apply_survives_factory_being_killed(self) -> None:
        """Regression for the live post-migration test C: a SIGKILLed Factory
        previously killed terraform through its stdout pipe, leaving a partial
        apply and a held state lock."""
        script = (
            "import sys; from pathlib import Path\n"
            "sys.path.insert(0, %r)\n"
            "from factory import config, deploy\n"
            "ctx = deploy.DeployContext(target=config.DeployTarget(name='default', dir='.'),\n"
            "    ticket={'ticket': 90, 'pr': 91, 'commit': 'c90'}, root=Path(%r),\n"
            "    factory_dir=Path(%r), worktree=Path(%r), planfile=Path(%r), env=%r)\n"
            "deploy.TerraformDeployAdapter(timeout_sec=60).execute(ctx)\n"
        ) % (str(Path(deploy.__file__).resolve().parents[1]), str(self.root), str(self.root / ".factory"),
             str(self.root), str(self.root / "plan"), {**self.env, "FAKE_TF_TICKS": "15"})
        (self.root / "plan").touch()
        factory_proc = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: factory_proc.poll() is None and factory_proc.kill())
        self.assertTrue(self.wait_for(self.argv_file), "fake terraform never started")
        time.sleep(0.3)
        factory_proc.kill()
        factory_proc.wait()
        self.assertTrue(self.wait_for(self.marker), "terraform died with Factory")
        [log] = self.logs()
        deadline = time.monotonic() + 5
        while b"Apply complete!" not in log.read_bytes() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertIn(b"Apply complete!", log.read_bytes())

    def test_pipe_output_reproduces_the_original_failure(self) -> None:
        """Negative control: with stdout on a pipe whose reader has gone, the
        Go-like process dies before writing state."""
        env = {**self.env, "FAKE_TF_TICKS": "15"}
        proc = subprocess.Popen(["terraform", "apply"], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertTrue(self.wait_for(self.argv_file))
        proc.stdout.close()  # the reader (Factory) is gone
        proc.wait(timeout=15)
        self.assertEqual(proc.returncode, -signal.SIGPIPE)
        self.assertFalse(self.marker.exists())

    def test_timeout_interrupts_gracefully_before_killing(self) -> None:
        with mock.patch.object(deploy, "TERRAFORM_INTERRUPT_GRACE_SEC", 10):
            res = deploy.TerraformDeployAdapter(timeout_sec=1).execute(self.ctx(FAKE_TF_MODE="graceful", FAKE_TF_TICKS="100"))
        self.assertFalse(res.ok)
        self.assertIn("timed out after 1s", res.error)
        self.assertIn("releasing state lock", res.output)
        self.assertFalse(self.marker.exists())

    def test_timeout_escalates_to_kill_when_interrupt_is_ignored(self) -> None:
        with mock.patch.object(deploy, "TERRAFORM_INTERRUPT_GRACE_SEC", 1):
            t0 = time.monotonic()
            res = deploy.TerraformDeployAdapter(timeout_sec=1).execute(self.ctx(FAKE_TF_MODE="stubborn", FAKE_TF_TICKS="100"))
        self.assertFalse(res.ok)
        self.assertIn("timed out after 1s", res.error)
        self.assertLess(time.monotonic() - t0, 8)
        self.assertFalse(self.marker.exists())
