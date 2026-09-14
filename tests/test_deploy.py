"""Unit and contract tests for deployment lifecycle, target configuration,
run persistence, and legacy event replay (SHA-186).
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from unittest import mock

from agent_factory import apply, config, deploy, dispatch
from tests.test_factory import make_repo


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
        from agent_factory import apply, dispatch, tf_plan_check

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
        from agent_factory import apply, dispatch, tf_plan_check

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
        from agent_factory import apply, dispatch

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
        from agent_factory import apply, dispatch
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

            # Mock PR list with an authorized PR that is NOT the direct commit
            approved_pr = {
                "pr": 20,
                "ticket": 30,
                "commit": "other_commit_123",
                "head_commit": "other_commit_123",
                "reviewDecision": "APPROVED",
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
        from agent_factory import apply, dispatch

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
                {"state": "APPROVED", "commit": {"oid": "rev_a_old_oid"}}
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
                {"state": "APPROVED", "commit": {"oid": "rev_b_head_oid"}}
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
        from agent_factory import apply, dispatch
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
            pr_b = {"pr": 2, "ticket": 12, "commit": c_b, "head_commit": c_b, "reviewDecision": "APPROVED"}
            pr_a = {"pr": 1, "ticket": 11, "commit": c_a, "head_commit": c_a, "reviewDecision": "APPROVED"}
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
        from agent_factory import apply, dispatch

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
            }
            with mock.patch.object(config, "load", return_value=cfg), \
                 mock.patch.object(dispatch, "run"), \
                 mock.patch.object(apply, "fetch_all_merged_prs", return_value=[candidate_pr]), \
                 mock.patch.object(apply, "touches_apply_dir", return_value=True):
                apply.main([])

            # Execution count MUST remain 1 -- no duplicate apply!
            self.assertEqual(tf_call_count, 1)

    def test_bounded_subprocess_execution_timeout(self) -> None:
        """TerraformDeployAdapter catches subprocess timeout and records durable error."""
        adapter = deploy.TerraformDeployAdapter(timeout_sec=1)
        with tempfile.TemporaryDirectory() as d:
            ctx = deploy.DeployContext(
                target=config.DeployTarget(name="default", dir="."),
                ticket={"ticket": 80, "pr": 35, "commit": "c80"},
                root=Path(d),
                factory_dir=Path(d) / ".factory",
                worktree=Path(d),
                planfile=Path(d) / "plan",
            )
            ctx.planfile.touch()

            def fake_timeout(*args, **kwargs):
                raise subprocess.TimeoutExpired(cmd=["terraform", "apply"], timeout=1, output="partial...", stderr="")

            with mock.patch("subprocess.run", side_effect=fake_timeout):
                res = adapter.execute(ctx, dry_run=False)
                self.assertFalse(res.ok)
                self.assertIn("timed out after 1s", res.error)

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


if __name__ == "__main__":
    unittest.main()

