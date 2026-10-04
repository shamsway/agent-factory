"""Deployment roots cannot reach legacy execution or free-form publication."""
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from factory import config, deploy, dispatch, incidents, investigation_routing
from tests.test_factory import make_repo


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repo = make_repo(Path(self.temp.name))
        dispatch.configure(config.load(self.repo))
        self.factory = dispatch.FACTORY.resolve()
        self.run = deploy.DeployRun("deploy-default-01234567-1", "default", "01234567" * 5,
                                   9, 1, deploy.DeployStatus.FAILED, "2026-10-03T00:00:00+00:00")
        self.root = incidents.enqueue(self.factory, dispatch.REPO, self.run)
        path = self.factory / "incidents" / (self.root + ".json")
        row = incidents.read(path)
        row.update(issue=11, status="delivered", uncertain=False)
        incidents.write(path, row)
        self.issue = {"number": 11, "title": "incident", "body": "", "labels": [{"name": config.LABEL_AGENT}]}

    def tearDown(self):
        self.temp.cleanup()

    def test_local_root_is_blocked_with_removed_marker_label_and_force(self):
        for dry_run in (True, False):
            with mock.patch.object(dispatch, "run_worker") as worker, mock.patch.object(dispatch, "ensure_worktree") as worktree:
                dispatch.process_ticket(self.issue, 1, dry_run, forced=True)
            worker.assert_not_called()
            worktree.assert_not_called()

    def test_marker_without_local_record_blocks_and_never_reads_handoff(self):
        issue = {**self.issue, "number": 12, "body": incidents.marker(self.root)}
        self.assertIsNotNone(investigation_routing.blocked(self.factory, issue))
        with mock.patch.object(dispatch, "gh_json", return_value={"body": issue["body"]}), mock.patch.object(dispatch, "run") as public:
            dispatch.finish_investigation(12, self.factory / "missing-worktree", None)
        public.assert_not_called()

    def test_legacy_lane_blocked_for_any_ticket_with_private_incident_store(self):
        issue = {**self.issue, "number": 12, "labels": [{"name": config.LABEL_INVESTIGATE}]}
        with mock.patch.object(dispatch, "run_worker") as worker:
            dispatch.process_ticket(issue, 1, True)
        worker.assert_not_called()
        self.assertIsNone(investigation_routing.blocked(self.factory, {**issue, "number": 13}))

    def test_unknown_or_symlink_routing_fails_closed(self):
        store = self.factory / "incidents"
        (store / "broken.json").write_text("{}")
        self.assertEqual(investigation_routing.blocked(self.factory, {**self.issue, "number": 12}), "incident_routing_unavailable")
        real = store.with_name("incidents-real")
        store.rename(real)
        store.symlink_to(real, target_is_directory=True)
        self.assertIsNotNone(investigation_routing.blocked(self.factory, {**self.issue, "number": 12}))

    def test_free_form_publisher_refuses_local_root_even_when_marker_removed(self):
        with mock.patch.object(dispatch, "gh_json", return_value={"body": ""}), mock.patch.object(dispatch, "run") as public:
            dispatch.finish_investigation(11, self.factory / "missing-worktree", None)
        public.assert_not_called()

    def test_publisher_lookup_failure_does_not_post(self):
        with mock.patch.object(dispatch, "gh_json", side_effect=RuntimeError("private error")), mock.patch.object(dispatch, "run") as public:
            dispatch.finish_investigation(12, self.factory / "missing-worktree", None)
        public.assert_not_called()

    def test_fresh_marker_cannot_bypass_with_stale_frontier_and_forced_ticket(self):
        # No local incident store, so only the fresh GitHub body exposes identity.
        import shutil
        shutil.rmtree(self.factory / "incidents")
        fresh = {"number": 12, "state": "OPEN", "body": incidents.marker(self.root),
                 "title": "incident", "assignees": [], "labels": [{"name": config.LABEL_AGENT}]}
        with mock.patch.object(dispatch, "gh_json", return_value=fresh), mock.patch.object(dispatch, "run_worker") as worker, mock.patch.object(dispatch, "ensure_worktree") as worktree:
            dispatch.process_ticket({**self.issue, "number": 12}, 1, False, forced=True)
        worker.assert_not_called()
        worktree.assert_not_called()


if __name__ == "__main__":
    unittest.main()
