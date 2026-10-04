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
        self.handoff_patch = mock.patch.object(investigation_routing, "handoff", return_value=False)
        self.handoff_mock = self.handoff_patch.start()
        self.addCleanup(self.handoff_patch.stop)
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

    def test_nonincident_investigation_allowed_with_private_store(self):
        issue = {**self.issue, "number": 12, "labels": [{"name": config.LABEL_INVESTIGATE}]}
        self.assertIsNone(investigation_routing.blocked(self.factory, issue, legacy_investigation=True))
        with mock.patch.object(dispatch, "initiative_kind", return_value=False), mock.patch.object(dispatch, "log") as log:
            dispatch.process_ticket(issue, 1, True)
        self.assertIn("run investigation worker", str(log.call_args_list))

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

    def test_inaccessible_routing_is_not_mistaken_for_absent_store(self):
        with mock.patch.object(Path, "lstat", side_effect=PermissionError("private path")):
            self.assertEqual(investigation_routing.blocked(self.factory, self.issue), "incident_routing_unavailable")

    def test_handoff_once_and_restart_then_no_legacy_findings(self):
        self.handoff_patch.stop()
        class Remote:
            def __init__(self):
                self.comments = []
                self.labels = [{"name": config.LABEL_INVESTIGATE}, {"name": "other"}]
                self.posts = self.edits = 0
                self.lost = False
            def api(remote, endpoint, payload=None, method="GET"):
                if method == "POST":
                    remote.posts += 1
                    remote.comments.append(payload)
                    if remote.lost:
                        remote.lost = False
                        raise TimeoutError()
                    return {"id": 123}
                if method == "PATCH":
                    remote.edits += 1
                    remote.labels = [{"name": x} for x in payload["labels"]]
                    return {}
                if "/comments?" in endpoint:
                    return remote.comments
                return {"labels": remote.labels}
        remote = Remote()
        with mock.patch.object(incidents, "GitHub", return_value=remote):
            for _ in range(3):
                dispatch.process_ticket(self.issue, 1, False, forced=True)
            self.assertEqual(remote.posts, 1)
            self.assertEqual(remote.edits, 1)
            self.assertIn({"name": config.LABEL_HUMAN}, remote.labels)
            self.assertNotIn({"name": config.LABEL_INVESTIGATE}, remote.labels)
            self.assertIn({"name": "other"}, remote.labels)
            events = [__import__("json").loads(x) for x in dispatch.EVENTS.read_text().splitlines()]
            self.assertEqual(sum(x.get("event") == "investigation-route-refused" for x in events), 1)
        # Lost response is adopted after restart, never a second comment.
        (self.factory / "routing-handoffs" / "11.json").unlink()
        remote.comments = []
        remote.posts = remote.edits = 0
        remote.lost = True
        self.assertTrue(investigation_routing.handoff(dispatch.cfg, 11, remote=remote))
        self.assertFalse(investigation_routing.handoff(dispatch.cfg, 11, remote=remote))
        self.assertEqual(remote.posts, 1)
        self.assertEqual(remote.edits, 1)

    def test_uncertain_missing_comment_never_reposted(self):
        self.handoff_patch.stop()
        class Remote:
            posts = 0
            def api(remote, endpoint, payload=None, method="GET"):
                if method == "POST":
                    remote.posts += 1
                    raise TimeoutError()
                if method == "PATCH":
                    return {}
                if "/comments?" in endpoint:
                    return []
                return {"labels": []}
        remote = Remote()
        self.assertTrue(investigation_routing.handoff(dispatch.cfg, 11, remote=remote))
        self.assertFalse(investigation_routing.handoff(dispatch.cfg, 11, remote=remote))
        self.assertEqual(remote.posts, 1)

    def test_inflight_nonincident_findings_survive_store_creation(self):
        wt = self.factory / "wt-12"
        (wt / ".factory").mkdir(parents=True)
        (wt / ".factory" / "handoff-12.md").write_text("ordinary software findings")
        with mock.patch.object(dispatch, "gh_json", return_value={"body": ""}), mock.patch.object(dispatch, "run") as public:
            dispatch.finish_investigation(12, wt, None)
        self.assertTrue(any("ordinary software findings" in str(call) for call in public.call_args_list))

    def test_label_failure_retry_adopts_comment_without_duplicate(self):
        self.handoff_patch.stop()
        class Remote:
            def __init__(remote):
                remote.comments = []
                remote.posts = remote.edits = 0
            def api(remote, endpoint, payload=None, method="GET"):
                if method == "POST":
                    remote.posts += 1
                    remote.comments.append(payload)
                    return {"id": 1}
                if method == "PATCH":
                    remote.edits += 1
                    if remote.edits == 1:
                        raise RuntimeError("lost label response")
                    return {}
                if "/comments?" in endpoint:
                    return remote.comments
                return {"labels": []}
        remote = Remote()
        with self.assertRaises(RuntimeError):
            investigation_routing.handoff(dispatch.cfg, 11, remote=remote)
        self.assertTrue(investigation_routing.handoff(dispatch.cfg, 11, remote=remote))
        self.assertEqual(remote.posts, 1)
        self.assertEqual(remote.edits, 2)


if __name__ == "__main__":
    unittest.main()
