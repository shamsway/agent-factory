"""Durable incident/outbox and GitHub delivery contracts; no live API calls."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

from factory import config, deploy, incidents
from tests.test_factory import make_repo


class Crash(BaseException):
    """Simulate process death, outside delivery's Exception handler."""


class MemoryGitHub(incidents.GitHub):
    """Use the real find/create/update logic against an in-memory REST service."""

    def __init__(self):
        super().__init__(SimpleNamespace(repo="acme/widgets"))
        self.issues = []
        self.calls = []
        self.before_create = None
        self.after_create = None
        self.lookup_error = None
        self.update_error = None

    def api(self, endpoint, payload=None, method="GET"):
        self.calls.append((method, endpoint, copy.deepcopy(payload)))
        if method == "GET":
            if self.lookup_error:
                raise self.lookup_error
            page = int(re.search(r"page=(\d+)$", endpoint)[1])
            return copy.deepcopy(self.issues[(page - 1) * 100:page * 100])
        if method == "POST":
            if self.before_create:
                self.before_create()
            issue = {"number": len(self.issues) + 1, "body": payload["body"], "state": "open",
                     "labels": [{"name": label} for label in payload["labels"]]}
            self.issues.append(issue)
            if self.after_create:
                self.after_create()
            return copy.deepcopy(issue)
        if method == "PATCH":
            if self.update_error:
                raise self.update_error
            number = int(endpoint.rsplit("/", 1)[1])
            issue = next(issue for issue in self.issues if issue["number"] == number)
            for key, value in payload.items():
                issue[key] = ([{"name": label} for label in value] if key == "labels" else value)
            return copy.deepcopy(issue)
        raise AssertionError(method)

    @property
    def creates(self):
        return sum(method == "POST" for method, _, _ in self.calls)


def failed(ticket=42, attempt=1, target="default"):
    return deploy.DeployRun(
        run_id=f"deploy-{target}-abcdef12-{attempt}", target=target, commit="abcdef123456",
        ticket=ticket, pr=55, attempt=attempt, status=deploy.DeployStatus.FAILED,
        started_at="2026-10-03T12:00:00Z", completed_at="2026-10-03T12:01:00Z",
        error="PRIVATE RAW ERROR MUST NOT ENTER OUTBOX", output="RAW PLAN MUST NOT ENTER OUTBOX",
    )


class IncidentTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.factory = Path(self.temp.name) / ".factory"
        self.client = MemoryGitHub()
        self.run = failed()
        self.id = incidents.enqueue(self.factory, self.client.repo, self.run)

    def row(self):
        return incidents.read(self.factory / "incidents" / (self.id + ".json"))

    def deliver(self):
        return incidents.deliver(self.factory, self.client)

    def test_duplicate_replay_creates_one_incident_and_preserves_private_boundary(self):
        self.assertEqual(incidents.enqueue(self.factory, self.client.repo, self.run), self.id)
        self.deliver()
        self.deliver()
        self.assertEqual(self.client.creates, 1)
        self.assertEqual(len(self.row()["runs"]), 1)
        text = json.dumps(self.row()) + self.client.issues[0]["body"]
        self.assertNotIn("PRIVATE RAW ERROR", text)
        self.assertNotIn("RAW PLAN", text)
        self.assertIn("artifacts/default/", text)
        path = self.factory / "incidents" / (self.id + ".json")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.client.issues[0]["labels"], [{"name": config.LABEL_INVESTIGATE}])

    def test_concurrent_delivery_cannot_create_twice(self):
        entered, release = threading.Event(), threading.Event()
        failures = []

        def block():
            entered.set()
            if not release.wait(5):
                raise AssertionError("release timeout")

        def first():
            try:
                self.deliver()
            except BaseException as exc:
                failures.append(exc)

        self.client.before_create = block
        thread = threading.Thread(target=first)
        thread.start()
        try:
            self.assertTrue(entered.wait(5))
            with self.assertRaises(BlockingIOError):
                self.deliver()
            with self.assertRaises(BlockingIOError):
                incidents.enqueue(self.factory, self.client.repo, self.run)
        finally:
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.deliver()
        self.assertEqual(self.client.creates, 1)

    def test_crash_before_create_persists_uncertainty_and_never_recreates(self):
        def crash():
            self.assertTrue(self.row()["uncertain"])
            raise Crash()

        self.client.before_create = crash
        with self.assertRaises(Crash):
            self.deliver()
        self.client.before_create = None
        self.deliver()
        self.assertEqual(self.client.creates, 1)
        self.assertEqual(self.row()["status"], "uncertain")
        with self.assertRaises(incidents.UncertainCreation):
            incidents.recover(self.factory, self.id, self.client)
        incidents.recover(self.factory, self.id, self.client, confirm_not_created=True)
        self.deliver()
        self.assertEqual(self.client.creates, 2)
        self.assertEqual(self.row()["status"], "delivered")

    def test_crash_after_remote_create_is_adopted_on_restart(self):
        self.client.after_create = lambda: (_ for _ in ()).throw(Crash())
        with self.assertRaises(Crash):
            self.deliver()
        self.assertTrue(self.row()["uncertain"])
        self.assertEqual(len(self.client.issues), 1)
        self.client.after_create = None
        self.deliver()
        self.assertEqual(self.client.creates, 1)
        self.assertEqual(self.row()["issue"], 1)
        self.assertEqual(self.row()["status"], "delivered")

    def test_lost_response_is_reconciled_not_recreated(self):
        self.client.after_create = lambda: (_ for _ in ()).throw(TimeoutError("SECRET PROVIDER OUTPUT"))
        self.deliver()
        self.assertTrue(self.row()["uncertain"])
        self.assertEqual(self.row()["last_error"], "TimeoutError")
        self.client.after_create = None
        self.deliver()
        self.assertEqual(self.client.creates, 1)
        self.assertEqual(self.row()["status"], "delivered")
        self.assertNotIn("SECRET PROVIDER OUTPUT", json.dumps(self.row()))

    def test_definite_permanent_refusals_are_not_uncertain(self):
        for status in (403, 422):
            with self.subTest(status=status):
                other = failed(ticket=status, target=f"target-{status}")
                rid = incidents.enqueue(self.factory, self.client.repo, other)
                self.client.before_create = lambda: (_ for _ in ()).throw(incidents.RequestRefused(status))
                incidents.deliver(self.factory, self.client, only=rid)
                row = incidents.read(self.factory / "incidents" / (rid + ".json"))
                self.assertFalse(row["uncertain"])
                self.assertEqual(row["status"], "failed")
                self.assertEqual(row["last_error"], f"HTTP{status}")
                self.client.before_create = None
                incidents.recover(self.factory, rid, self.client)
                incidents.deliver(self.factory, self.client, only=rid)
                self.assertEqual(incidents.read(self.factory / "incidents" / (rid + ".json"))["status"], "delivered")

    def test_rate_limits_exhaust_side_effect_budget_and_safe_operator_retry(self):
        self.client.before_create = lambda: (_ for _ in ()).throw(incidents.RequestRefused(429))
        for _ in range(incidents.MAX_ATTEMPTS + 1):
            self.deliver()
        self.assertEqual(self.client.creates, incidents.MAX_ATTEMPTS)
        self.assertEqual(self.row()["status"], "failed")
        self.assertFalse(self.row()["uncertain"])
        self.client.before_create = None
        incidents.recover(self.factory, self.id, self.client)
        self.deliver()
        self.assertEqual(self.row()["status"], "delivered")
        self.assertEqual(self.row()["operator_retries"], 1)

    def test_lookup_outage_does_not_consume_create_budget(self):
        self.client.lookup_error = TimeoutError("RAW API DETAIL")
        for _ in range(5):
            self.deliver()
        self.assertEqual(self.row()["attempts"], 0)
        self.assertEqual(self.row()["lookup_failures"], 5)
        self.assertEqual(self.row()["status"], "pending")
        self.client.lookup_error = None
        self.deliver()
        self.assertEqual(self.client.creates, 1)

    def test_closed_incident_is_reopened_and_relabelled_for_repeat_failure(self):
        self.deliver()
        issue = self.client.issues[0]
        issue.update(state="closed", labels=[{"name": "custom"}, {"name": config.LABEL_HUMAN}])
        issue["body"] += "\nUser-owned notes."
        incidents.enqueue(self.factory, self.client.repo, failed(attempt=2))
        self.deliver()
        self.assertEqual(self.client.creates, 1)
        self.assertEqual(issue["state"], "open")
        self.assertEqual(issue["labels"], [{"name": "custom"}, {"name": config.LABEL_INVESTIGATE}])
        self.assertIn("User-owned notes.", issue["body"])
        self.assertIn("deploy-default-abcdef12-2", issue["body"])

    def test_update_failure_is_idempotently_retried_and_budgeted(self):
        self.deliver()
        incidents.enqueue(self.factory, self.client.repo, failed(attempt=2))
        self.client.update_error = RuntimeError("SECRET")
        for _ in range(incidents.MAX_ATTEMPTS + 1):
            self.deliver()
        self.assertEqual(self.row()["attempts"], incidents.MAX_ATTEMPTS)
        self.assertEqual(self.row()["status"], "failed")
        self.assertEqual(self.client.creates, 1)
        self.client.update_error = None
        incidents.recover(self.factory, self.id, self.client)
        self.deliver()
        self.assertEqual(self.row()["status"], "delivered")

    def test_corrupt_record_is_reported_without_blocking_new_root(self):
        bad = self.factory / "incidents" / (incidents.identity(self.client.repo, "default", 99) + ".json")
        bad.write_text("malformed PRIVATE PATH")
        rid = incidents.enqueue(self.factory, self.client.repo, failed(ticket=50, target="another"))
        self.deliver()
        snapshot = incidents.snapshot(self.factory)
        self.assertEqual(snapshot["status"], "degraded")
        self.assertEqual(len(snapshot["errors"]), 1)
        self.assertNotIn("PRIVATE PATH", json.dumps(snapshot))
        self.assertTrue(any(row["id"] == rid and row["status"] == "delivered" for row in snapshot["incidents"]))
        self.assertEqual(bad.read_text(), "malformed PRIVATE PATH")

    def test_bad_existing_root_is_not_overwritten(self):
        path = self.factory / "incidents" / (self.id + ".json")
        path.write_text("bad")
        with self.assertRaises(ValueError):
            incidents.enqueue(self.factory, self.client.repo, self.run)
        self.assertEqual(path.read_text(), "bad")

    def test_multiple_remote_markers_stop_creation_and_recovery(self):
        row = self.row()
        self.client.issues = [{"number": n, "body": incidents.body(row)} for n in (1, 2)]
        self.deliver()
        self.assertEqual(self.row()["status"], "failed")
        self.assertEqual(self.client.creates, 0)
        with self.assertRaises(incidents.AmbiguousIncidents):
            incidents.recover(self.factory, self.id, self.client)

    def test_recorded_remote_issue_is_never_replaced(self):
        self.deliver()
        self.client.issues = []
        incidents.enqueue(self.factory, self.client.repo, failed(attempt=2))
        self.deliver()
        self.assertEqual(self.row()["status"], "failed")
        self.assertEqual(self.client.creates, 1)
        with self.assertRaises(incidents.RemoteIncidentUnavailable):
            incidents.recover(self.factory, self.id, self.client, confirm_not_created=True)

    def test_explicit_repair_attachment_survives_replay(self):
        repair = failed(ticket=43, attempt=2)
        self.assertEqual(incidents.enqueue(self.factory, self.client.repo, repair, root_id=self.id), self.id)
        self.assertEqual(incidents.enqueue(self.factory, self.client.repo, repair), self.id)
        self.assertEqual(len(incidents.snapshot(self.factory)["incidents"]), 1)
        self.assertEqual(len(self.row()["runs"]), 2)

    def test_successful_runs_cannot_open_incidents(self):
        self.run.status = deploy.DeployStatus.SUCCEEDED
        with self.assertRaises(ValueError):
            incidents.enqueue(self.factory, self.client.repo, self.run)

    def test_replay_skips_acknowledged_history_and_isolates_corrupt_root(self):
        cfg = SimpleNamespace(factory=self.factory, repo=self.client.repo)
        journal = self.factory / "events.jsonl"
        deploy.record_deploy_run(self.run, events_path=journal)
        bad = self.factory / "incidents" / (self.id + ".json")
        bad.write_text("bad record")
        other = failed(ticket=50, target="another")
        acknowledged = failed(ticket=51, target="acknowledged")
        deploy.record_deploy_run(other, events_path=journal)
        deploy.record_deploy_run(acknowledged, events_path=journal)
        from factory import lifecycle
        lifecycle.append(journal, {"event": "deploy_acknowledged", "target": acknowledged.target,
                                   "run_id": acknowledged.run_id})
        errors = incidents.sync_failed(cfg)
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]["run_id"], self.run.run_id)
        rows = incidents.snapshot(self.factory)["incidents"]
        self.assertEqual([r["original_ticket"] for r in rows], [50])

    def test_symlink_store_is_refused(self):
        alias = Path(self.temp.name) / "other"
        alias.mkdir()
        (alias / "incidents").symlink_to(self.factory / "incidents", target_is_directory=True)
        with self.assertRaises(ValueError):
            incidents.enqueue(alias, self.client.repo, self.run)


class TransportTest(unittest.TestCase):
    def test_http_status_is_classified_without_leaking_response(self):
        client = incidents.GitHub(SimpleNamespace(repo="acme/widgets"))
        for code in (403, 422, 429):
            with self.subTest(code=code), mock.patch.object(incidents.subprocess, "run", return_value=
                    subprocess.CompletedProcess([], 1, "RAW SECRET", f"gh: PRIVATE CONTENT (HTTP {code})")):
                with self.assertRaises(incidents.RequestRefused) as error:
                    client.api("repos/acme/widgets/issues", {}, "POST")
                self.assertEqual(error.exception.status, code)
                self.assertEqual(str(error.exception), f"HTTP{code}")

    def test_transport_and_server_errors_keep_unknown_create_outcome(self):
        client = incidents.GitHub(SimpleNamespace(repo="acme/widgets"))
        for message in ("network lost PRIVATE", "gh: server failure (HTTP 503)"):
            with self.subTest(message=message), mock.patch.object(incidents.subprocess, "run", return_value=
                    subprocess.CompletedProcess([], 1, "", message)):
                with self.assertRaises(RuntimeError):
                    client.api("repos/acme/widgets/issues", {}, "POST")

    def test_identity_is_process_environment_not_install_credentials(self):
        cfg = SimpleNamespace(repo="acme/widgets", install={"env": {"GH_TOKEN": "DISPATCHER"}},
                              apply_env={"GH_TOKEN": "APPLY-CONFIG"})
        with mock.patch.dict(os.environ, {"GH_TOKEN": "PROCESS", "OP_SERVICE_ACCOUNT_TOKEN": "PROCESS-OP"}, clear=True):
            client = incidents.GitHub(cfg)
        self.assertEqual(client.env["GH_TOKEN"], "PROCESS")
        self.assertEqual(client.env["OP_SERVICE_ACCOUNT_TOKEN"], "PROCESS-OP")
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertNotIn("GH_TOKEN", incidents.GitHub(cfg).env)

    def test_total_api_deadline_is_enforced(self):
        client = incidents.GitHub(SimpleNamespace(repo="acme/widgets"))
        client.deadline = 0
        with mock.patch.object(incidents.subprocess, "run") as run:
            with self.assertRaises(TimeoutError):
                client.api("repos/acme/widgets/issues")
            run.assert_not_called()

    def test_lookup_uses_all_states_pagination_and_fails_closed_at_limit(self):
        client = MemoryGitHub()
        row = {"id": incidents.identity(client.repo, "default", 42)}
        client.issues = [{"number": n, "body": "unrelated"} for n in range(1, 101)]
        client.issues.append({"number": 101, "state": "closed", "body": incidents.marker(row["id"])})
        self.assertEqual(client.find(row)[0]["number"], 101)
        self.assertTrue(all("state=all" in endpoint for _, endpoint, _ in client.calls))
        client.issues = [{"number": n, "body": "unrelated"} for n in range(1000)]
        with self.assertRaises(RuntimeError):
            client.find(row)


class ApplyIntegrationTest(unittest.TestCase):
    def test_escalation_queues_without_delivering_and_dry_run_is_read_only(self):
        from factory import apply, dispatch
        with tempfile.TemporaryDirectory() as temp:
            cfg = config.load(make_repo(Path(temp), "[apply]\nenabled = true\n"))
            apply.configure(cfg)
            with mock.patch.object(dispatch, "run", return_value=subprocess.CompletedProcess([], 0, "", "")), \
                    mock.patch.object(incidents, "deliver") as delivery:
                apply.apply_escalate(42, 55, "failure", commit="abcdef123456", dry_run=True)
                self.assertFalse((cfg.factory / "incidents").exists())
                apply.apply_escalate(42, 55, "failure", commit="abcdef123456")
                delivery.assert_not_called()
            self.assertEqual(len(incidents.snapshot(cfg.factory)["incidents"]), 1)
            self.assertEqual(deploy.get_target_state(events_path=dispatch.EVENTS).runs[-1].status,
                             deploy.DeployStatus.FAILED)

    def test_delivery_failure_does_not_change_empty_apply_pass_result(self):
        from factory import apply, dispatch
        with tempfile.TemporaryDirectory() as temp:
            cfg = config.load(make_repo(Path(temp), "[apply]\nenabled = true\n"))
            with mock.patch.object(config, "load", return_value=cfg), \
                    mock.patch.object(dispatch, "run", return_value=subprocess.CompletedProcess([], 0, "", "")), \
                    mock.patch.object(apply, "fetch_all_merged_prs", return_value=[]), \
                    mock.patch.object(deploy, "select_candidates_for_target", return_value=([], [])), \
                    mock.patch.object(incidents, "deliver", side_effect=TimeoutError("PRIVATE")) as delivery:
                self.assertEqual(apply.main([]), 0)
                delivery.assert_called_once()
                self.assertEqual(apply.main(["--dry-run"]), 0)
                delivery.assert_called_once()

    def test_delivery_runs_once_after_target_lock_is_released(self):
        from factory import apply, dispatch
        with tempfile.TemporaryDirectory() as temp:
            cfg = config.load(make_repo(Path(temp), "[apply]\nenabled = true\n"))
            candidate = {"ticket": 42, "pr": 55, "commit": "abcdef123456"}

            def fail(*args, **kwargs):
                apply.apply_escalate(42, 55, "failure", commit=candidate["commit"])
                return False

            def delivery(*args, **kwargs):
                ok, handle = deploy.acquire_target_lock(cfg.factory, "default")
                self.assertTrue(ok)
                deploy.release_lock(handle)
                self.assertEqual(deploy.get_target_state(events_path=dispatch.EVENTS).runs[-1].status,
                                 deploy.DeployStatus.FAILED)

            with mock.patch.object(config, "load", return_value=cfg), \
                    mock.patch.object(dispatch, "run", return_value=subprocess.CompletedProcess([], 0, "", "")), \
                    mock.patch.object(apply, "fetch_all_merged_prs", return_value=[]), \
                    mock.patch.object(deploy, "select_candidates_for_target", return_value=([candidate], [])), \
                    mock.patch.object(apply, "apply_one", side_effect=fail), \
                    mock.patch.object(incidents, "deliver", side_effect=delivery) as delivered:
                self.assertEqual(apply.main([]), 1)
                delivered.assert_called_once()


if __name__ == "__main__":
    unittest.main()
