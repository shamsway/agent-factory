"""Trusted outbox acceptance uses synthetic evidence and a fake publisher only."""
import json
import unittest
from unittest import mock
from tests import test_investigation_model as fixtures
from factory import incidents, investigation_outbox as outbox, investigation_model as model
from factory import investigation_evidence as evidence


class FakePublisher:
    def __init__(self, mode="ok"):
        self.mode, self.comments, self.posts = mode, [], 0

    def api(self, endpoint, payload=None, method=None):
        if method != "POST":
            if self.mode == "lookup_failed": raise RuntimeError(fixtures.SECRET)
            return self.comments
        self.posts += 1
        if self.mode == "rejected": raise incidents.RequestRefused(403)
        row = {"id": 1, "body": payload["body"], "user": {"login": "publisher-bot"}}
        if self.mode == "unknown_without_comment": raise RuntimeError(fixtures.SECRET)
        self.comments.append(row)
        if self.mode == "lost_response": raise RuntimeError(fixtures.SECRET)
        return row


class OutboxTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ModelTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.cfg = self.fixture.cfg
        self.incident, self.run = self.fixture.fixture.root_id, self.fixture.fixture.run.run_id
        self.fixture.call(client=self.fixture.client)

    def enqueue(self):
        return outbox.enqueue(self.cfg, self.incident, self.run, now=fixtures.NOW + 2)

    def deliver(self, publisher, **kwargs):
        return outbox.deliver(self.cfg, self.incident, self.run, publisher=publisher,
                             publisher_login=kwargs.get("publisher_login", "publisher-bot"), now=fixtures.NOW + 2)

    def test_durable_enqueue_and_confirmed_replay(self):
        row = self.enqueue()
        self.assertEqual(row, self.enqueue())
        self.assertNotIn("body", row)
        remote = FakePublisher()
        state = self.deliver(remote)
        self.assertEqual(state["state"], "delivered")
        self.assertEqual(self.deliver(remote), state)
        self.assertEqual(remote.posts, 1)
        self.assertNotIn(fixtures.SECRET, remote.comments[0]["body"])

    def test_intent_precedes_post(self):
        self.enqueue()
        remote = FakePublisher()
        original = remote.api
        def api(endpoint, payload=None, method=None):
            if method == "POST":
                row = next((self.cfg.factory / "investigation-outbox").glob("*.json"))
                self.assertEqual(json.loads(row.read_text())["state"], "uncertain")
            return original(endpoint, payload, method)
        remote.api = api
        self.assertEqual(self.deliver(remote)["state"], "delivered")

    def test_lost_response_adopted_without_second_post(self):
        self.enqueue()
        remote = FakePublisher("lost_response")
        self.assertEqual(self.deliver(remote)["state"], "uncertain")
        self.assertEqual(self.deliver(remote)["state"], "delivered")
        self.assertEqual(remote.posts, 1)

    def test_missing_comment_after_uncertainty_never_reposts(self):
        self.enqueue()
        remote = FakePublisher("unknown_without_comment")
        self.assertEqual(self.deliver(remote)["state"], "uncertain")
        self.assertEqual(self.deliver(remote)["state"], "uncertain")
        self.assertEqual(remote.posts, 1)
        row = next((self.cfg.factory / "investigation-outbox").glob("*.json"))
        self.assertNotIn(fixtures.SECRET, row.read_text())

    def test_lookup_failure_does_not_post(self):
        self.enqueue()
        remote = FakePublisher("lookup_failed")
        self.assertEqual(self.deliver(remote)["state"], "queued")
        self.assertEqual(remote.posts, 0)

    def test_changed_destination_and_resolved_evidence_block(self):
        self.enqueue()
        remote = FakePublisher()
        with mock.patch.object(model, "prepare", side_effect=evidence.EvidenceRefused("run_already_resolved")):
            self.assertEqual(self.deliver(remote)["state"], "blocked")
        self.assertEqual(remote.posts, 0)

    def test_publisher_identity_cannot_change_after_unknown_post(self):
        self.enqueue()
        remote = FakePublisher("unknown_without_comment")
        self.deliver(remote)
        with self.assertRaises(evidence.EvidenceRefused):
            self.deliver(remote, publisher_login="another-bot")
        self.assertEqual(remote.posts, 1)

    def test_wrong_author_does_not_reconcile(self):
        self.enqueue()
        remote = FakePublisher("lost_response")
        self.deliver(remote)
        remote.comments[0]["user"]["login"] = "someone-else"
        self.assertEqual(self.deliver(remote)["state"], "uncertain")
        self.assertEqual(remote.posts, 1)

    def test_definite_rejection_is_visible_and_not_retried(self):
        self.enqueue()
        remote = FakePublisher("rejected")
        self.assertEqual(self.deliver(remote)["state"], "failed")
        self.assertEqual(self.deliver(remote)["code"], "post_rejected")
        self.assertEqual(remote.posts, 1)

    def test_extra_receipt_fields_fail_closed(self):
        self.enqueue()
        path = next((self.cfg.factory / "investigation-outbox").glob("*.json"))
        row = json.loads(path.read_text())
        row["body"] = fixtures.SECRET
        path.write_text(json.dumps(row))
        remote = FakePublisher()
        with self.assertRaises(evidence.EvidenceRefused):
            self.deliver(remote)
        self.assertEqual(remote.posts, 0)

    def test_symlink_receipt_refused(self):
        self.enqueue()
        row = next((self.cfg.factory / "investigation-outbox").glob("*.json"))
        row.rename(row.with_suffix(".backup"))
        row.symlink_to(row.with_suffix(".backup"))
        with self.assertRaises(evidence.EvidenceRefused):
            self.deliver(FakePublisher())
