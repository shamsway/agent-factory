"""Dedicated publisher integration: bounded fake GitHub, no public writes."""
import copy
import io
import json
import os
import subprocess
import unittest
from contextlib import redirect_stdout
from unittest import mock
from tests import test_investigation_model as fixtures
from factory import config, incidents, investigation_outbox as outbox
from factory import investigation_publisher as publisher, verify_secrets


class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ModelTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.cfg = self.fixture.cfg
        self.cfg.install = copy.deepcopy(self.cfg.install)
        self.cfg.publisher = publisher.policy({"enabled": True, "allow_publish": True,
            "key": "dedicated-publication-token", "login": "dedicated-publisher[bot]"})
        self.incident, self.run = self.fixture.fixture.root_id, self.fixture.fixture.run.run_id
        self.fixture.call(client=self.fixture.client)
        self.calls, self.comments = [], []

    def wire(self, wire):
        self.calls.append(wire)
        endpoint = wire["endpoint"]
        if endpoint == "installation/repositories?per_page=100":
            body = {"repositories": [{"full_name": self.cfg.repo}]}
        elif endpoint == "user": body = {"login": self.cfg.publisher["login"]}
        else: body = self.comments
        return {"status": "ok", "body": json.dumps(body)}

    def transport(self, wire):
        if wire["method"] != "POST": return self.wire(wire)
        self.calls.append(wire)
        path = next((self.cfg.factory / "investigation-outbox").glob("*.json"))
        self.assertEqual(json.loads(path.read_text())["state"], "uncertain")
        self.comments.append({"id": 1, "body": wire["payload"]["body"],
                              "user": {"login": self.cfg.publisher["login"]}})
        return {"status": "ok", "body": json.dumps(self.comments[-1])}

    def test_controlled_end_to_end_and_cached_delivery(self):
        outbox.enqueue(self.cfg, self.incident, self.run, now=fixtures.NOW + 2)
        state = publisher.send(self.cfg, self.incident, self.run, wire_fn=self.transport, now=fixtures.NOW + 2)
        self.assertEqual(state["state"], "delivered")
        publisher.send(self.cfg, self.incident, self.run, wire_fn=self.transport, now=fixtures.NOW + 2)
        self.assertEqual(sum(c["method"] == "POST" for c in self.calls), 1)
        self.assertNotIn(fixtures.SECRET, self.comments[0]["body"])

    def test_no_dispatch_apply_model_credential_reuse(self):
        for key in ("GH_TOKEN", "OP_SERVICE_ACCOUNT_TOKEN"):
            self.cfg.install["env"][key] = self.cfg.publisher["key"]
            self.assertEqual(publisher.credential_status(self.cfg), "invalid")
            self.cfg.install["env"].pop(key)
        self.cfg.apply_env["OTHER"] = self.cfg.publisher["key"]
        self.assertEqual(publisher.credential_status(self.cfg), "invalid")
        self.cfg.apply_env.clear()
        self.cfg.investigation["key"] = self.cfg.publisher["key"]
        self.assertEqual(publisher.credential_status(self.cfg), "invalid")

    def test_disabled_role_does_not_call(self):
        self.cfg.publisher["enabled"] = False
        with self.assertRaises(publisher.PublisherRefused):
            publisher.send(self.cfg, self.incident, self.run, wire_fn=lambda _: self.fail("network"))

    def test_endpoint_allowlist_and_request_budget(self):
        client = publisher.Publisher(self.cfg, wire_fn=self.transport)
        for endpoint, method, payload in (("repos/other/repo/issues/99/comments", "POST", {"body": "wrong"}),
                                           ("https://evil.example", "GET", None),
                                           ("repos/acme/widgets/issues/99", "DELETE", None)):
            with self.assertRaises(publisher.PublisherRefused): client.api(endpoint, payload, method)
        client.p["max_requests"] = 1
        client.verify()
        with self.assertRaises(publisher.PublisherRefused): client.verify()
        self.assertEqual(len(self.calls), 1)

    def test_unknown_post_retained_without_retry(self):
        outbox.enqueue(self.cfg, self.incident, self.run, now=fixtures.NOW + 2)
        def wire(w):
            if w["method"] == "POST":
                self.calls.append(w)
                return {"status": "unknown"}
            return self.transport(w)
        for _ in range(2):
            state = publisher.send(self.cfg, self.incident, self.run, wire_fn=wire, now=fixtures.NOW + 2)
            self.assertEqual(state["state"], "uncertain")
        self.assertEqual(sum(c["method"] == "POST" for c in self.calls), 1)

    def test_bad_identity_prevents_post(self):
        self.cfg.publisher["kind"] = "bot_token"
        def wrong(w): return {"status": "ok", "body": json.dumps({"login": fixtures.SECRET})}
        self.assertEqual(publisher.verify_status(self.cfg, wire_fn=wrong), "unavailable")
        with self.assertRaises(publisher.PublisherRefused):
            publisher.send(self.cfg, self.incident, self.run, wire_fn=wrong)

    def test_scoped_verifier_outputs_only_role_status(self):
        with mock.patch.object(publisher, "verify_status", return_value="read_verified"):
            rows = verify_secrets.credential_rows(self.cfg, "publisher", True)
        self.assertEqual(rows, [{"scope": "publisher", "key": publisher.KEY_NAME, "status": "read_verified"}])
        self.assertNotIn(self.cfg.publisher["key"], json.dumps(rows))

    def test_cli_never_sends_without_confirmation(self):
        with mock.patch.object(config, "load", return_value=self.cfg), mock.patch.object(publisher, "send") as send, redirect_stdout(io.StringIO()):
            self.assertEqual(publisher.main(["--incident", self.incident, "--run", self.run, "--send"]), 1)
            send.assert_not_called()

    def test_http_key_only_on_stdin_and_clean_child_environment(self):
        wire = {"key": self.cfg.publisher["key"], "timeout": 1, "max_response_bytes": 1000}
        child = mock.Mock(returncode=0, pid=9999)
        child.communicate.return_value = (b'{"status":"ok","body":"{}"}', b'')
        child.poll.return_value = 0
        with mock.patch.object(publisher.subprocess, "Popen", return_value=child) as popen:
            publisher.http_call(wire)
        args, kwargs = popen.call_args
        self.assertNotIn(wire["key"], json.dumps(args))
        self.assertEqual(kwargs["env"], {})
        self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
        self.assertIn(wire["key"].encode(), child.communicate.call_args[0][0])

    def test_host_policy_default_disabled_and_invalid_values_refused(self):
        self.assertFalse(publisher.policy({})["enabled"])
        for raw in ({"enabled": True}, {"key": "header\\r\\ninjection"}, {"kind": []}, {"max_requests": 13}):
            with self.assertRaises(config.ConfigError): publisher.policy(raw)

    def test_model_role_cannot_export_publisher_token(self):
        from factory import investigation_model
        self.cfg.investigation["key"] = self.cfg.publisher["key"]
        self.assertEqual(investigation_model.credential_status(self.cfg), "invalid")

    def test_host_only_loader_and_secret_repr(self):
        from pathlib import Path
        import tempfile
        from tests.test_factory import make_repo
        with tempfile.TemporaryDirectory() as folder:
            root = make_repo(Path(folder))
            raw = {"key": "publisher-private-fixture", "login": "dedicated-publisher[bot]"}
            with mock.patch.object(config, "host_config", return_value={"defaults": {"publisher": raw}}):
                cfg = config.load(root)
                self.assertEqual(cfg.publisher["key"], raw["key"])
                self.assertNotIn(raw["key"], repr(cfg))
            with (root / ".factory.toml").open("a") as stream:
                stream.write('\n[publisher]\nenabled = false\n')
            with self.assertRaisesRegex(config.ConfigError, "host-only"):
                config.load(root)

    def test_preview_shows_only_trusted_fixed_body_without_transport(self):
        from factory import investigation_model
        envelope = investigation_model.prepare(self.cfg, self.incident, self.run, now=fixtures.NOW + 2)
        with mock.patch.object(config, "load", return_value=self.cfg), mock.patch.object(publisher.model, "prepare", return_value=envelope), mock.patch.object(publisher, "http_call") as http, redirect_stdout(io.StringIO()) as output:
            code = publisher.main(["--incident", self.incident, "--run", self.run, "--preview"])
        self.assertEqual(code, 0)
        http.assert_not_called()
        row = json.loads(output.getvalue())
        self.assertEqual(row["issue"], 99)
        self.assertIn("explicit OOM", row["body"])
        self.assertFalse(row["public_write"])
        self.assertNotIn(fixtures.SECRET, output.getvalue())
