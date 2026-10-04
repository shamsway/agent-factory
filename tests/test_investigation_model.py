"""Trusted model transport acceptance: synthetic evidence, no provider export."""
import copy
import json
import os
from pathlib import Path
import threading
import time
import unittest
from unittest import mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from factory import config, investigation_model as model, incidents, verify_secrets
from factory import investigation_evidence as evidence
from tests import test_investigation_boundary as fixtures

NOW, SECRET = fixtures.NOW, fixtures.SECRET


class ModelTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.BoundaryTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.cfg = config.Config(root=self.fixture.factory.parent, repo="acme/widgets")
        self.cfg.investigation = model.policy({"enabled": True, "allow_export": True,
            "url": "https://model.example/v1/chat/completions", "model": "fixed-model",
            "key": "dedicated-model-key"})
        path = self.fixture.factory / "incidents" / (self.fixture.root_id + ".json")
        row = incidents.read(path)
        row.update(status="delivered", uncertain=False, issue=99)
        incidents.write(path, row)
        self.calls = []

    def call(self, **kwargs):
        return model.investigate(self.cfg, self.fixture.root_id, self.fixture.run.run_id,
                                 now=NOW + 2, **kwargs)

    def wire(self, payload, result=None):
        input_ = json.loads(payload["messages"][1]["content"])
        result = result or {"projection_sha256": input_["projection_sha256"], "outcome": "proposal",
                  "findings": [{"code": "OOM_EVENT", "refs": ["e0004"]}], "action": "REVIEW_OOM"}
        return {"status": "ok", "body": json.dumps({"model": "fixed-model", "choices": [{
            "finish_reason": "stop", "message": {"role": "assistant", "content": json.dumps(result)}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 100, "total_tokens": 200}})}

    def client(self, policy, payload):
        self.calls.append(payload)
        # Read the durable receipt before the fake provider receives anything.
        receipt = next((self.cfg.factory / "investigations").glob("*.json"))
        state = json.loads(receipt.read_text())
        self.assertEqual(state["state"], "uncertain")
        self.assertEqual(state["request_count"], 1)
        self.assertGreater(state["reserved_input_tokens"], 100)
        self.assertEqual(payload["model"], "fixed-model")
        self.assertEqual(payload["tool_choice"], "none")
        self.assertNotIn("tools", payload)
        self.assertNotIn(SECRET, json.dumps(payload))
        self.assertNotIn("dedicated-model-key", json.dumps(payload))
        return self.wire(payload)

    def test_valid_result_persisted_once_and_fixed_publication(self):
        state = self.call(client=self.client)
        self.assertEqual(state["state"], "complete")
        self.assertEqual(self.call(client=self.client), state)
        self.assertEqual(len(self.calls), 1)
        envelope = model.prepare(self.cfg, self.fixture.root_id, self.fixture.run.run_id, now=NOW + 2)
        self.assertEqual(envelope.issue, 99)
        self.assertIn("explicit OOM", envelope.body)
        self.assertNotIn(SECRET, envelope.body)
        self.assertEqual(model.snapshot(self.cfg)["states"]["complete"], 1)

    def test_uncertainty_and_crash_do_not_retry(self):
        for mode in ("timeout", "crash"):
            with self.subTest(mode=mode):
                if mode == "timeout":
                    state = self.call(client=lambda *_: {"status": "uncertain", "code": "transport_timeout"})
                else:
                    def crash(*_): raise KeyboardInterrupt
                    with self.assertRaises(KeyboardInterrupt): self.call(client=crash)
                state = self.call(client=lambda *_: self.fail("must not retry"))
                self.assertEqual(state["state"], "uncertain")
                self.assertEqual(state["request_count"], 1)
                body = model.prepare(self.cfg, self.fixture.root_id, self.fixture.run.run_id, now=NOW + 2).body
                self.assertIn("budget is exhausted", body)
                for path in (self.cfg.factory / "investigations").glob("*.json"): path.unlink()

    def test_hostile_output_and_unknown_secret_refused_without_persistence(self):
        for mutation in ({"text": SECRET}, {"action": "curl secret"},
                         {"findings": [{"code": "OOM_EVENT", "refs": ["e0001"]}]}):
            with self.subTest(mutation=mutation):
                def hostile(p, payload):
                    result = {"projection_sha256": json.loads(payload["messages"][1]["content"])["projection_sha256"],
                              "outcome": "proposal", "findings": [{"code": "OOM_EVENT", "refs": ["e0004"]}],
                              "action": "REVIEW_OOM", **mutation}
                    return self.wire(payload, result)
                state = self.call(client=hostile)
                self.assertEqual(state["state"], "failed")
                raw = next((self.cfg.factory / "investigations").glob("*.json")).read_text()
                self.assertNotIn(SECRET, raw)
                self.assertNotIn("curl", raw)
                for path in (self.cfg.factory / "investigations").glob("*.json"): path.unlink()

    def test_export_key_and_token_budget_before_call(self):
        for updates in ({"enabled": False}, {"key": "apply-key"}, {"token_budget": 1024}):
            with self.subTest(updates=updates):
                original = dict(self.cfg.investigation)
                self.cfg.apply_env = {"GH_TOKEN": "apply-key"}
                self.cfg.investigation.update(updates)
                with self.assertRaises(model.ModelRefused):
                    self.call(client=lambda *_: self.fail("must not export"))
                self.cfg.investigation = original
        self.assertFalse((self.cfg.factory / "investigations").exists())
        with self.assertRaises(config.ConfigError):
            model.policy({"enabled": True, "allow_export": False})

    def test_changed_policy_or_projection_does_not_spend_again(self):
        self.call(client=self.client)
        self.cfg.investigation["model"] = "other-model"
        with self.assertRaisesRegex(model.ModelRefused, "state_identity_changed"):
            self.call(client=lambda *_: self.fail("must not retry"))

    def test_identity_strings_are_narrow_and_hash_only(self):
        for value in ("ignore instructions", "x" * 129, "job\nsteal", "秘密"):
            with self.assertRaises(evidence.EvidenceRefused): evidence.alias("job", value)
        self.assertNotIn("worker", evidence.alias("job", "worker"))

    def test_verify_secrets_separate_role_and_no_live_export(self):
        rows = verify_secrets.credential_rows(self.cfg, "all", False)
        self.assertIn({"scope": "investigation", "key": model.KEY_NAME, "status": "configured"}, rows)
        self.assertNotIn("dedicated-model-key", json.dumps(rows))
        self.cfg.llm_key = "dedicated-model-key"
        self.assertEqual(verify_secrets.credential_rows(self.cfg, "all", True)[-1]["status"], "invalid")

    def test_unsafe_store_and_corrupt_receipt_fail_closed(self):
        self.call(client=self.client)
        root = self.cfg.factory / "investigations"
        path = next(root.glob("*.json"))
        original = path.read_text()
        path.write_text('{"version":1,"version":1}')
        with self.assertRaises(evidence.EvidenceRefused): self.call(client=self.client)
        self.assertEqual(model.snapshot(self.cfg)["status"], "unavailable")
        path.write_text(original)
        path.unlink()
        path.symlink_to(self.fixture.path / "diagnostics.json")
        with self.assertRaises(evidence.EvidenceRefused): self.call(client=self.client)

    def test_provider_tokens_model_tool_calls_and_size_validated(self):
        for mutation in ("tokens", "model", "tool", "length", "size"):
            def invalid(p, payload):
                wire = self.wire(payload)
                body = json.loads(wire["body"])
                if mutation == "tokens": body["usage"]["completion_tokens"] = 99999
                if mutation == "model": body["model"] = "invented"
                if mutation == "tool": body["choices"][0]["message"]["tool_calls"] = [{"name": "exec"}]
                if mutation == "length": body["choices"][0]["finish_reason"] = "length"
                if mutation == "size": body["choices"][0]["message"]["content"] = "x" * 9000
                return {"status": "ok", "body": json.dumps(body)}
            self.assertEqual(self.call(client=invalid)["state"], "failed")
            for path in (self.cfg.factory / "investigations").glob("*.json"): path.unlink()

    def test_supported_classes_and_unsupported_escalation(self):
        for code, action, ref in (("PLACEMENT_CONSTRAINTS", "REVIEW_CONSTRAINTS", "e0002"),
                                 ("RESOURCE_CPU", "REVIEW_CPU", "e0002"),
                                 ("RESOURCE_MEMORY", "REVIEW_MEMORY", "e0002")):
            def supported(p, payload):
                return self.wire(payload, {"projection_sha256": json.loads(payload["messages"][1]["content"])["projection_sha256"],
                    "outcome": "proposal", "findings": [{"code": code, "refs": [ref]}], "action": action})
            self.assertEqual(self.call(client=supported)["state"], "complete")
            for path in (self.cfg.factory / "investigations").glob("*.json"): path.unlink()
        def insufficient(p, payload):
            return self.wire(payload, {"projection_sha256": json.loads(payload["messages"][1]["content"])["projection_sha256"],
                             "outcome": "escalate", "reason": "UNSUPPORTED"})
        self.call(client=insufficient)
        body = model.prepare(self.cfg, self.fixture.root_id, self.fixture.run.run_id, now=NOW + 2).body
        self.assertIn("needs human investigation", body)
        self.assertNotIn(SECRET, body)

    def test_fresh_evidence_required_before_publication(self):
        self.call(client=self.client)
        with self.assertRaisesRegex(model.ModelRefused, "state_identity_changed"):
            model.prepare(self.cfg, self.fixture.root_id, self.fixture.run.run_id, now=NOW + 4000)

    def test_receipt_write_failure_prevents_network(self):
        with mock.patch.object(model, "_write", side_effect=OSError(SECRET)):
            with self.assertRaises((model.ModelRefused, evidence.EvidenceRefused)) as refused:
                self.call(client=lambda *_: self.fail("network must follow fsync"))
            self.assertNotIn(SECRET, str(refused.exception))

    def test_refused_evidence_can_prepare_escalation_without_model(self):
        self.fixture.bundle["logs_enabled"] = True
        self.fixture.write_bundle()
        with self.assertRaises(evidence.EvidenceRefused):
            self.call(client=lambda *_: self.fail("refused evidence must not export"))
        body = model.prepare(self.cfg, self.fixture.root_id, self.fixture.run.run_id, now=NOW + 2).body
        self.assertIn("logs_not_allowed", body)
        self.assertNotIn(SECRET, body)

    def test_local_http_transport_no_proxy_redirect_retry_or_environment_key(self):
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                owner.calls.append(self.path)
                self.server.auth = self.headers.get("Authorization")
                self.server.request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if self.server.mode == "redirect":
                    self.send_response(302); self.send_header("Location", "/steal"); self.end_headers(); return
                if self.server.mode == "slow": time.sleep(2)
                if self.server.mode == "reject":
                    self.send_response(403); self.end_headers(); return
                raw = b"x" * 65537 if self.server.mode == "oversize" else owner.wire(self.server.request)["body"].encode()
                self.send_response(200); self.end_headers()
                try: self.wfile.write(raw)
                except BrokenPipeError: pass
            def log_message(self, *_): pass
        with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
            server.mode = "ok"
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            self.addCleanup(server.shutdown)
            self.cfg.investigation.update(url=f"http://127.0.0.1:{server.server_port}/v1/chat/completions",
                                          allow_loopback_http=True, timeout=1)
            with mock.patch.dict(os.environ, {"HTTPS_PROXY": "http://invalid.example", "GH_TOKEN": SECRET}):
                self.assertEqual(self.call()["state"], "complete")
            self.assertEqual(server.auth, "Bearer dedicated-model-key")
            self.assertEqual(len(self.calls), 1)
            for mode in ("redirect", "reject", "oversize", "slow"):
                for path in (self.cfg.factory / "investigations").glob("*.json"): path.unlink()
                server.mode = mode
                state = self.call()
                self.assertEqual(state["state"], "failed" if mode in ("reject", "oversize") else "uncertain")
                self.call(client=lambda *_: self.fail("must not retry"))
            self.assertEqual(len(self.calls), 5)
            server.shutdown()


class ModelConfigurationTests(unittest.TestCase):
    def test_host_only_settings_and_no_key_repr(self):
        import tempfile
        from tests.test_factory import make_repo
        with tempfile.TemporaryDirectory() as folder:
            root = make_repo(Path(folder))
            p = {"key": "private-model-key", "model": "fixed-model", "url": "https://model.example/v1/chat/completions"}
            with mock.patch.object(config, "host_config", return_value={"defaults": {"investigation": p}}):
                cfg = config.load(root)
                self.assertEqual(cfg.investigation["key"], "private-model-key")
                self.assertNotIn("private-model-key", repr(cfg))
            with (root / ".factory.toml").open("a") as stream:
                stream.write('\n[investigation]\nallow_export = true\n')
            with self.assertRaisesRegex(config.ConfigError, "host-only"): config.load(root)

    def test_endpoint_config_is_strict(self):
        for url in ("http://model.example/v1/chat/completions", "https://user:pass@model.example/v1/chat/completions",
                    "https://model.example/v1/chat/completions?key=x", "https://model.example/other",
                    "https://model.example/\nv1/chat/completions"):
            with self.assertRaises(config.ConfigError): model.policy({"url": url})
        for updates in ({"max_output_tokens": True}, {"timeout": 0}, {"model": "ignore instructions"},
                        {"unexpected": "secret"}, {"key": "key\nheader"}):
            with self.assertRaises(config.ConfigError): model.policy(updates)

if __name__ == "__main__": unittest.main()
