"""Operator investigation-run command: fixture-only, fake model, no network or publication."""
import contextlib
import fcntl
import io
import json
import os
import unittest
from unittest import mock

from factory import cli, config, incidents, lifecycle
from factory import investigation_evidence as evidence
from factory import investigation_model as model
from factory import investigation_run as run_cmd
from tests import test_investigation_boundary as fixtures

NOW, SECRET = fixtures.NOW, fixtures.SECRET
KEY = "dedicated-model-key"


class InvestigationRunTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.BoundaryTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.cfg = config.Config(root=self.fixture.factory.parent, repo="acme/widgets")
        self.configure()
        path = self.fixture.factory / "incidents" / (self.fixture.root_id + ".json")
        row = incidents.read(path)
        row.update(status="delivered", uncertain=False, issue=99)
        incidents.write(path, row)
        self.incident, self.run_id = self.fixture.root_id, self.fixture.run.run_id
        self.calls = []
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop(lifecycle.CONTEXT_ENV, None)

    def configure(self, **overrides):
        self.cfg.investigation = model.policy({"enabled": True, "allow_export": True,
            "url": "https://model.example/v1/chat/completions", "model": "fixed-model", "key": KEY, **overrides})

    def provider(self, policy, payload, *, content=None):
        self.calls.append(payload)
        projection = json.loads(payload["messages"][1]["content"])["projection_sha256"]
        content = content or json.dumps({"projection_sha256": projection, "outcome": "proposal",
                                         "findings": [{"code": "OOM_EVENT", "refs": ["e0004"]}],
                                         "action": "REVIEW_OOM"})
        return {"status": "ok", "body": json.dumps({"model": "fixed-model", "choices": [{
            "finish_reason": "stop", "message": {"role": "assistant", "content": content}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 100, "total_tokens": 200}})}

    def run_(self, **kwargs):
        kwargs.setdefault("client", self.provider)
        return run_cmd.investigation_run(self.cfg, kwargs.pop("incident", self.incident),
                                         kwargs.pop("run", self.run_id), now=NOW + 2, **kwargs)

    def live(self, **kwargs):
        sha = evidence.read_evidence(self.cfg.factory, self.incident, self.run_id, now=NOW + 2).sha256
        return self.run_(live=True, confirm_spend_cap=True, projection_sha256=sha, **kwargs)

    def refused(self, code, **kwargs):
        live = kwargs.pop("live_call", False)
        with self.assertRaises((run_cmd.RunRefused, model.ModelRefused, evidence.EvidenceRefused)) as caught:
            self.live(**kwargs) if live else self.run_(**kwargs)
        self.assertEqual(str(caught.exception), code)

    def journal(self):
        return [r for r in lifecycle.read_events(self.cfg.factory / "events.jsonl") if r.get("event") == run_cmd.EVENT]

    def receipts(self):
        return list((self.cfg.factory / "investigations").glob("*.json"))

    def assert_private(self, text):
        for private in (SECRET, KEY, "worker", "infra", "e0004", "messages", "evidence", "Analyze only"):
            self.assertNotIn(private, text)

    def test_preview_makes_no_model_call_and_reports_metadata_only(self):
        result = self.run_(client=lambda *_: self.fail("preview must not call the provider"))
        self.assertTrue(result["ok"])
        self.assertFalse(result["provider_called"])
        self.assertTrue(result["would_call"])
        self.assertIsNone(result["blocked"])
        self.assertEqual(result["receipt"], "new")
        self.assertFalse(result["public_write"])
        self.assertEqual(result["request"]["model"], "fixed-model")
        self.assertIn("--projection-sha256 " + result["projection_sha256"], result["next"][0])
        self.assertEqual(self.receipts(), [])
        self.assert_private(json.dumps(result))
        rows = self.journal()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["mode"], "preview")
        self.assertEqual(result["audit"], "recorded")

    def test_resolves_incident_from_run_and_newest_run_from_incident(self):
        self.assertEqual(run_cmd.resolve(self.cfg, None, self.run_id), (self.incident, self.run_id))
        self.assertEqual(run_cmd.resolve(self.cfg, self.incident, None), (self.incident, self.run_id))
        for incident, run_id, code in ((None, None, "identity_required"), ("../x", None, "invalid_identity"),
                                       (None, "unknown-run", "incident_not_found")):
            with self.subTest(code=code), self.assertRaises(run_cmd.RunRefused) as caught:
                run_cmd.resolve(self.cfg, incident, run_id)
            self.assertEqual(str(caught.exception), code)
        other = config.Config(root=self.cfg.root, repo="acme/other")
        with self.assertRaises(run_cmd.RunRefused):
            run_cmd.resolve(other, self.incident, None)

    def test_resolved_run_refused(self):
        lifecycle.append(self.cfg.factory / "events.jsonl",
                         {"event": "deploy_acknowledged", "target": "default", "run_id": self.run_id})
        self.refused("run_already_resolved")
        self.refused("run_already_resolved", live_call=False, live=True, confirm_spend_cap=True,
                     projection_sha256="0" * 64)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.journal()[-1]["code"], "run_already_resolved")

    def test_mismatched_evidence_hash_and_unconfirmed_projection_refused(self):
        path = self.fixture.path / "diagnostics.json"
        path.write_bytes(path.read_bytes() + b" ")
        self.refused("diagnostics_hash_mismatch")
        path.write_bytes(path.read_bytes()[:-1])
        self.refused("projection_changed", live=True, confirm_spend_cap=True, projection_sha256="0" * 64)
        self.refused("projection_confirmation_required", live=True, confirm_spend_cap=True)
        self.assertEqual(self.calls, [])

    def test_missing_lineage_refused(self):
        for observation in self.fixture.bundle["observations"]:
            if "lineage" in observation:
                observation["lineage"]["id"] = "unrelated"
        self.fixture.write_bundle()
        self.refused("lineage_unavailable")
        self.refused("incident_run_mismatch", run="deploy-default-01234567-9")
        self.assertEqual(self.calls, [])

    def test_live_call_with_fake_model_then_cached_replay(self):
        result = self.live()
        self.assertTrue(result["ok"])
        self.assertTrue(result["provider_called"])
        self.assertEqual(result["outcome"], "called")
        self.assertEqual(result["result"]["findings"], ["OOM_EVENT"])
        self.assertEqual(result["receipt"]["request_count"], 1)
        self.assertIn("investigation-publish", result["next"][0])
        self.assertFalse(result["public_write"])
        replay = self.live()
        self.assertFalse(replay["provider_called"])
        self.assertEqual(replay["outcome"], "cached")
        self.assertEqual(replay["result"], result["result"])
        self.assertEqual(len(self.calls), 1)
        preview = self.run_()
        self.assertFalse(preview["would_call"])
        self.assertEqual(preview["receipt"], "cached")
        self.assertFalse((self.cfg.factory / "outbox").exists())
        rows = self.journal()
        self.assertEqual([r["mode"] for r in rows], ["live", "live", "preview"])
        self.assertEqual([r["provider_called"] for r in rows], [True, False, False])
        self.assertEqual(rows[0]["usage"]["total_tokens"], 200)
        for row in rows:
            self.assertNotIn("result", row)
            self.assert_private(json.dumps(row))

    def test_evidence_changed_after_confirmation_refused_before_call(self):
        real = evidence.read_evidence
        reads = []

        def changing(*args, **kwargs):
            projection = real(*args, **kwargs)
            reads.append(projection)
            if len(reads) == 1:
                return projection
            return mock.Mock(repository=projection.repository, sha256="f" * 64, data=projection.data)

        sha = real(self.cfg.factory, self.incident, self.run_id, now=NOW + 2).sha256
        with (mock.patch.object(evidence, "read_evidence", side_effect=changing),
              self.assertRaises(run_cmd.RunRefused) as caught):
            self.run_(live=True, confirm_spend_cap=True, projection_sha256=sha)
        self.assertEqual(str(caught.exception), "projection_changed")
        self.assertEqual(self.calls, [])

    def test_unknown_outcome_recorded_and_never_retried(self):
        def lost(policy, payload):
            self.calls.append(payload)
            return {"status": "uncertain", "code": "transport_timeout"}
        result = self.live(client=lost)
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "uncertain")
        self.assertEqual(result["code"], "transport_timeout")
        self.assertIn("investigation-reset", result["next"][0])
        for retry in (False, True):
            again = self.live(client=lost, retry=retry)
            self.assertFalse(again["provider_called"])
            self.assertEqual(again["outcome"], "uncertain")
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.journal()[-1]["state"], "uncertain")

    def test_invalid_provider_text_never_reaches_journal_or_output(self):
        result = self.live(client=lambda p, payload: self.provider(p, payload, content=SECRET))
        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["validation_reason"], "content_not_json")
        self.assert_private(json.dumps(result))
        self.assert_private(json.dumps(self.journal()))

    def test_definite_retryable_needs_retry_flag(self):
        def refused(policy, payload):
            self.calls.append(payload)
            return {"status": "retryable", "code": "rate_limited"}
        self.assertEqual(self.live(client=refused)["state"], "retryable")
        self.assertIn("--retry", self.run_()["next"][0])
        self.refused("retry_flag_required", live_call=True)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.live(retry=True)["state"], "complete")
        self.assertEqual(len(self.calls), 2)

    def test_budget_exhaustion_refuses_without_call(self):
        self.configure(token_budget=1024, max_input_bytes=1024)
        self.refused("request_budget")
        self.configure(max_requests=1)
        def refused(policy, payload):
            self.calls.append(payload)
            return {"status": "retryable", "code": "connection_refused"}
        self.live(client=refused)
        self.assertEqual(self.run_()["blocked"], "request_budget")
        self.refused("request_budget", live_call=True, retry=True)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.journal()[-1]["code"], "request_budget")

    def test_lock_contention_refuses(self):
        directory = self.cfg.factory / "investigations"
        directory.mkdir(mode=0o700)
        name = evidence.digest((self.incident + "\0" + self.run_id).encode()) + ".lock"
        fd = os.open(directory / name, os.O_CREAT | os.O_RDWR, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)
        self.refused("investigation_busy")
        self.refused("investigation_busy", live_call=True)
        self.assertEqual(self.calls, [])

    def test_config_switches_and_spend_cap_acknowledgement(self):
        self.cfg.investigation = model.policy({"url": "https://model.example/v1/chat/completions",
                                               "model": "fixed-model", "key": KEY})
        self.assertEqual(self.run_()["blocked"], "model_export_disabled")
        self.refused("model_export_disabled", live_call=True)
        self.cfg.investigation = {"enabled": True, "allow_export": False}
        self.refused("configuration_invalid")
        self.configure()
        self.refused("provider_spend_cap_ack_required", live=True, projection_sha256="0" * 64)
        self.cfg.llm_key = KEY
        self.refused("model_credential_invalid", live_call=True)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.receipts(), [])

    def test_worker_and_reviewer_context_refused_without_journal(self):
        before = len(self.journal())
        os.environ[lifecycle.CONTEXT_ENV] = json.dumps({"schema_version": 1, "path": "/x"})
        self.refused("operator_context_required")
        out = io.StringIO()
        with contextlib.redirect_stdout(out), mock.patch.object(config, "load", side_effect=AssertionError):
            self.assertEqual(run_cmd.main(["--incident", self.incident]), 1)
        self.assertEqual(json.loads(out.getvalue()), {"ok": False, "code": "operator_context_required"})
        self.assertEqual(len(self.journal()), before)

    def test_cli_registered_preview_prints_fixed_json(self):
        self.assertEqual(cli.COMMANDS["investigation-run"][:2], ("investigation_run", "main"))
        out = io.StringIO()
        with (contextlib.redirect_stdout(out), mock.patch.object(config, "load", return_value=self.cfg),
              mock.patch("time.time", return_value=NOW + 2)):
            self.assertEqual(run_cmd.main(["--run", self.run_id]), 0)
        result = json.loads(out.getvalue())
        self.assertEqual(result["incident"], self.incident)
        self.assertFalse(result["provider_called"])
        self.assert_private(out.getvalue())
        out = io.StringIO()
        with contextlib.redirect_stdout(out), mock.patch.object(config, "load", return_value=self.cfg):
            self.assertEqual(run_cmd.main(["--incident", self.incident, "--live"]), 1)
        self.assertEqual(json.loads(out.getvalue()), {"ok": False, "code": "provider_spend_cap_ack_required"})


if __name__ == "__main__":
    unittest.main()
