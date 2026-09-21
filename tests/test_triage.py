"""Triage LLM call behavior: bearer auth header only when a key is configured.

Run: python -m unittest discover -s tests
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agent_factory import config

from tests.test_factory import make_repo


class TriageTest(unittest.TestCase):
    def test_call_llm_sends_bearer_header_only_when_key_configured(self) -> None:
        """A gated OpenAI-compatible endpoint (e.g. LiteLLM) needs an
        Authorization header -- without one, call_llm's request looks
        identical to a plain unauthenticated local-Ollama call and the
        endpoint 401s. The header must appear iff a key is configured, and
        never for the (still-supported) no-auth local-model case."""
        from unittest import mock

        from agent_factory import triage

        class FakeResponse:
            def __enter__(self) -> "FakeResponse":
                return self

            def __exit__(self, *exc: object) -> bool:
                return False

            def read(self) -> bytes:
                return json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode()

        captured: dict = {}

        def fake_urlopen(req: object, timeout: int | None = None) -> FakeResponse:
            captured["auth"] = req.get_header("Authorization")  # type: ignore[attr-defined]
            return FakeResponse()

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), '[triage]\nurl = "http://h/v1/chat/completions"\nkey = "sk-secret"\n')
            triage.configure(config.load(repo))
            with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
                self.assertEqual(triage.call_llm([{"role": "user", "content": "hi"}]), "ok")
            self.assertEqual(captured["auth"], "Bearer sk-secret")

        with tempfile.TemporaryDirectory() as d:
            repo2 = make_repo(Path(d), '[triage]\nurl = "http://h/v1/chat/completions"\n')
            triage.configure(config.load(repo2))
            with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
                triage.call_llm([{"role": "user", "content": "hi"}])
            self.assertIsNone(captured["auth"])


if __name__ == "__main__":
    unittest.main()
