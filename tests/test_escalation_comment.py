"""The dispatcher's escalation comment on a public issue withholds runner-local paths and live mentions.

Only the GitHub comment is sanitized; the journal keeps the raw reason and the packet, logs and
handoff files are untouched.
"""

from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from factory import config, lifecycle
from tests.test_factory import make_repo

URL = "https://github.com/acme/widgets/actions/runs/42"


class EscalationCommentSanitizedTest(unittest.TestCase):
    def test_public_comment_withholds_paths_and_mentions_and_keeps_urls(self) -> None:
        from unittest import mock

        from factory import dispatch

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d))
            dispatch.configure(config.load(repo))
            wt = dispatch.FACTORY / "wt-7"
            (wt / ".factory").mkdir(parents=True)
            (wt / ".factory" / "handoff-7.md").write_text(
                f"Checked {URL} and asked @ops-team; fixture at /srv/runner/fixtures/7.json.\n")
            log_path = Path("/tmp/runner-only/logs/7-attempt-3.log")
            reason = "gate failed; worktree kept at /tmp/runner-only/wt-7"
            with mock.patch.object(dispatch, "run") as run_mock, \
                 mock.patch.object(dispatch, "gh_json", return_value={"labels": []}):
                dispatch.escalate(7, reason, log_path, code="gate_failed")

            [comment] = [c.args[0] for c in run_mock.call_args_list if c.args[0][:3] == ["gh", "issue", "comment"]]
            body = comment[comment.index("--body") + 1]

            self.assertTrue(body.startswith("Factory dispatcher escalating: "), body)
            self.assertIn("gate failed; worktree kept at (local path withheld)", body)
            self.assertIn("(local path withheld)", body)
            for leaked in ("/tmp/", "/srv/", str(dispatch.FACTORY), str(log_path)):
                self.assertNotIn(leaked, body)
            self.assertIsNone(re.search(r"@(?=[A-Za-z0-9])", body), body)
            self.assertIn("&#64;ops-team", body)
            self.assertIn(URL, body)

            escalation = next(e for e in lifecycle.read_events(dispatch.EVENTS) if e.get("event") == "escalate")
            self.assertEqual(escalation["reason"], reason)
            self.assertEqual(escalation["log"], str(log_path))


if __name__ == "__main__":
    unittest.main()
