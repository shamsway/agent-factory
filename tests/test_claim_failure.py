import io
import subprocess
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from factory import dispatch

TOKEN = "ghp_" + "a1B2c3D4e5" * 3 + "xyz012"
CMD = ["gh", "issue", "edit", "7"]


def failing(cmd, **kw):
    raise subprocess.CalledProcessError(1, cmd, "", f"boom: GraphQL error {TOKEN}\n")


class ClaimFailure(unittest.TestCase):
    def test_checked_run_logs_redacted_tail_and_raises(self):
        buf = io.StringIO()
        with patch.object(subprocess, "run", failing), redirect_stdout(buf), \
                self.assertRaises(subprocess.CalledProcessError):
            dispatch.run(CMD)
        out = buf.getvalue()
        self.assertIn("GraphQL error", out)
        self.assertNotIn(TOKEN, out)

    def test_tail_is_bounded(self):
        self.assertLessEqual(len(dispatch.stderr_tail("x" * 5000)), 2000)

    def test_token_cut_at_the_boundary_leaks_no_fragment(self):
        tail = dispatch.stderr_tail(TOKEN + "y" * 1990)
        self.assertLessEqual(len(tail), 2000)
        self.assertNotIn(TOKEN[-8:], tail)

    def test_claim_failure_skips_ticket(self):
        from tests.test_wait_decisions import WaitDecisions as Base

        class Case(Base):
            def runTest(self):
                self.cfg.workers = {"default": ["python3", "{prompt}"]}
                fresh = {"state": "OPEN", "labels": [{"name": "ready-for-agent"}], "assignees": [],
                         "title": "t", "body": "", "comments": []}
                calls = []

                def fake(cmd, **kw):
                    calls.append(cmd)
                    return failing(cmd)

                buf = io.StringIO()
                with patch.object(dispatch, "gh_json", return_value=fresh), \
                        patch.object(dispatch, "admit_plan", return_value=None), \
                        patch.object(dispatch, "_run", lambda cmd, *a: fake(cmd)), \
                        patch.object(dispatch, "ensure_worktree") as wt, redirect_stdout(buf):
                    dispatch.process_ticket(self.issue, 1, False)
                wt.assert_not_called()
                self.assertEqual(len(calls), 1)
                self.assertIn("claim failed", buf.getvalue())
                self.assertIn("GraphQL error", buf.getvalue())
                self.assertNotIn(TOKEN, buf.getvalue())
                events = [e for e in dispatch.lifecycle.read_events(self.events)
                          if e.get("event") == "claim-failed"]
                self.assertEqual(len(events), 1)
                self.assertNotIn(TOKEN, str(events[0]))
                self.assertFalse(dispatch.lock_held(dispatch.ticket_lock(7)))

        case = Case()
        case.setUp()
        try:
            case.runTest()
        finally:
            case.doCleanups()
            case.tearDown()


if __name__ == "__main__":
    unittest.main()
