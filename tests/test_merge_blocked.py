"""#77: a merge GitHub refuses on branch policy waits; the merge pass carries on."""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from factory import config, dispatch, lifecycle

os.environ.pop(lifecycle.CONTEXT_ENV, None)  # never journal fixture rows into a live dispatcher's journal

HEAD = "a" * 40
POLICY = (
    "X Pull request acme/widgets#70 is not mergeable: the base branch policy prohibits the merge.\n"
)


class MergeBlockedTest(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        cfg = config.Config(root=Path(temp.name), repo="acme/widgets")
        dispatch.configure(cfg)
        self.events = cfg.factory / "events.jsonl"
        pr = {
            "number": 70, "headRefName": "agent/7", "headRefOid": HEAD,
            "baseRefName": "main", "isDraft": False,
            "labels": [{"name": dispatch.FACTORY_APPROVED}],
            "reviewDecision": "APPROVED", "state": "OPEN", "title": "feature",
            "files": [{"path": "factory/dispatch.py"}],
        }
        self.pr = pr
        # Risk tier, gate, review and approval already recorded for this exact head.
        # Without a risk row the head is an unclassified legacy head, and its High-risk
        # path (factory/dispatch.py) fails the evidence check before the merge.
        for row in (
            {"event": "risk", "ticket": 7, "head": HEAD, "tier": "Medium",
             "matched_rules": ["medium:fixture"]},
            {"event": "attempt", "ticket": 7, "head": HEAD, "gate": "PASS", "actual_head": HEAD},
            {"event": "review", "ticket": 7, "head": HEAD, "accepted": True,
             "verdict": "APPROVE", "actual_head": HEAD},
            {"event": "approved", "ticket": 7, "pr": 70, "head": HEAD,
             "gate_head": HEAD, "review_head": HEAD},
        ):
            lifecycle.append(self.events, row)
        self.calls: list[list[str]] = []

    def gh_json(self, args):
        if args[:2] == ["pr", "list"]:
            return [self.pr]
        if args[:2] == ["pr", "view"]:
            return self.pr
        if args[0] == "api":
            return {"behind_by": 0}
        raise AssertionError(args)

    def gh_run(self, refusal: str | None):
        def gh(cmd, **kwargs):
            self.calls.append(cmd)
            if cmd[:3] == ["gh", "pr", "merge"] and refusal is not None:
                raise subprocess.CalledProcessError(1, cmd, output="", stderr=refusal)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        return gh

    def merge_pass(self, refusal: str | None):
        """One merge pass over PR #70 (ticket 7) with `gh pr merge` answering `refusal`."""
        with mock.patch.object(dispatch, "gh_json", side_effect=self.gh_json), \
                mock.patch.object(dispatch, "pr_checks", return_value=[{"name": "ci", "bucket": "pass"}]), \
                mock.patch.object(dispatch, "initiative_kind", return_value=None), \
                mock.patch.object(dispatch, "run", side_effect=self.gh_run(refusal)), \
                mock.patch.object(dispatch, "escalate") as escalate, \
                mock.patch.object(dispatch, "cleanup_after_merge"), \
                mock.patch("factory.learn.promote_pass"), \
                mock.patch.object(dispatch, "log") as log:
            dispatch.merge_pass_locked(False)
        return escalate, log

    def rows(self, event: str) -> list[dict]:
        return [row for row in lifecycle.read_events(self.events) if row.get("event") == event]

    def test_policy_refused_merge_waits_and_leaves_the_approval_in_place(self) -> None:
        escalate, log = self.merge_pass(POLICY)

        self.assertFalse(any(
            "--remove-label" in cmd or cmd[:3] == ["gh", "pr", "edit"] for cmd in self.calls
        ))
        escalate.assert_not_called()
        self.assertTrue(any(
            "base branch policy prohibits the merge" in call.args[0] for call in log.call_args_list
        ))
        self.assertEqual(self.rows("merged"), [])

        [decision] = [row for row in self.rows("decision") if row.get("stage") == "merge"]
        self.assertEqual(decision["chosen"], "merge blocked")
        self.assertEqual(decision["pr"], 70)
        self.assertIn(HEAD, [i["ref"].rsplit("/", 1)[-1] for i in decision["inputs"] if i["kind"] == "head"])

        waits = [
            row for row in lifecycle.read_events(self.events)
            if row.get("event") == "lifecycle" and row.get("kind") == "wait"
        ]
        self.assertEqual(waits[-1]["wait"]["reason"], "merge_blocked")
        self.assertEqual(waits[-1]["wait"]["mode"], "eligibility")

    def test_successful_merge_still_records_merged(self) -> None:
        escalate, _ = self.merge_pass(None)

        escalate.assert_not_called()
        [merged] = self.rows("merged")
        self.assertEqual(
            {key: merged[key] for key in ("ticket", "pr", "method", "head")},
            {"ticket": 7, "pr": 70, "method": "squash", "head": HEAD},
        )
        self.assertTrue(any(cmd[:3] == ["gh", "pr", "merge"] for cmd in self.calls))
        self.assertEqual(self.rows("decision")[-1]["chosen"], "merge now")

    def test_other_merge_failures_still_raise(self) -> None:
        with self.assertRaises(subprocess.CalledProcessError):
            self.merge_pass("X Something else broke the merge.\n")


if __name__ == "__main__":
    unittest.main()
