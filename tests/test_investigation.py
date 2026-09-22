"""`ready-for-investigation` lane: report-only scheduling, human handoff, and
dedup against `ready-for-agent`.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from factory import config  # noqa: E402

from tests.test_factory import make_repo  # noqa: E402


class InvestigationLaneTest(unittest.TestCase):
    def test_frontier_queries_the_given_label(self) -> None:
        from unittest import mock

        from factory import dispatch

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d))
            dispatch.configure(config.load(repo))
            with mock.patch.object(dispatch, "gh_json", return_value=[]) as gh_mock:
                dispatch.frontier(config.LABEL_INVESTIGATE)
            gh_mock.assert_called_once_with(
                ["issue", "list", "--repo", dispatch.REPO, "--state", "open",
                 "--label", config.LABEL_INVESTIGATE, "--json", "number,title,body,labels,assignees"]
            )

    def test_dry_run_reports_investigation_short_path_without_admission(self) -> None:
        from unittest import mock

        from factory import dispatch

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d))
            dispatch.configure(config.load(repo))
            issue = {
                "number": 7, "title": "why is prod slow",
                "labels": [{"name": config.LABEL_INVESTIGATE}], "assignees": [],
            }
            with mock.patch.object(dispatch, "initiative_kind", return_value=False), \
                 mock.patch.object(dispatch, "admit_plan") as admit_plan, \
                 mock.patch.object(dispatch, "log") as log_mock:
                dispatch.process_ticket(issue, budget_min=60, dry_run=True)
            admit_plan.assert_not_called()
            message = " ".join(str(c) for c in log_mock.call_args_list)
            self.assertIn("run investigation worker, post findings, route to human", message)

    def test_investigation_lane_runs_short_path_and_skips_implementation_pipeline(self) -> None:
        from unittest import mock

        from factory import dispatch

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d))
            dispatch.configure(config.load(repo))
            wt = dispatch.FACTORY / "wt-7"
            wt.mkdir(parents=True)
            issue = {
                "number": 7, "title": "why is prod slow",
                "labels": [{"name": config.LABEL_INVESTIGATE}], "assignees": [],
            }
            fresh = {
                "state": "OPEN", "labels": [{"name": config.LABEL_INVESTIGATE}],
                "assignees": [], "title": "why is prod slow", "body": "", "comments": [],
            }
            calls: list[list[str]] = []

            def fake_run(cmd, cwd=None, check=True, **kw):
                calls.append(cmd)
                import subprocess
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            with mock.patch.object(dispatch, "gh_json", side_effect=[fresh]), \
                 mock.patch("factory.plan.is_initiative", return_value=False), \
                 mock.patch.object(dispatch, "run", side_effect=fake_run), \
                 mock.patch.object(dispatch, "ensure_worktree", return_value=wt), \
                 mock.patch.object(dispatch, "build_prompt", return_value="prompt") as build_prompt_mock, \
                 mock.patch.object(dispatch, "run_worker", return_value=0) as run_worker_mock, \
                 mock.patch.object(dispatch, "finish_investigation") as finish_mock, \
                 mock.patch.object(dispatch, "admit_plan") as admit_plan_mock, \
                 mock.patch.object(dispatch, "push_and_pr") as push_and_pr_mock, \
                 mock.patch.object(dispatch, "review") as review_mock, \
                 mock.patch.object(dispatch, "worker_round") as worker_round_mock:
                dispatch.process_ticket(issue, budget_min=60, dry_run=False)

            # Claimed like any ticket, but never went through plan admission,
            # the implementation attempt loop, a PR, or review.
            admit_plan_mock.assert_not_called()
            worker_round_mock.assert_not_called()
            push_and_pr_mock.assert_not_called()
            review_mock.assert_not_called()

            build_prompt_mock.assert_called_once_with(7, wt, investigation=True)
            run_worker_mock.assert_called_once()
            finish_mock.assert_called_once()
            self.assertEqual(finish_mock.call_args[0][0], 7)
            self.assertEqual(finish_mock.call_args[0][1], wt)

            self.assertIn(["gh", "issue", "edit", "7", "--repo", dispatch.REPO, "--add-assignee", "@me"], calls)
            self.assertTrue(any(c[:4] == ["git", "worktree", "remove", "--force"] for c in calls))
            self.assertTrue(any(c[:3] == ["git", "branch", "-D"] and c[3] == "agent/7" for c in calls))

    def test_finish_investigation_posts_findings_and_routes_to_human(self) -> None:
        from unittest import mock

        from factory import dispatch

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d))
            dispatch.configure(config.load(repo))
            wt = dispatch.FACTORY / "wt-7"
            (wt / ".factory").mkdir(parents=True)
            (wt / ".factory" / "handoff-7.md").write_text("root cause: connection pool exhaustion\n")
            calls: list[list[str]] = []

            def fake_run(cmd, cwd=None, check=True, **kw):
                calls.append(cmd)
                import subprocess
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            with mock.patch.object(dispatch, "run", side_effect=fake_run):
                dispatch.finish_investigation(7, wt, None)

            comment = next(c for c in calls if c[:3] == ["gh", "issue", "comment"])
            self.assertIn("connection pool exhaustion", comment[comment.index("--body") + 1])
            edit = next(c for c in calls if c[:3] == ["gh", "issue", "edit"])
            self.assertIn("--remove-assignee", edit)
            self.assertIn(config.LABEL_INVESTIGATE, edit[edit.index("--remove-label") + 1])
            self.assertIn(config.LABEL_HUMAN, edit[edit.index("--add-label") + 1])
            events = [
                __import__("json").loads(line) for line in dispatch.EVENTS.read_text().splitlines()
            ]
            self.assertEqual(events[-1]["event"], "investigated")
            self.assertEqual(events[-1]["ticket"], 7)

    def test_finish_investigation_escalates_when_no_findings_report(self) -> None:
        from unittest import mock

        from factory import dispatch

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d))
            dispatch.configure(config.load(repo))
            wt = dispatch.FACTORY / "wt-7"
            wt.mkdir(parents=True)  # no .factory/handoff-7.md written
            with mock.patch.object(dispatch, "escalate") as escalate_mock:
                dispatch.finish_investigation(7, wt, None)
            escalate_mock.assert_called_once()
            self.assertEqual(escalate_mock.call_args[0][0], 7)
            self.assertIn("no findings", escalate_mock.call_args[0][1])

    def test_main_dedups_tickets_carrying_both_labels(self) -> None:
        from unittest import mock

        from factory import dispatch

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d))
            cfg = config.load(repo)
            cfg.max_active = 5  # isolate dedup from capacity truncation
            both = {"number": 9, "title": "both labels", "labels": [], "assignees": []}
            agent_only = {"number": 10, "title": "agent only", "labels": [], "assignees": []}
            investigate_only = {"number": 11, "title": "investigate only", "labels": [], "assignees": []}

            def fake_frontier(label=config.LABEL_AGENT):
                if label == config.LABEL_AGENT:
                    return [both, agent_only]
                return [both, investigate_only]

            processed: list[int] = []

            with mock.patch.object(dispatch, "config") as config_mock, \
                 mock.patch.object(dispatch, "land_pass"), \
                 mock.patch.object(dispatch, "review_intake_pass"), \
                 mock.patch("factory.manage.manage_pass"), \
                 mock.patch.object(dispatch, "active_ticket_count", return_value=0), \
                 mock.patch.object(dispatch, "frontier", side_effect=fake_frontier), \
                 mock.patch.object(dispatch, "process_ticket", side_effect=lambda issue, *a, **kw: processed.append(issue["number"])):
                config_mock.load.return_value = cfg
                dispatch.main(["--dry-run"])

            # #9 carries both labels: it's queued once, from the agent (first-queried) lane.
            self.assertEqual(processed, [9, 10, 11])


if __name__ == "__main__":
    unittest.main()
