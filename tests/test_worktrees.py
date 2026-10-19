"""Finished tickets' worktrees are removed only when nothing in flight or unpushed is lost."""

from __future__ import annotations

import contextlib
import fcntl
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from factory import config, dispatch, lifecycle, worktrees
from tests.test_factory import factory, git, make_repo, stub_bin


def closed_issue(n: int, **extra: object) -> dict:
    return {"number": n, "state": "CLOSED", "labels": [], "assignees": [], **extra}


class WorktreeRetentionTest(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.enterContext(mock.patch.dict(os.environ, {lifecycle.CONTEXT_ENV: ""}))
        self.out = self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        self.repo = make_repo(Path(temp.name))
        self.cfg = config.Config(root=self.repo, repo="acme/widgets")
        self.cfg.factory.mkdir()
        self.events = self.cfg.factory / "events.jsonl"
        self.enterContext(mock.patch.multiple(
            dispatch, create=True, cfg=self.cfg, ROOT=self.cfg.root, REPO=self.cfg.repo,
            UPSTREAM=None, UPSTREAM_REPO=None, FACTORY=self.cfg.factory, LOGS=self.cfg.factory / "logs",
            SYNC_LOG=self.cfg.factory / "upstream-sync.jsonl", EVENTS=self.events,
            MAX_ACTIVE=1, MAX_ATTEMPTS=self.cfg.max_attempts,
        ))
        self.issues: dict[int, dict] = {}
        self.prs: dict[int, list[dict]] = {}
        self.calls: list[list[str]] = []
        self.enterContext(mock.patch.object(dispatch, "gh_json", side_effect=self.gh_json))

    def gh_json(self, args: list[str], env: dict | None = None) -> object:
        self.calls.append(args)
        if args[:2] == ["issue", "list"]:
            return [{k: i[k] for k in ("number", "labels", "assignees")}
                    for i in self.issues.values() if i["state"] == "OPEN"]
        if args[:2] == ["pr", "list"] and "--head" not in args:
            return [{"number": pr["number"], "headRefName": f"agent/{n}"}
                    for n, prs in self.prs.items() for pr in prs if pr["state"] == "OPEN"]
        if args[:2] == ["issue", "view"]:
            return self.issues[int(args[2])]
        if args[:2] == ["pr", "list"]:
            return self.prs.get(int(args[args.index("--head") + 1].removeprefix("agent/")), [])
        raise AssertionError(f"unexpected gh call {args}")

    def worktree(self, n: int, *, commit: bool = True, push: bool = True) -> tuple[Path, str]:
        """`.factory/wt-<n>` on `agent/<n>`, one commit ahead of main (pushed to origin/agent/<n>)."""
        wt = self.cfg.factory / f"wt-{n}"
        git(self.repo, "worktree", "add", "-q", str(wt), "-b", f"agent/{n}", "origin/main")
        if commit:
            (wt / f"change-{n}.txt").write_text(f"payload-{n}\n")
            git(wt, "add", f"change-{n}.txt")
            git(wt, "commit", "-q", "-m", f"agent/{n}: work")
        head = git(wt, "rev-parse", "HEAD")
        if push:
            git(self.repo, "update-ref", f"refs/remotes/origin/agent/{n}", head)
        # Ignored scratch: the handoff, gate report and prompt never make a worktree dirty.
        (wt / ".factory").mkdir()
        (wt / ".factory" / f"gate-report-{n}.md").write_text("PASS\n")
        (wt / ".factory-prompt.md").write_text("prompt\n")
        return wt, head

    def finished(self, n: int, head: str, state: str = "MERGED") -> None:
        self.issues[n] = closed_issue(n)
        self.prs[n] = [{"number": n + 100, "state": state, "headRefOid": head}]

    def rows(self, event: str) -> list[dict]:
        return [r for r in lifecycle.read_events(self.events) if r.get("event") == event]

    def decision(self, result: dict, n: int) -> dict:
        return next(d for d in result["decisions"] if d["ticket"] == n)

    def test_finished_clean_worktree_is_removed_and_transcripts_kept(self) -> None:
        merged = 7
        wt_m, head_m = self.worktree(merged)
        closed, _ = self.worktree(8, push=False)  # closed PR, never pushed: the branch keeps the head
        head_c = git(closed, "rev-parse", "HEAD")
        self.finished(merged, head_m)
        self.finished(8, "f" * 40, state="CLOSED")
        transcript = self.cfg.factory / "transcripts" / str(merged) / "s.jsonl"
        transcript.parent.mkdir(parents=True)
        transcript.write_text("{}\n")
        log = self.cfg.factory / "logs" / f"{merged}-attempt-1.log"
        log.parent.mkdir()
        log.write_text("worker output\n")

        result = worktrees.sweep(dry_run=False)

        self.assertEqual(self.decision(result, merged)["action"], "removed")
        self.assertFalse(wt_m.exists())
        self.assertTrue(transcript.is_file())
        self.assertTrue(log.is_file())
        self.assertNotIn(str(wt_m), git(self.repo, "worktree", "list"))
        # The merged branch's tip is pushed: deleted, as cleanup_after_merge does.
        self.assertEqual(git(self.repo, "branch", "--list", f"agent/{merged}"), "")
        # The closed ticket's unpushed head lives on in its kept branch.
        self.assertEqual(self.decision(result, 8)["action"], "removed")
        self.assertEqual(self.decision(result, 8)["branch"], "keep")
        self.assertEqual(git(self.repo, "rev-parse", "agent/8"), head_c)
        removed = {r["ticket"]: r for r in self.rows("worktree-removed")}
        self.assertEqual(set(removed), {merged, 8})
        self.assertEqual(removed[merged]["path"], f".factory/wt-{merged}")
        self.assertEqual((removed[merged]["head"], removed[merged]["branch"]), (head_m, "deleted"))
        self.assertGreater(removed[merged]["bytes"], 0)
        self.assertNotIn("payload", json.dumps(removed[merged]))  # metadata only

    def test_accepted_handoff_is_retained_before_removal(self) -> None:
        wt, head = self.worktree(9)
        (wt / ".factory" / "handoff-9.md").write_text("what changed\n")
        self.finished(9, head)
        dispatch.record("approved", ticket=9, pr=109, head=head, gate_head=head, review_head=head)
        with mock.patch.object(dispatch, "retain_handoff", return_value=False) as retain:
            result = worktrees.sweep(dry_run=False)
        retain.assert_called_once_with(9, head)
        self.assertEqual(self.decision(result, 9)["code"], "retention_incomplete")
        self.assertTrue(wt.is_dir())
        with mock.patch.object(dispatch, "retain_handoff", return_value=True):
            result = worktrees.sweep(dry_run=False)
        self.assertEqual(self.decision(result, 9)["action"], "removed")
        self.assertEqual(self.rows("worktree-removed")[0]["retained_head"], head)

    def test_unscored_handoff_keeps_the_worktree_until_scored(self) -> None:
        wt, head = self.worktree(10)
        (wt / ".factory" / "handoff-10.md").write_text("escalated notes\n")
        self.finished(10, head, state="CLOSED")
        transcript = self.cfg.factory / "transcripts" / "10" / "s.jsonl"
        transcript.parent.mkdir(parents=True)
        transcript.write_text("{}\n")
        dispatch.record("attempt", ticket=10, attempt=1, transcript=str(transcript), gate="FAIL")
        dispatch.record("escalate", ticket=10, code="gate_failed")
        result = worktrees.sweep(dry_run=False)
        self.assertEqual(self.decision(result, 10)["code"], "evidence")
        self.assertIn("factory score", self.decision(result, 10)["reason"])
        self.assertTrue(wt.is_dir())
        dispatch.record("score", ticket=10, attempt=1, transcript=str(transcript))
        self.assertEqual(self.decision(worktrees.sweep(dry_run=False), 10)["action"], "removed")

    def test_in_flight_tickets_are_kept(self) -> None:
        assigned, _ = self.worktree(11)
        lane, _ = self.worktree(12)
        locked, head = self.worktree(13)
        open_pr, _ = self.worktree(14)
        self.issues[11] = {**closed_issue(11), "state": "OPEN", "assignees": [{"login": "bot"}]}
        self.prs[11] = [{"number": 111, "state": "CLOSED", "headRefOid": head}]
        self.issues[12] = {**closed_issue(12), "state": "OPEN", "labels": [{"name": config.LABEL_HUMAN}]}
        self.prs[12] = [{"number": 112, "state": "CLOSED", "headRefOid": head}]
        self.finished(13, head)
        self.issues[14] = closed_issue(14)
        self.prs[14] = [{"number": 114, "state": "OPEN", "headRefOid": head}]
        with dispatch.ticket_lock(13).open("w") as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = worktrees.sweep(dry_run=False)
        for n, wt in ((11, assigned), (12, lane), (13, locked), (14, open_pr)):
            d = self.decision(result, n)
            self.assertEqual((d["action"], d["code"], d["stale"]), ("keep", "in_flight", False), d)
            self.assertTrue(wt.is_dir())
        self.assertIn("assigned", self.decision(result, 11)["reason"])
        self.assertIn(config.LABEL_HUMAN, self.decision(result, 12)["reason"])
        self.assertIn("lock", self.decision(result, 13)["reason"])
        self.assertEqual(self.rows("worktree-removed"), [])
        self.assertEqual(self.rows("worktree-kept"), [])  # in flight is not stale
        # In-flight tickets cost no per-ticket GitHub reads.
        self.assertFalse([c for c in self.calls if c[:2] == ["issue", "view"]])
        # An open issue outside every lane with no PR at all is not finished either.
        self.issues[11] = {**closed_issue(11), "state": "OPEN"}
        self.prs[11] = []
        self.assertEqual(self.decision(worktrees.sweep(dry_run=False), 11)["code"], "in_flight")

    def test_dirty_or_unpushed_worktree_of_a_closed_ticket_is_kept_and_reported(self) -> None:
        dirty, _ = self.worktree(15, push=False)
        (dirty / "notes.txt").write_text("uncommitted\n")
        detached, _ = self.worktree(16, push=False)
        git(detached, "checkout", "-q", "--detach")
        (detached / "extra.txt").write_text("x\n")
        git(detached, "add", "extra.txt")
        git(detached, "commit", "-q", "-m", "detached work")
        self.finished(15, "e" * 40, state="CLOSED")
        self.finished(16, "e" * 40, state="CLOSED")
        result = worktrees.sweep(dry_run=False)
        d15, d16 = self.decision(result, 15), self.decision(result, 16)
        self.assertEqual((d15["action"], d15["code"], d15["stale"]), ("keep", "dirty", True))
        self.assertIn("1 uncommitted or untracked path(s)", d15["reason"])
        self.assertIn("not pushed", d15["reason"])
        self.assertEqual((d16["action"], d16["code"]), ("keep", "unpushed"))
        self.assertTrue(dirty.is_dir() and detached.is_dir())
        kept = self.rows("worktree-kept")
        self.assertEqual(sorted((r["ticket"], r["code"]) for r in kept), [(15, "dirty"), (16, "unpushed")])
        # Kept rows repeat at most daily for the same reason.
        worktrees.sweep(dry_run=False)
        self.assertEqual(len(self.rows("worktree-kept")), 2)
        self.assertEqual(worktrees.counts(result)["kept"], 2)

    def test_dry_run_removes_nothing_and_reports_every_decision(self) -> None:
        wt, head = self.worktree(17)
        dirty, _ = self.worktree(18, push=False)
        (dirty / "notes.txt").write_text("uncommitted\n")
        self.finished(17, head)
        self.finished(18, "e" * 40, state="CLOSED")
        self.issues[19] = {**closed_issue(19), "state": "OPEN", "labels": [{"name": config.LABEL_AGENT}]}
        self.worktree(19)
        before = (git(self.repo, "worktree", "list"), git(self.repo, "branch", "--list"))
        with mock.patch.object(config, "load", return_value=self.cfg):
            self.assertEqual(worktrees.main(["--dry-run"]), 0)
            text = self.out.getvalue()
            self.out.seek(0)
            self.out.truncate()
            self.assertEqual(worktrees.main(["--dry-run", "--json"]), 0)
            report = json.loads(self.out.getvalue())
        self.assertTrue(wt.is_dir())
        self.assertEqual((git(self.repo, "worktree", "list"), git(self.repo, "branch", "--list")), before)
        self.assertFalse(self.events.exists())
        self.assertIn("dry run", text)
        self.assertRegex(text, r"would remove\s+#17\s+\.factory/wt-17\s+\d")
        self.assertRegex(text, r"keep \(stale\)\s+#18 .*dirty")
        self.assertRegex(text, r"keep\s+#19 .*in flight: issue open in lane ready-for-agent")
        self.assertIn("1 to remove, 1 stale but kept, 1 in flight, 0 unchecked", text)
        self.assertTrue(report["dry_run"])
        self.assertEqual(report["summary"], {"removable": 1, "kept": 1, "in_flight": 1, "unchecked": 0})
        self.assertEqual(self.decision(report, 17)["branch"], "delete")

    def test_dispatcher_pass_is_bounded(self) -> None:
        for n in range(20, 20 + worktrees.AUTO_LIMIT + 2):
            _, head = self.worktree(n)
            self.finished(n, head)
        worktrees.dispatcher_pass(dry_run=False)
        self.assertEqual(len(self.rows("worktree-removed")), worktrees.AUTO_LIMIT)
        self.assertEqual(len([c for c in self.calls if c[:2] == ["issue", "view"]]), worktrees.AUTO_LIMIT)
        worktrees.dispatcher_pass(dry_run=False)
        self.assertEqual(len(self.rows("worktree-removed")), worktrees.AUTO_LIMIT + 2)

    def test_doctor_row_counts_removable_and_kept(self) -> None:
        self.assertEqual(worktrees.doctor_row(self.cfg), (True, "no ticket worktrees"))
        for n in (30, 31):
            _, head = self.worktree(n)
            self.finished(n, head)
        dirty, _ = self.worktree(32, push=False)
        (dirty / "notes.txt").write_text("uncommitted\n")
        self.finished(32, "e" * 40, state="CLOSED")
        self.worktree(33)
        self.issues[33] = {**closed_issue(33), "state": "OPEN", "assignees": [{"login": "bot"}]}
        status, detail = worktrees.doctor_row(self.cfg)
        self.assertIsNone(status)  # WARN, never FAIL
        self.assertIn("2 removable", detail)
        self.assertIn("1 stale but kept: #32 dirty", detail)
        self.assertIn("1 in flight", detail)
        self.assertTrue((self.cfg.factory / "wt-30").is_dir())
        self.assertFalse(self.events.exists())

    def test_github_failure_removes_nothing(self) -> None:
        wt, head = self.worktree(40)
        self.finished(40, head)
        with mock.patch.object(dispatch, "gh_json", side_effect=ValueError("bad json")):
            result = worktrees.sweep(dry_run=False)
        self.assertTrue(wt.is_dir())
        self.assertIn("GitHub unavailable", result["error"])
        self.assertEqual(worktrees.counts(result)["unchecked"], 1)


class WorktreeCliTest(unittest.TestCase):
    GH = """case "$1 $2" in
  "repo view") echo ADMIN;;
  "label list"|"issue list") echo "[]";;
  "issue view") echo '{"number": 1, "state": "CLOSED", "labels": [], "assignees": []}';;
  "pr list") case "$*" in *--head*) echo '[{"number": 5, "state": "MERGED", "headRefOid": ""}]';; *) echo "[]";; esac;;
esac
exit 0"""

    def test_doctor_and_dry_run_report_stale_worktrees(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d))
            stubs = stub_bin(Path(d), gh=self.GH, systemctl="echo inactive")

            def row() -> dict:
                rows = json.loads(factory(repo, "doctor", "--json", path=stubs).stdout)["rows"]
                return next(r for r in rows if r["label"] == "stale ticket worktrees")

            self.assertEqual(row()["status"], "PASS")
            git(repo, "worktree", "add", "-q", str(repo / ".factory" / "wt-1"), "-b", "agent/1", "main")
            git(repo, "worktree", "add", "-q", str(repo / ".factory" / "wt-2"), "-b", "agent/2", "main")
            (repo / ".factory" / "wt-2" / "notes.txt").write_text("uncommitted\n")
            r = row()
            self.assertEqual(r["status"], "WARN")
            self.assertIn("1 removable", r["detail"])
            self.assertIn("1 stale but kept: #2 dirty", r["detail"])
            proc = factory(repo, "prune-worktrees", "--dry-run", path=stubs)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertRegex(proc.stdout, r"would remove\s+#1\s+\.factory/wt-1")
            self.assertTrue((repo / ".factory" / "wt-1").is_dir())


if __name__ == "__main__":
    unittest.main()
