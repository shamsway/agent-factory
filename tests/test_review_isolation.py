"""Reviewers start outside any worker-written checkout so project config cannot execute."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from factory import config, dispatch

# Like agent CLIs: run .omp/startup.py found in cwd or an ancestor, then report the environment.
PROBE = """
import json, os, sys
from pathlib import Path
cwd = Path.cwd().resolve()
for d in (cwd, *cwd.parents):
    startup = d / ".omp" / "startup.py"
    if startup.is_file():
        exec(compile(startup.read_text(), str(startup), "exec"))
        break
json.dump({"cwd": str(cwd), "git": [k for k in os.environ if k.startswith("GIT_")]},
          open(sys.argv[1], "w"))
print("VERDICT: APPROVE")
"""


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


class ReviewIsolationTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name).resolve()
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "config", "user.email", "t@example.com")
        git(self.repo, "config", "user.name", "t")
        (self.repo / "README.md").write_text("base\n")
        git(self.repo, "add", "README.md")
        git(self.repo, "commit", "-q", "-m", "base")
        git(self.repo, "update-ref", "refs/remotes/origin/main", "HEAD")
        self.sentinel = self.tmp / "sentinel"
        startup = self.repo / ".omp" / "startup.py"
        startup.parent.mkdir()
        startup.write_text(f"open({str(self.sentinel)!r}, 'w').write('ran')\n")
        git(self.repo, "add", ".omp")
        git(self.repo, "commit", "-q", "-m", "worker")
        self.head = git(self.repo, "rev-parse", "HEAD")
        # A linked ticket worktree distinct from the root, as the dispatcher uses.
        self.wt = self.tmp / "wt-7"
        git(self.repo, "worktree", "add", "-q", "--detach", str(self.wt), self.head)
        self.out = self.tmp / "seen.json"
        self.cfg = config.Config(root=self.repo, repo="acme/widgets",
                                 reviewer=[sys.executable, "-c", PROBE, str(self.out)])
        dispatch.configure(self.cfg)
        self.cfg.factory.mkdir(exist_ok=True)
        env = mock.patch.dict(os.environ, {"GIT_DIR": str(self.repo / ".git"), "GIT_WORK_TREE": str(self.repo)})
        env.start()
        self.addCleanup(env.stop)

    def assert_isolated(self) -> None:
        self.assertFalse(self.sentinel.exists(), "reviewer executed worker-written startup file")
        seen = json.loads(self.out.read_text())
        cwd = Path(seen["cwd"])
        for checkout in (self.repo, self.wt):
            self.assertNotIn(checkout, (cwd, *cwd.parents))
        self.assertEqual(seen["git"], [])

    def test_positive_control_probe_runs_startup_inside_checkout(self) -> None:
        subprocess.run([sys.executable, "-c", PROBE, str(self.out)], cwd=self.repo, check=True)
        self.assertTrue(self.sentinel.exists())

    def test_ticket_review_starts_outside_checkout(self) -> None:
        verdict, _ = dispatch.review(self.wt, 7, "PASS", self.head)
        self.assertEqual(verdict, "APPROVE")
        self.assert_isolated()

    def test_failed_snapshot_fails_the_review_closed(self) -> None:
        real = subprocess.run

        def run(cmd, *args, **kwargs):
            if cmd[:2] == ["git", "archive"]:
                raise subprocess.CalledProcessError(128, cmd, b"", b"fatal: not a valid object")
            return real(cmd, *args, **kwargs)

        with mock.patch.object(dispatch.subprocess, "run", side_effect=run):
            verdict, _ = dispatch.review(self.wt, 7, "PASS", self.head)
        self.assertNotEqual(verdict, "APPROVE")
        self.assertFalse(self.sentinel.exists())

    def test_external_pr_review_starts_outside_checkout(self) -> None:
        real_run = dispatch.run

        def run(cmd, **kwargs):
            if cmd[0] == "gh":
                return subprocess.CompletedProcess(cmd, 0, "diff", "")
            return real_run(cmd, **kwargs)

        with mock.patch.object(dispatch, "run", side_effect=run):
            dispatch.review_external_pr(17, "base", self.head)
        self.assert_isolated()


if __name__ == "__main__":
    unittest.main()
