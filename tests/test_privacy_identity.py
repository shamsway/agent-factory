"""scripts/privacy-check.py --range also checks commit author and committer identities.

Synthetic fixtures only: the protected term is assembled at runtime, and every
repository lives in a throwaway temporary directory. No network.

Run: python -m unittest tests.test_privacy_identity
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "privacy-check.py"
TERM = "zz" + "codename" + "qq"           # stands in for a private operator domain
CLEAN = ("Tester", "t@example.com")


def run_git(cwd: Path, *args: str, env: dict[str, str] | None = None) -> str:
    proc = subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True,
                          env={**os.environ, **(env or {})}, check=True)
    return proc.stdout.strip()


class PrivacyIdentityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.denylist = self.tmp / "denylist"
        self.denylist.write_text(f"# private terms\n\\b{TERM}\\b\n")
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        run_git(self.repo, "init", "-q", "-b", "main")
        self.counter = 0
        self.commit(CLEAN, CLEAN, "base", "base.txt")

    def check(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, str(SCRIPT), "--denylist", str(self.denylist), *args],
                              cwd=self.repo, capture_output=True, text=True, check=False)

    def commit(self, author: tuple[str, str], committer: tuple[str, str], message: str,
               name: str | None = None) -> str:
        """Commit one new file with the given identities; return the full sha."""
        self.counter += 1
        (self.repo / (name or f"file{self.counter}.txt")).write_text(f"line {self.counter}\n")
        run_git(self.repo, "add", "-A")
        env = {
            "GIT_AUTHOR_NAME": author[0], "GIT_AUTHOR_EMAIL": author[1],
            "GIT_COMMITTER_NAME": committer[0], "GIT_COMMITTER_EMAIL": committer[1],
        }
        run_git(self.repo, "commit", "-q", "-m", message, env=env)
        return run_git(self.repo, "rev-parse", "HEAD")

    def test_matching_author_and_committer_fail_and_are_named(self) -> None:
        run_git(self.repo, "checkout", "-q", "-b", "work")
        author_sha = self.commit(("Tester", f"ops@{TERM}.example.invalid"), CLEAN, "by matching author")
        committer_sha = self.commit(CLEAN, (f"Ops {TERM}", "ops@example.invalid"), "by matching committer")

        proc = self.check("--range", "main...work")

        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn(f"commit {author_sha[:12]} author:1: denylist rule 2", proc.stdout)
        self.assertIn(f"commit {committer_sha[:12]} committer:1: denylist rule 2", proc.stdout)
        self.assertNotIn(f"commit {author_sha[:12]} committer", proc.stdout)
        self.assertNotIn(f"commit {committer_sha[:12]} author", proc.stdout)
        self.assertNotIn(TERM, proc.stdout)

    def test_clean_identity_passes(self) -> None:
        run_git(self.repo, "checkout", "-q", "-b", "work")
        self.commit(CLEAN, CLEAN, "clean commit")

        proc = self.check("--range", "main...work")

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("privacy-check: clean", proc.stdout)

    def test_matching_identity_reachable_from_published_is_skipped(self) -> None:
        run_git(self.repo, "checkout", "-q", "-b", "upstream")
        upstream_sha = self.commit(("Upstream", f"dev@{TERM}.example.invalid"), CLEAN, "upstream commit")
        run_git(self.repo, "checkout", "-q", "-b", "work", "upstream")
        self.commit(CLEAN, CLEAN, "fork commit")

        unpublished = self.check("--range", "main...work")
        self.assertEqual(unpublished.returncode, 1, unpublished.stdout)
        self.assertIn(f"commit {upstream_sha[:12]} author:1: denylist rule 2", unpublished.stdout)

        published = self.check("--range", "main...work", "--published", "upstream")
        self.assertEqual(published.returncode, 0, published.stdout + published.stderr)
        self.assertIn("privacy-check: clean", published.stdout)
        self.assertNotIn(TERM, published.stdout)


if __name__ == "__main__":
    unittest.main()
