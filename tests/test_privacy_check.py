"""scripts/privacy-check.py with synthetic fixtures only.

The protected strings below are assembled at runtime so this file's own diff
passes the check it tests; real operator terms live only in a private denylist.

Run: python -m unittest tests.test_privacy_check
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.test_factory import git

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "privacy-check.py"
TERM = "zz" + "codename" + "qq"           # stands in for a private hostname
ADDRESS = "192." + "168.7.9"              # a private IPv4 address
HOME = "/ho" + "me/" + "alice/src"        # a user home path


class PrivacyCheckTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(subprocess.run, ["rm", "-rf", str(self.tmp)], check=False)
        self.denylist = self.tmp / "denylist"
        self.denylist.write_text(f"# private terms\n\\b{TERM}\\b\n")
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "config", "user.email", "t@example.com")
        git(self.repo, "config", "user.name", "T")
        (self.repo / "old.txt").write_text(f"pre-existing {TERM}\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "base")

    def check(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, str(SCRIPT), "--denylist", str(self.denylist), *args],
                              cwd=self.repo, capture_output=True, text=True, check=False)

    def commit(self, files: dict[str, str], message: str = "change") -> None:
        for name, text in files.items():
            (self.repo / name).write_text(text)
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", message)

    def test_added_lines_messages_and_branch_are_checked_and_masked(self) -> None:
        self.commit({"new.txt": f"ok\nhost {TERM} at {ADDRESS}\npath {HOME}\n"}, f"deploy to {TERM}")
        proc = self.check("--range", "HEAD~1...HEAD", "--branch", f"fix/{TERM}-thing")
        self.assertEqual(proc.returncode, 1)
        out = proc.stdout
        self.assertIn("new.txt:2: denylist rule 2", out)
        self.assertIn("new.txt:2: private IPv4 address", out)
        self.assertIn("new.txt:3: user home path", out)
        self.assertIn("message", out)
        self.assertIn("branch name:1: denylist rule 2", out)
        self.assertNotIn("old.txt", out)  # unchanged lines are not this change's findings
        for secret in (TERM, ADDRESS, HOME):
            self.assertNotIn(secret, out)

    def test_clean_change_passes_and_generic_paths_are_allowed(self) -> None:
        self.commit({"new.txt": "see /home/runner/work and /home/<user>/.config, 203.0.113.5\n"})
        proc = self.check("--range", "HEAD~1...HEAD", "--branch", "fix/generic-name")
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("privacy-check: clean", proc.stdout)

    def test_text_files_and_tree_report_existing_exposure(self) -> None:
        body = self.tmp / "pr.md"
        body.write_text(f"Rolled out on {TERM}.\n")
        self.assertEqual(self.check("--text", str(body)).returncode, 1)
        tree = self.check("--tree")
        self.assertEqual(tree.returncode, 1)
        self.assertIn("old.txt:1: denylist rule 2", tree.stdout)

    def test_missing_explicit_denylist_is_an_error(self) -> None:
        proc = subprocess.run([sys.executable, str(SCRIPT), "--denylist", str(self.tmp / "absent"), "--tree"],
                              cwd=self.repo, capture_output=True, text=True, check=False)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("not found", proc.stderr)


if __name__ == "__main__":
    unittest.main()
