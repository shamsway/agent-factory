"""Factory's own git commands and the gate ignore worker-planted Git state.

Disposable repositories only. Each test first shows the planted state does what an
attacker wants under plain git (so the fixture would catch a regression), then that
the dispatcher's guarded calls and the gate do not honor it.

Run: python -m unittest tests.test_gitguard
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from factory import config, dashboard, dispatch, gitguard
from tests.test_factory import git

TOML = ('[gate]\nprotected_paths = [".factory.toml", "policy/*"]\n'
        '[leak_scan]\npattern = "SENTINEL_[A-Z]+"\n')


class Checkout:
    """A main checkout with a fake `origin/main` and two ticket worktrees under .factory/."""

    def __init__(self, tmp: Path) -> None:
        self.root = tmp / "root"
        self.root.mkdir()
        git(self.root, "init", "-q", "-b", "main")
        git(self.root, "config", "user.email", "t@example.com")
        git(self.root, "config", "user.name", "T")
        git(self.root, "remote", "add", "origin", "git@github.com:acme/widgets.git")
        (self.root / ".factory.toml").write_text(TOML)
        (self.root / "policy").mkdir()
        (self.root / "policy" / "rules.txt").write_text("v1\n")
        (self.root / ".gitignore").write_text(".factory/\n")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "v1")
        self.v1 = git(self.root, "rev-parse", "HEAD")
        (self.root / "policy" / "rules.txt").write_text("v2\n")
        git(self.root, "commit", "-q", "-am", "v2")
        self.base = git(self.root, "rev-parse", "HEAD")
        git(self.root, "update-ref", "refs/remotes/origin/main", "HEAD")
        (self.root / ".factory").mkdir()
        self.wt = self.root / ".factory" / "wt-1"
        git(self.root, "worktree", "add", "-q", str(self.wt), "-b", "agent/1", "origin/main")
        git(self.root, "worktree", "add", "-q", str(self.root / ".factory" / "wt-2"), "-b", "agent/2", "origin/main")
        self.admin = self.root / ".git" / "worktrees" / "wt-1"

    def commit(self, message: str = "work") -> str:
        git(self.wt, "add", "-A")
        git(self.wt, "commit", "-q", "-m", message)
        return git(self.wt, "rev-parse", "HEAD")


class GitGuardTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        self.tmp = tmp
        self.c = Checkout(tmp)
        self.marker = tmp / "planted-command-ran"
        dispatch.configure(config.load(self.c.root))

    def planted_gitdir(self, where: Path) -> Path:
        """A copy of wt-1's Git state whose config runs a command on the next index refresh."""
        shutil.copytree(self.c.root / ".git", where)
        with (where / "config").open("a") as f:
            f.write(f'[core]\n\tfsmonitor = "touch {self.marker}; false"\n')
        return where

    def assert_guarded_calls_ignore_plant(self) -> None:
        plain = subprocess.run(["git", "status", "--porcelain"], cwd=self.c.wt, capture_output=True, check=False)
        self.assertTrue(self.marker.exists(), "fixture: plain git should honor the planted state")
        self.assertEqual(plain.returncode, 0)
        self.marker.unlink()
        guarded = dispatch.run(["git", "status", "--porcelain"], cwd=self.c.wt, check=False)
        dispatch._activity(self.c.wt, self.tmp / "log", self.tmp / "handoff")
        with mock.patch.object(dashboard, "ROOT", self.c.root, create=True):
            dashboard.sh(["git", "status", "--porcelain"], cwd=self.c.wt)
        dispatch.commit_leftovers(self.c.wt, 1, "leftovers")
        self.assertFalse(self.marker.exists())
        self.assertEqual(guarded.returncode, 0, guarded.stderr)

    def test_worktree_git_pointer_redirect_is_ignored(self) -> None:
        evil = self.planted_gitdir(self.c.wt / "planted")
        (self.c.wt / ".git").write_text(f"gitdir: {evil}\n")
        self.assert_guarded_calls_ignore_plant()

    def test_worktree_git_directory_replacement_is_ignored(self) -> None:
        (self.c.wt / ".git").unlink()
        self.planted_gitdir(self.c.wt / ".git")
        (self.c.wt / ".git" / "config").write_text(
            f'[core]\n\trepositoryformatversion = 0\n\tfsmonitor = "touch {self.marker}; false"\n')
        self.assert_guarded_calls_ignore_plant()

    def test_admin_commondir_redirect_is_ignored(self) -> None:
        evil = self.planted_gitdir(self.tmp / "planted-common")
        (self.c.admin / "commondir").write_text(f"{evil}\n")
        self.assert_guarded_calls_ignore_plant()

    def test_unresolved_worktree_fails_closed(self) -> None:
        (self.c.admin / "gitdir").write_text(str(self.tmp / "elsewhere" / ".git") + "\n")
        proc = dispatch.run(["git", "rev-parse", "HEAD"], cwd=self.c.wt, check=False)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(gitguard.UNRESOLVED, gitguard.env(self.c.root, self.c.wt)["GIT_DIR"])

    def test_checks_and_other_cwds_get_no_pinned_paths(self) -> None:
        env = gitguard.env(self.c.root, self.c.wt, {"PATH": "/bin"})
        self.assertEqual(env["GIT_WORK_TREE"], str(self.c.wt.resolve()))
        self.assertEqual(env["GIT_DIR"], str(self.c.admin.resolve()))
        self.assertEqual(gitguard.strip(env), {"PATH": "/bin"})
        root_env = gitguard.env(self.c.root, self.c.root, {})
        self.assertEqual(root_env, gitguard.HARDENED)

    def gate(self, **kwargs) -> tuple[bool, str]:
        return dispatch.run_gate(self.c.wt, 1, **kwargs)

    def test_forged_baseline_ref_does_not_move_the_captured_base(self) -> None:
        captured = dispatch.trusted_rev("origin/main")
        self.assertEqual(captured, self.c.base)
        (self.c.wt / "policy" / "rules.txt").write_text("unlocked\n")
        head = self.c.commit()
        git(self.c.wt, "update-ref", "refs/remotes/origin/main", head)  # what a wide-open sandbox allowed
        self.assertTrue(self.gate(base="origin/main", skip="leak-scan")[0], "fixture: forged ref hides the edit")
        ok, report = self.gate(base=captured, skip="leak-scan")
        self.assertFalse(ok)
        self.assertIn("- protected-paths: FAIL", report)

    def test_replace_ref_cannot_swap_the_base_policy(self) -> None:
        (self.c.wt / ".factory.toml").write_text("[gate]\nprotected_paths = []\n")
        (self.c.wt / "policy" / "rules.txt").write_text("unlocked\n")
        head = self.c.commit()
        fake = git(self.c.wt, "commit-tree", f"{head}^{{tree}}", "-p", self.c.v1, "-m", "fake base")
        git(self.c.wt, "replace", self.c.base, fake)
        plain = git(self.c.root, "show", f"{self.c.base}:.factory.toml")
        self.assertNotIn("policy/*", plain, "fixture: replace ref swaps the base policy")
        ok, report = self.gate(base=self.c.base, skip="leak-scan")
        self.assertFalse(ok)
        self.assertIn("- protected-paths: FAIL", report)

    def test_grafts_cannot_move_the_merge_base(self) -> None:
        (self.c.wt / "policy" / "rules.txt").write_text("v1\n")  # revert main's v2 policy
        head = self.c.commit()
        # Quiet the deprecation hint so plain git would honor the graft silently.
        git(self.c.root, "config", "advice.graftFileDeprecated", "false")
        (self.c.root / ".git" / "info").mkdir(exist_ok=True)
        (self.c.root / ".git" / "info" / "grafts").write_text(f"{head} {self.c.v1}\n")
        merge_base = subprocess.run(["git", "merge-base", self.c.base, head], cwd=self.c.root,
                                    capture_output=True, text=True, check=False).stdout.strip()
        self.assertEqual(merge_base, self.c.v1, "fixture: the graft moves the merge base")
        ok, report = self.gate(base=self.c.base, skip="leak-scan")
        self.assertFalse(ok)
        self.assertIn("- protected-paths: FAIL", report)
        self.assertIn("-v2\n+v1", report)

    def test_gitattributes_cannot_hide_added_lines_from_the_leak_scan(self) -> None:
        token = "SENTINEL_" + "VALUE"
        (self.c.wt / "notes.txt").write_text(f"key = {token}\n")
        (self.c.wt / ".gitattributes").write_text("notes.txt -diff\n")
        head = self.c.commit()
        plain = git(self.c.wt, "diff", "--unified=0", f"{self.c.base}..{head}")
        self.assertNotIn(token, plain, "fixture: -diff hides the line from a plain diff")
        ok, report = self.gate(base=self.c.base)
        self.assertFalse(ok)
        self.assertIn("- leak-scan: FAIL", report)


class DetachedWorkerTest(unittest.TestCase):
    def test_worker_commits_on_a_detached_head_land_on_its_branch(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        c = Checkout(tmp)
        dispatch.configure(config.load(c.root))
        branch = dispatch._detach(c.wt)
        self.assertEqual(branch, "refs/heads/agent/1")
        self.assertEqual(subprocess.run(["git", "symbolic-ref", "-q", "HEAD"], cwd=c.wt, check=False).returncode, 1)
        (c.wt / "work.txt").write_text("done\n")
        head = c.commit()
        (c.wt / "leftover.txt").write_text("uncommitted\n")
        dispatch._reattach(c.wt, branch)
        self.assertEqual(git(c.wt, "symbolic-ref", "HEAD"), "refs/heads/agent/1")
        self.assertEqual(git(c.root, "rev-parse", "agent/1"), head)
        self.assertIn("leftover.txt", git(c.wt, "status", "--porcelain"))
        self.assertEqual(git(c.root, "rev-parse", "agent/2"), c.base)


if __name__ == "__main__":
    unittest.main()
