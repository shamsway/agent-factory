"""scripts/bwrap-sandbox.sh under real bubblewrap, against disposable checkouts.

Needs Linux with a usable `bwrap`; skipped otherwise, and a failure when
FACTORY_REQUIRE_ISOLATION=1 (CI) or FACTORY_REQUIRE_SANDBOX=1 (scripts/test-linux.sh).
The fake home holds a synthetic sentinel only.

Run: python -m unittest tests.test_sandbox
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from factory import config, dispatch
from tests.test_factory import git
from tests.test_gitguard import Checkout

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "bwrap-sandbox.sh"
SENTINEL = "sentinel-operator-credential"


def require_bwrap(test: unittest.TestCase) -> None:
    required = "1" in (os.environ.get("FACTORY_REQUIRE_ISOLATION"), os.environ.get("FACTORY_REQUIRE_SANDBOX"))
    usable = sys.platform == "linux" and shutil.which("bwrap") and subprocess.run(
        ["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--unshare-pid", "true"],
        capture_output=True, check=False).returncode == 0
    if not usable:
        if required:
            test.fail("required Linux bubblewrap boundary unavailable")
        test.skipTest("requires Linux bubblewrap")


class SandboxTest(unittest.TestCase):
    def setUp(self) -> None:
        require_bwrap(self)
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        self.c = Checkout(tmp)
        self.home = tmp / "home"
        (self.home / ".config" / "op").mkdir(parents=True)
        (self.home / ".config" / "op" / "token").write_text(SENTINEL)
        self.env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(self.home),
                    "GH_TOKEN": SENTINEL, "FAKE_TOKEN": SENTINEL}
        transcripts = self.c.root / ".factory" / "transcripts"
        for n in ("1", "2"):
            (transcripts / n).mkdir(parents=True)
            (transcripts / n / "session.jsonl").write_text(f"ticket {n}\n")
        (self.c.root / ".factory" / "events.jsonl").write_text("{}\n")
        dispatch.configure(config.load(self.c.root))

    def sandbox(self, script: str, cwd: Path | None = None, *extra: str) -> subprocess.CompletedProcess:
        cwd = cwd or self.c.wt
        return subprocess.run(
            [str(SCRIPT), "--cwd", str(cwd), "--root", str(self.c.root), "--drop-env", "FAKE_TOKEN", *extra,
             "--", "bash", "-c", script],
            env=self.env, capture_output=True, text=True, check=False)

    def ok(self, script: str, cwd: Path | None = None) -> str:
        proc = self.sandbox(script, cwd)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return proc.stdout

    def fails(self, script: str, cwd: Path | None = None) -> None:
        proc = self.sandbox(script, cwd)
        self.assertNotEqual(proc.returncode, 0, f"sandbox allowed: {script}\n{proc.stdout}{proc.stderr}")

    def test_current_ticket_commits_on_its_detached_head(self) -> None:
        branch = dispatch._detach(self.c.wt)
        self.ok("echo done > work.txt && git add work.txt && git commit -qm work")
        head = git(self.c.wt, "rev-parse", "HEAD")
        dispatch._reattach(self.c.wt, branch)
        self.assertEqual(git(self.c.root, "rev-parse", "agent/1"), head)
        self.assertEqual(git(self.c.root, "rev-parse", "agent/2"), self.c.base)

    def test_shared_refs_and_other_tickets_metadata_are_read_only(self) -> None:
        dispatch._detach(self.c.wt)
        self.ok("echo x > f && git add f && git commit -qm x")
        common = self.c.root / ".git"
        before = {p: p.read_bytes() for p in common.rglob("*")
                  if p.is_file() and "objects" not in p.parts and "wt-1" not in p.parts}
        for attempt in (
            "git update-ref refs/remotes/origin/main HEAD",
            "git update-ref refs/heads/agent/2 HEAD",
            "git branch planted HEAD",
            "git tag planted",
            "git replace $(git rev-parse origin/main) HEAD",
            f"echo $(git rev-parse HEAD) > {common}/info/grafts",
            f"echo $(git rev-parse HEAD) > {common}/shallow",
            f"echo planted >> {common}/packed-refs",
            f"echo planted >> {common}/config",
            f"echo planted > {common}/hooks/post-commit",
            f"echo ref: refs/heads/main > {common}/worktrees/wt-2/HEAD",
            f"echo {self.c.root}/elsewhere > {common}/worktrees/wt-2/commondir",
            "echo more >> f && git stash",
        ):
            with self.subTest(attempt=attempt):
                self.fails(attempt)
        after = {p: p.read_bytes() for p in before if p.exists()}
        self.assertEqual(after, before)
        self.assertFalse((common / "info" / "grafts").exists())
        self.assertEqual(git(self.c.root, "rev-parse", "origin/main"), self.c.base)

    def test_root_cwd_keeps_factory_state_hidden_and_git_read_only(self) -> None:
        listing = self.ok(f"ls -A {self.c.root}/.factory", cwd=self.c.root)
        self.assertEqual(listing.split(), [])
        self.fails(f"touch {self.c.root}/.git/planted", cwd=self.c.root)
        self.fails("git update-ref refs/heads/planted HEAD", cwd=self.c.root)

    def test_bind_order_hides_other_tickets_and_keeps_own_transcripts(self) -> None:
        listing = self.ok(f"ls -A {self.c.root}/.factory {self.c.root}/.factory/transcripts")
        self.assertIn("wt-1", listing)
        for hidden in ("wt-2", "events.jsonl", "2"):
            self.assertNotIn(hidden, listing.split())
        self.assertEqual(self.ok(f"cat {self.c.root}/.factory/transcripts/1/session.jsonl"), "ticket 1\n")
        self.ok(f"echo more >> {self.c.root}/.factory/transcripts/1/session.jsonl")
        self.fails(f"cat {self.c.root}/.factory/transcripts/2/session.jsonl")
        self.assertEqual((self.c.root / ".factory" / "transcripts" / "1" / "session.jsonl").read_text(),
                         "ticket 1\nmore\n")

    def test_symlinks_do_not_reach_hidden_or_read_only_paths(self) -> None:
        self.ok(f"ln -s {self.home}/.config/op/token token-link && "
                f"ln -s {self.c.root}/.git/refs/remotes/origin/main base-link && "
                f"ln -s {self.c.root}/.factory/wt-2 sibling-link")
        self.fails("cat token-link")
        self.fails("echo 0000000000000000000000000000000000000000 > base-link")
        self.fails("ls sibling-link/")
        self.assertEqual(git(self.c.root, "rev-parse", "origin/main"), self.c.base)
        # A symlinked --cwd resolves to the real worktree: same boundary.
        alias = self.c.root.parent / "alias"
        alias.symlink_to(self.c.wt)
        self.assertEqual(self.ok("pwd", cwd=alias).strip(), str(self.c.wt.resolve()))
        self.fails(f"cat {self.c.root}/.factory/transcripts/2/session.jsonl", cwd=alias)

    def test_credentials_and_environment_are_withheld(self) -> None:
        out = self.ok(f"ls -A {self.home}; echo \"gh=${{GH_TOKEN:-}} fake=${{FAKE_TOKEN:-}}\"")
        self.assertNotIn(SENTINEL, out)
        self.assertNotIn(".config", out)

    def test_sigkilled_plan_in_the_sandbox_leaves_nothing_on_the_host(self) -> None:
        import json
        import signal
        import time

        from tests.test_tf_plan_check import FAKE_TERRAFORM
        from tests.test_tf_plan_check import SENTINEL as PLAN_SECRET

        bin_dir = self.c.wt / "fakebin"  # inside the worktree: visible in the sandbox
        bin_dir.mkdir()
        (bin_dir / "terraform").write_text(FAKE_TERRAFORM.format(python=sys.executable, secret=PLAN_SECRET))
        (bin_dir / "terraform").chmod(0o755)
        (self.c.wt / "tf").mkdir()
        seen = self.c.wt / "seen.json"
        host_temp = Path(tempfile.gettempdir())
        before = {p.name for p in host_temp.glob("factory-tfplan-*")}
        source = Path(__file__).resolve().parents[1]
        env = {**self.env, "PATH": f"{bin_dir}:{self.env['PATH']}", "FAKE_TF": "sleep",
               "FAKE_TF_SEEN": str(seen), "PYTHONPATH": str(source)}
        proc = subprocess.Popen(
            [str(SCRIPT), "--cwd", str(self.c.wt), "--root", str(self.c.root), "--ro", str(source), "--",
             sys.executable, "-m", "factory.tf_plan_check", "--dir", "tf"],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, start_new_session=True)
        self.addCleanup(proc.kill)
        deadline = time.monotonic() + 30
        while not seen.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        plan = Path(json.loads(seen.read_text())["path"])
        self.assertEqual(plan.parts[1], "tmp")  # the sandbox's private /tmp
        os.killpg(proc.pid, signal.SIGKILL)  # what the gate's timeout does to a wrapped check
        proc.communicate(timeout=30)
        self.assertFalse(plan.exists())
        self.assertFalse(plan.parent.exists())
        self.assertEqual({p.name for p in host_temp.glob("factory-tfplan-*")}, before)


if __name__ == "__main__":
    unittest.main()
