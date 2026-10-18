"""tf_plan_check pure-function and CLI checks.

Run: python -m unittest discover -s tests
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import ClassVar


class TfPlanCheckTest(unittest.TestCase):
    """Pure-function checks against a canned `terraform show -json` shape;
    no terraform binary needed."""

    def test_run_plan_passes_env_to_both_subprocess_calls(self) -> None:
        """apply_env()'s credentials (e.g. OP_SERVICE_ACCOUNT_TOKEN) were
        computed but never actually passed to the plan subprocess -- run_plan
        had no env parameter at all, always inheriting the calling process's
        plain environment. Confirmed live: factory apply's fresh re-plan
        401'd against 1Password's interactive desktop-app flow because of
        this, even with apply_env() correctly populated. env=None (the
        gate's own CLI use, which already has install.env baked into its
        process by the dispatcher's systemd unit) must keep inheriting."""
        from unittest import mock

        from factory import tf_plan_check

        calls = []

        def fake_run(cmd, cwd=None, capture_output=None, text=None, env=None):
            calls.append(env)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        with mock.patch("subprocess.run", side_effect=fake_run):
            tf_plan_check.run_plan(Path("/tmp"), Path("/tmp/plan"), env={"FAKE": "1"})
        self.assertEqual(calls, [{"FAKE": "1"}, {"FAKE": "1"}])

        calls.clear()
        with mock.patch("subprocess.run", side_effect=fake_run):
            tf_plan_check.run_plan(Path("/tmp"), Path("/tmp/plan"))
        self.assertEqual(calls, [None, None])

    CLEAN_PLAN: ClassVar[dict] = {
        "resource_changes": [
            {"address": "aws_instance.foo", "change": {"actions": ["no-op"]}},
            {"address": "aws_s3_bucket.logs", "change": {"actions": ["create"]}},
        ]
    }
    DESTRUCTIVE_PLAN: ClassVar[dict] = {
        "resource_changes": [
            {"address": "aws_instance.foo", "change": {"actions": ["no-op"]}},
            {"address": "aws_instance.bar", "change": {"actions": ["delete", "create"]}},
            {"address": "aws_db_instance.main", "change": {"actions": ["delete"]}},
        ]
    }

    def test_clean_plan_has_no_destructive_changes(self) -> None:
        from factory import tf_plan_check

        self.assertEqual(tf_plan_check.destructive_changes(self.CLEAN_PLAN), [])
        self.assertEqual(tf_plan_check.unexpected_changes(self.CLEAN_PLAN, ""), [])

    def test_destructive_plan_flags_delete_and_replace(self) -> None:
        from factory import tf_plan_check

        changes = tf_plan_check.destructive_changes(self.DESTRUCTIVE_PLAN)
        self.assertEqual(
            {addr for addr, _ in changes}, {"aws_instance.bar", "aws_db_instance.main"}
        )

    def test_allowed_destroy_line_exempts_one_address(self) -> None:
        from factory import tf_plan_check

        ticket = "Upgrade the DB.\n\nAllowedDestroy: aws_db_instance.main\n"
        unexpected = tf_plan_check.unexpected_changes(self.DESTRUCTIVE_PLAN, ticket)
        self.assertEqual([addr for addr, _ in unexpected], ["aws_instance.bar"])

    def test_no_allow_list_flags_everything_destructive(self) -> None:
        from factory import tf_plan_check

        unexpected = tf_plan_check.unexpected_changes(self.DESTRUCTIVE_PLAN, "no allow lines here")
        self.assertEqual(
            {addr for addr, _ in unexpected}, {"aws_instance.bar", "aws_db_instance.main"}
        )

    def test_plan_out_directory_created_under_dir_not_invocation_cwd(self) -> None:
        """--plan-out is a path relative to --dir (that's what run_plan's
        subprocess, cwd=--dir, actually resolves it against), so the mkdir
        must create it there too -- not relative to wherever the check
        itself happens to be invoked from (the worktree root)."""
        from unittest import mock

        from factory import tf_plan_check

        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d).resolve()
            tf_root = tmp / "terraform" / "collectors"
            tf_root.mkdir(parents=True)
            invocation_cwd = tmp / "worktree-root"
            invocation_cwd.mkdir()

            original_cwd = Path.cwd()
            os.chdir(invocation_cwd)
            self.addCleanup(os.chdir, original_cwd)

            clean_proc = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
            with mock.patch.object(tf_plan_check, "run_plan", return_value=clean_proc) as run_plan, \
                 mock.patch.object(tf_plan_check, "show_json", return_value=self.CLEAN_PLAN):
                rc = tf_plan_check.main(
                    ["--dir", str(tf_root), "--plan-out", ".factory/tfplan"]
                )

            self.assertEqual(rc, 0)
            self.assertTrue((tf_root / ".factory").is_dir())
            self.assertFalse((invocation_cwd / ".factory").exists())
            run_plan.assert_called_once_with(Path(str(tf_root)), Path(".factory/tfplan"))
            self.assertFalse((tf_root / ".factory" / "tfplan").exists())

    def _run_main(self, tf_root: Path, argv: list[str], *, plan_rc: int = 0, show_error: bool = False):
        """Run main() with a fake terraform that writes a real plan file; return (rc or exception, plan path, mode)."""
        from unittest import mock

        from factory import tf_plan_check

        seen: dict = {}

        def fake_plan(cwd, planfile, env=None):
            path = planfile if planfile.is_absolute() else cwd / planfile
            path.write_text("secret-bearing plan\n")
            seen["path"], seen["mode"] = path, path.parent.stat().st_mode & 0o777
            return subprocess.CompletedProcess(args=[], returncode=plan_rc, stdout="", stderr="")

        show = mock.patch.object(tf_plan_check, "show_json", return_value=self.CLEAN_PLAN)
        if show_error:
            show = mock.patch.object(tf_plan_check, "show_json",
                                     side_effect=subprocess.CalledProcessError(1, ["terraform", "show"]))
        with mock.patch.object(tf_plan_check, "run_plan", side_effect=fake_plan), show:
            try:
                result = tf_plan_check.main(["--dir", str(tf_root), *argv])
            except subprocess.CalledProcessError as exc:
                result = exc
        return result, seen["path"], seen["mode"]

    def test_default_plan_is_private_and_removed_whatever_the_outcome(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            tf_root = Path(d).resolve() / "terraform" / "collectors"
            tf_root.mkdir(parents=True)
            for label, kwargs, expect in (("pass", {}, 0), ("plan fails", {"plan_rc": 1}, 1),
                                          ("show fails", {"show_error": True}, 1)):
                with self.subTest(label):
                    result, path, mode = self._run_main(tf_root, [], **kwargs)
                    self.assertEqual(result, expect)
                    self.assertEqual(mode, 0o700)
                    self.assertNotIn(tf_root, path.parents)
                    self.assertFalse(path.exists())
                    self.assertFalse(path.parent.exists())
            self.assertEqual(list(tf_root.rglob("*")), [])

    def test_explicit_plan_out_is_removed_when_show_fails(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            tf_root = Path(d).resolve()
            result, path, mode = self._run_main(tf_root, ["--plan-out", ".factory/tfplan"], show_error=True)
            self.assertEqual(result, 1)
            self.assertEqual(mode, 0o700)
            self.assertEqual(path, tf_root / ".factory" / "tfplan")
            self.assertFalse(path.exists())

SENTINEL = "SENTINEL-PLAN-SECRET"
FAKE_TERRAFORM = '''#!{python}
import json, os, sys, time
args, mode = sys.argv[1:], os.environ.get("FAKE_TF", "ok")
if args[0] == "init":
    if mode == "init-fail":
        print("Error: Failed to query available provider packages\\n\\nprovider said: {secret}")
        sys.exit(1)
    sys.exit(0)
if args[0] == "plan":
    out = os.path.abspath(args[args.index("-out") + 1])
    with open(out, "w") as f:
        f.write("{secret}")
    with open(os.environ["FAKE_TF_SEEN"], "w") as f:
        json.dump({{"path": out, "mode": os.stat(out).st_mode & 0o777,
                   "dir_mode": os.stat(os.path.dirname(out)).st_mode & 0o777}}, f)
    if mode == "sleep":
        time.sleep(120)
    if mode == "plan-fail":
        print("\\u2577\\n\\u2502 Error: Invalid provider configuration\\n\\u2502\\n"
              "\\u2502   on main.tf line 3, in provider \\"x\\":\\n\\u2502 response body: {secret}\\n\\u2575")
        sys.exit(1)
    sys.exit(0)
if args[0] == "show":
    if mode == "show-fail":
        sys.stderr.write("Error: Failed to read plan\\n{secret}\\n")
        sys.exit(1)
    print("{secret} is not json" if mode == "show-badjson" else json.dumps({{"resource_changes": []}}))
'''


class PlanLifecycleTest(unittest.TestCase):
    """The real CLI against a fake terraform that writes a sentinel plan: no plan or
    scratch survives any outcome the check can observe, and no sentinel reaches output."""

    def setUp(self) -> None:
        import shutil
        import sys

        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        tf = self.bin / "terraform"
        tf.write_text(FAKE_TERRAFORM.format(python=sys.executable, secret=SENTINEL))
        tf.chmod(0o755)
        self.temp = self.tmp / "temp"  # the check's TMPDIR: residue is visible here
        self.temp.mkdir()
        self.dir = self.tmp / "repo" / "terraform" / "svc"
        self.dir.mkdir(parents=True)
        self.seen = self.tmp / "seen.json"
        root = Path(__file__).resolve().parents[1]
        self.env = {**os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}", "TMPDIR": str(self.temp),
                    "FAKE_TF_SEEN": str(self.seen), "PYTHONPATH": str(root)}
        self.env.pop("FACTORY_LIFECYCLE_CONTEXT", None)

    def argv(self, *extra: str) -> list[str]:
        import sys

        return [sys.executable, "-m", "factory.tf_plan_check", "--dir", str(self.dir), *extra]

    def plan(self) -> dict:
        import json

        return json.loads(self.seen.read_text())

    def assert_no_residue(self) -> None:
        self.assertFalse(Path(self.plan()["path"]).exists())
        self.assertEqual(list(self.temp.iterdir()), [])

    def test_every_outcome_removes_the_plan_and_withholds_details(self) -> None:
        cases = {"ok": (0, "no destroy/replace"), "plan-fail": (1, "on main.tf line 3"),
                 "show-fail": (1, "Error: Failed to read plan"), "show-badjson": (1, "not JSON")}
        for explicit in (False, True):
            for mode, (code, expected) in cases.items():
                with self.subTest(mode=mode, explicit=explicit):
                    extra = ("--plan-out", ".factory/tfplan") if explicit else ()
                    proc = subprocess.run(self.argv(*extra), env={**self.env, "FAKE_TF": mode},
                                          capture_output=True, text=True, check=False)
                    self.assertEqual(proc.returncode, code, proc.stdout + proc.stderr)
                    self.assertIn(expected, proc.stdout)
                    self.assertNotIn(SENTINEL, proc.stdout + proc.stderr)
                    self.assertEqual(self.plan()["mode"], 0o600)
                    if explicit:
                        self.assertEqual(self.plan()["path"], str(self.dir / ".factory" / "tfplan"))
                        self.assertEqual(self.plan()["dir_mode"], 0o700)
                    else:
                        self.assertEqual(self.plan()["dir_mode"], 0o700)
                        self.assertIn(str(self.temp), self.plan()["path"])
                    self.assert_no_residue()
        proc = subprocess.run(self.argv(), env={**self.env, "FAKE_TF": "init-fail"},
                              capture_output=True, text=True, check=False)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("Error: Failed to query available provider packages", proc.stdout)
        self.assertNotIn(SENTINEL, proc.stdout + proc.stderr)
        self.assertEqual(list(self.temp.iterdir()), [])

    def started(self, extra: tuple[str, ...] = ()) -> subprocess.Popen:
        import time

        self.seen.unlink(missing_ok=True)
        proc = subprocess.Popen(self.argv(*extra), env={**self.env, "FAKE_TF": "sleep"},
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.addCleanup(proc.kill)
        deadline = time.monotonic() + 30
        while not self.seen.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(Path(self.plan()["path"]).exists())
        return proc

    def test_sigterm_removes_the_plan(self) -> None:
        import signal

        for extra in ((), ("--plan-out", ".factory/tfplan")):
            with self.subTest(extra=extra):
                proc = self.started(extra)
                proc.send_signal(signal.SIGTERM)
                out, _ = proc.communicate(timeout=30)
                self.assertEqual(proc.returncode, 128 + signal.SIGTERM, out)
                self.assertIn("plan removed", out)
                self.assert_no_residue()

    def test_sigkilled_explicit_plan_is_cleared_by_the_next_run(self) -> None:
        import signal

        proc = self.started(("--plan-out", ".factory/tfplan"))
        proc.send_signal(signal.SIGKILL)
        proc.communicate(timeout=30)
        left = self.dir / ".factory" / "tfplan"
        self.assertTrue(left.exists())  # the documented limit: no process survives to remove it
        self.assertEqual(left.stat().st_mode & 0o777, 0o600)
        proc = subprocess.run(self.argv("--plan-out", ".factory/tfplan"), env={**self.env, "FAKE_TF": "ok"},
                              capture_output=True, text=True, check=False)
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("removed a plan an interrupted earlier run left", proc.stdout)
        self.assertFalse(left.exists())

    def test_symlinked_plan_out_is_refused(self) -> None:
        target = self.tmp / "elsewhere"
        target.write_text("keep\n")
        (self.dir / ".factory").mkdir()
        (self.dir / ".factory" / "tfplan").symlink_to(target)
        proc = subprocess.run(self.argv("--plan-out", ".factory/tfplan"), env=self.env,
                              capture_output=True, text=True, check=False)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("symlink; refusing", proc.stdout + proc.stderr)
        self.assertEqual(target.read_text(), "keep\n")
        self.assertFalse(self.seen.exists())

    def gate_repo(self, run: list[str], timeout: int = 3) -> Path:
        from tests.test_factory import git, make_repo

        repo = make_repo(self.tmp / "gate", '[[gate.check]]\nname = "tf"\nrun = '
                         + "[" + ", ".join(f'"{a}"' for a in run) + f"]\ntimeout = {timeout}\n")
        (repo / "tf").mkdir()
        (repo / "tf" / "main.tf").write_text("# fake\n")
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", "tf")
        git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
        return repo

    def gate(self, repo: Path, **env: str) -> subprocess.CompletedProcess:
        import sys

        return subprocess.run([sys.executable, "-m", "factory", "gate", "--skip", "leak-scan"], cwd=repo,
                              env={**self.env, **env}, capture_output=True, text=True, check=False)

    def test_gate_timeout_sigkill_leaves_no_default_plan(self) -> None:
        import sys

        (self.tmp / "gate").mkdir()
        repo = self.gate_repo([sys.executable, "-m", "factory.tf_plan_check", "--dir", "tf"])
        proc = self.gate(repo, FAKE_TF="sleep")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("check timed out after 3s", (repo / ".factory" / "gate-report.md").read_text())
        self.assertIn("factory-check-", self.plan()["path"])  # the gate's scratch held it
        self.assert_no_residue()

    def test_gate_sweeps_scratch_a_killed_gate_left(self) -> None:
        dead = subprocess.Popen(["true"])
        dead.wait()
        abandoned = self.temp / f"factory-check-{dead.pid}-x"
        (abandoned / "factory-tfplan-1-y").mkdir(parents=True)
        (abandoned / "factory-tfplan-1-y" / "tfplan").write_text(SENTINEL)
        live = self.temp / f"factory-check-{os.getpid()}-z"
        live.mkdir()
        (self.tmp / "gate").mkdir()
        repo = self.gate_repo(["true"])
        proc = self.gate(repo)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertFalse(abandoned.exists())
        self.assertTrue(live.exists())
        self.assertIn("Removed 1 check scratch dir(s)", (repo / ".factory" / "gate-report.md").read_text())

    def test_doctor_finds_abandoned_plan_dirs_by_name_only(self) -> None:
        from factory import onboard

        (self.temp / "factory-tfplan-123-a").mkdir()
        (self.temp / "factory-check-456-b").mkdir()
        (self.temp / "unrelated").mkdir()
        (self.temp / "factory-tfplan-link").symlink_to(self.temp / "unrelated")
        self.assertEqual(onboard.abandoned_plan_dirs(self.temp), ["factory-check-456-b", "factory-tfplan-123-a"])
        self.assertEqual(onboard.abandoned_plan_dirs(self.temp, limit=0), [])
        repo = self.tmp / "walk"
        for i in range(3):
            (repo / f"d{i}" / ".factory").mkdir(parents=True)
            (repo / f"d{i}" / ".factory" / "tfplan").write_text("plan\n")
        self.assertEqual(len(onboard.leftover_plans(repo)[0]), 3)
        self.assertTrue(onboard.leftover_plans(repo, limit=2)[1])


if __name__ == "__main__":
    unittest.main()
