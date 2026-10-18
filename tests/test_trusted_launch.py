"""The dispatcher's gate launch runs the engine, never worker-written Python.

A ticket worktree is worker-controlled. `python -m factory gate` from it would import
a planted `factory` module first, unwrapped and with the dispatcher's environment;
`launch.factory_argv` must not. Fixtures are disposable repositories and a fake
sentinel credential; nothing real is read.

Run: python -m unittest tests.test_trusted_launch
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from factory import config, dispatch, launch, release
from tests.test_factory import XDG, git, host_file, make_repo

SENTINEL = "sentinel-dispatcher-credential"
# Each planted file records that it ran, and which credential it could see.
PLANT = "import os, pathlib\npathlib.Path({marker!r}).write_text(os.environ.get('FAKE_DISPATCHER_TOKEN', ''))\n"


class TrustedGateLaunchTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(subprocess.run, ["rm", "-rf", str(tmp)], check=False)
        self.markers = tmp / "markers"
        self.markers.mkdir()
        self.repo = make_repo(tmp, "")
        self.env = {**os.environ, "FAKE_DISPATCHER_TOKEN": SENTINEL, "XDG_CONFIG_HOME": str(XDG)}
        self.env.pop("PYTHONSAFEPATH", None)

    def plant(self, layout: str) -> None:
        """Worker-written import-path and startup-hook files in the worktree."""
        code = PLANT.format(marker=str(self.markers / layout))
        if layout == "module":
            (self.repo / "factory.py").write_text(code)
        else:
            (self.repo / "factory").mkdir()
            (self.repo / "factory" / "__init__.py").write_text(code)
            (self.repo / "factory" / "__main__.py").write_text(code)
        for hook in ("sitecustomize", "usercustomize"):
            (self.repo / f"{hook}.py").write_text(PLANT.format(marker=str(self.markers / hook)))
        (self.repo / "startup.py").write_text(PLANT.format(marker=str(self.markers / "startup")))

    def ran(self) -> dict[str, str]:
        return {p.name: p.read_text() for p in self.markers.iterdir()}

    def test_plain_module_launch_imports_the_planted_module(self) -> None:
        # The vulnerable form: proves the fixture would catch a regression.
        for layout in ("module", "package"):
            with self.subTest(layout=layout):
                self.plant(layout)
                subprocess.run([sys.executable, "-m", "factory", "gate"], cwd=self.repo, env=self.env,
                               capture_output=True, text=True, check=False)
                self.assertEqual(self.ran().get(layout), SENTINEL)
                subprocess.run(["rm", "-rf", "factory", "factory.py"], cwd=self.repo, check=True)
                for marker in self.markers.iterdir():
                    marker.unlink()

    def test_run_gate_runs_the_engine_not_planted_modules_or_startup_hooks(self) -> None:
        for layout in ("module", "package"):
            with self.subTest(layout=layout):
                self.plant(layout)
                hostile = {**self.env, "PYTHONPATH": str(self.repo), "PYTHONSTARTUP": str(self.repo / "startup.py"),
                           "PYTHONINSPECT": "", "PYTHONUSERBASE": str(self.repo)}
                dispatch.configure(config.load(self.repo))
                with mock.patch.dict(os.environ, hostile, clear=True):
                    ok, report = dispatch.run_gate(self.repo, 7, skip="leak-scan")
                self.assertEqual(self.ran(), {})
                self.assertTrue(ok, report)
                self.assertIn("- conflict-markers: PASS", report)
                subprocess.run(["rm", "-rf", "factory", "factory.py"], cwd=self.repo, check=True)

    def test_launch_is_isolated_and_pins_this_package(self) -> None:
        argv = launch.factory_argv("gate")
        self.assertEqual(argv[:2], [sys.executable, "-I"])
        self.assertEqual(Path(argv[4]), Path(config.__file__).resolve().parent.parent)
        probe = subprocess.run([*argv[:5], "--version"], cwd=self.repo, env=self.env,
                               capture_output=True, text=True, check=False)
        self.assertEqual(probe.returncode, 0, probe.stderr)

    def test_configured_checks_stay_inside_check_wrap_on_every_tier(self) -> None:
        log = self.markers.parent / "wrap.log"
        host_file(f'[defaults.check_wrap]\ncommand = ["sh", "-c", "echo \\"$*\\" >> {log}; exec \\"$@\\"", "wrap"]\n')
        self.addCleanup(host_file, "")
        (self.repo / config.CONFIG_NAME).write_text(
            "".join(f'[[gate.check]]\nname = "{tier}-check"\nrun = ["true", "{tier}"]\n'
                    + (f'when = "{tier}"\n' if tier != "attempt" else "") for tier in ("attempt", "pr", "release")))
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "checks")
        git(self.repo, "update-ref", "refs/remotes/origin/main", "HEAD")
        self.plant("module")
        dispatch.configure(config.load(self.repo))
        with mock.patch.dict(os.environ, self.env, clear=True):
            for tier in ("attempt", "pr", "release"):
                ok, report = dispatch.run_gate(self.repo, f"t-{tier}", tier=tier, skip="leak-scan")
                self.assertTrue(ok, report)
            self.assertTrue(release.gate_passes(self.repo))
        self.assertEqual(self.ran(), {})
        self.assertEqual(log.read_text().splitlines(),
                         ["true attempt", "true pr", "true release", "true release"])


if __name__ == "__main__":
    unittest.main()
