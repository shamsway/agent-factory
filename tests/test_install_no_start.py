"""`factory install --no-start`: the installation-without-activation contract
(docs/upstream-migration-plan.md, Section 2). Asserts the actual systemctl
call set, not merely the CLI return code, per the plan's explicit requirement.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from factory import config, onboard  # noqa: E402


class NoStartInstallTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / config.CONFIG_NAME).write_text('[repo]\nslug = "acme/widgets"\n')
        self.cfg = config.Config(self.root, "acme/widgets", signoff=False)
        self.cfg.install = {"every": "10min", "dashboard": False, "host": "127.0.0.1", "python": None, "env": {}}
        self.host_path = self.root / "config.toml"
        self.units = self.root / "units"

    def install(self, argv: list[str], *, dashboard_active: str = "inactive") -> tuple[int, list[list[str]]]:
        """Run onboard.install(argv) with systemd/network fully mocked; return
        (exit code, every subprocess argv actually invoked)."""
        calls: list[list[str]] = []

        def command(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
            calls.append(cmd)
            if cmd[:3] == ["systemctl", "--user", "is-active"]:
                return subprocess.CompletedProcess(cmd, 0, f"{dashboard_active}\n", "")
            if cmd[0] == "loginctl":
                return subprocess.CompletedProcess(cmd, 0, "yes\n", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with patch.object(onboard.config, "load", return_value=self.cfg), \
                patch.object(onboard.config, "host_config_path", return_value=self.host_path), \
                patch.object(onboard, "unit_dir", return_value=self.units), \
                patch.object(onboard, "sh", side_effect=command), \
                patch.object(onboard.shutil, "which", return_value="/bin/systemctl"):
            code = onboard.install(argv)
        return code, calls

    @staticmethod
    def mutating_calls(calls: list[list[str]]) -> list[list[str]]:
        """systemctl calls that enable, start, restart, stop, or otherwise change
        enablement links -- everything --no-start's contract forbids."""
        return [
            c for c in calls
            if c[0] == "systemctl" and len(c) > 2 and c[2] in ("enable", "disable", "start", "restart", "stop")
        ]

    def test_new_installation_writes_units_and_reloads_only(self) -> None:
        code, calls = self.install(["--no-start", "--dashboard"])
        self.assertEqual(code, 0)
        self.assertTrue((self.units / "factory-widgets.service").exists())
        self.assertTrue((self.units / "factory-widgets.timer").exists())
        self.assertTrue((self.units / "factory-widgets-dashboard.service").exists())
        self.assertEqual(self.mutating_calls(calls), [])
        self.assertIn(["systemctl", "--user", "daemon-reload"], calls)

    def test_changed_unit_is_rewritten_but_not_restarted(self) -> None:
        self.units.mkdir()
        (self.units / "factory-widgets.service").write_text("stale content\n")
        (self.units / "factory-widgets.timer").write_text("stale content\n")
        code, calls = self.install(["--no-start"])
        self.assertEqual(code, 0)
        self.assertNotEqual((self.units / "factory-widgets.service").read_text(), "stale content\n")
        self.assertEqual(self.mutating_calls(calls), [])

    def test_unchanged_units_are_not_rewritten_and_stay_idempotent(self) -> None:
        first_code, _ = self.install(["--no-start"])
        self.assertEqual(first_code, 0)
        service_before = (self.units / "factory-widgets.service").read_text()
        mtime_before = (self.units / "factory-widgets.service").stat().st_mtime_ns

        second_code, calls = self.install(["--no-start"])
        self.assertEqual(second_code, 0)
        self.assertEqual((self.units / "factory-widgets.service").read_text(), service_before)
        self.assertEqual((self.units / "factory-widgets.service").stat().st_mtime_ns, mtime_before)
        self.assertEqual(self.mutating_calls(calls), [])
        self.assertIn(["systemctl", "--user", "daemon-reload"], calls)

    def test_removes_obsolete_dashboard_unit_when_inactive(self) -> None:
        self.units.mkdir()
        (self.units / "factory-widgets-dashboard.service").write_text("old dashboard unit\n")
        code, calls = self.install(["--no-start"], dashboard_active="inactive")
        self.assertEqual(code, 0)
        self.assertFalse((self.units / "factory-widgets-dashboard.service").exists())
        self.assertEqual(self.mutating_calls(calls), [])
        self.assertIn(["systemctl", "--user", "is-active", "factory-widgets-dashboard.service"], calls)

    def test_refuses_to_remove_active_obsolete_dashboard_unit(self) -> None:
        self.units.mkdir()
        (self.units / "factory-widgets-dashboard.service").write_text("old dashboard unit\n")
        with self.assertRaises(onboard.ConfigError):
            self.install(["--no-start"], dashboard_active="active")
        # The refusal must happen before any mutation: the file survives, untouched.
        self.assertEqual((self.units / "factory-widgets-dashboard.service").read_text(), "old dashboard unit\n")

    def test_never_enables_starts_or_stops_already_active_units(self) -> None:
        """Convergence: units already written, and (per this stub) reported active
        by systemctl, still get no enable/start/restart/stop call under --no-start."""
        first_code, _ = self.install(["--no-start"], dashboard_active="active")
        self.assertEqual(first_code, 0)
        code, calls = self.install(["--no-start"], dashboard_active="active")
        self.assertEqual(code, 0)
        self.assertEqual(self.mutating_calls(calls), [])

    def test_print_and_no_start_are_independent_and_print_never_touches_disk(self) -> None:
        code, calls = self.install(["--print", "--no-start"])
        self.assertEqual(code, 0)
        self.assertEqual(calls, [])
        self.assertFalse(self.units.exists())


if __name__ == "__main__":
    unittest.main()
