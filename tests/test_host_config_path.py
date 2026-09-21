"""The single host-config-path resolver (docs/upstream-migration-plan.md,
Section 4): old-only, new-only, both/distinct, neither, malformed preferred
config, dangling links, custom XDG_CONFIG_HOME, and writer behavior.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from factory import config  # noqa: E402


class HostConfigPathTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.xdg = Path(temporary.name)
        self._prior_xdg = os.environ.get("XDG_CONFIG_HOME")
        os.environ["XDG_CONFIG_HOME"] = str(self.xdg)
        self.addCleanup(self._restore_xdg)
        self.new_path = self.xdg / "factory" / "config.toml"
        self.old_path = self.xdg / "agent-factory" / "config.toml"

    def _restore_xdg(self) -> None:
        if self._prior_xdg is None:
            os.environ.pop("XDG_CONFIG_HOME", None)
        else:
            os.environ["XDG_CONFIG_HOME"] = self._prior_xdg

    def test_neither_present_selects_new_default_path(self) -> None:
        self.assertEqual(config.host_config_path(), self.new_path)
        self.assertEqual(config.host_config(), {})

    def test_old_only_falls_back_to_old_path(self) -> None:
        self.old_path.parent.mkdir(parents=True)
        self.old_path.write_text('[defaults.triage]\nurl = "http://old/v1/chat/completions"\n')
        self.assertEqual(config.host_config_path(), self.old_path)
        self.assertEqual(
            config.host_config()["defaults"]["triage"]["url"], "http://old/v1/chat/completions"
        )

    def test_new_only_selects_new_path(self) -> None:
        self.new_path.parent.mkdir(parents=True)
        self.new_path.write_text('[defaults.triage]\nurl = "http://new/v1/chat/completions"\n')
        self.assertEqual(config.host_config_path(), self.new_path)
        self.assertEqual(
            config.host_config()["defaults"]["triage"]["url"], "http://new/v1/chat/completions"
        )

    def test_both_distinct_prefers_new_over_old(self) -> None:
        self.old_path.parent.mkdir(parents=True)
        self.old_path.write_text('[defaults.triage]\nurl = "http://old/v1/chat/completions"\n')
        self.new_path.parent.mkdir(parents=True)
        self.new_path.write_text('[defaults.triage]\nurl = "http://new/v1/chat/completions"\n')
        self.assertEqual(config.host_config_path(), self.new_path)
        self.assertEqual(
            config.host_config()["defaults"]["triage"]["url"], "http://new/v1/chat/completions"
        )

    def test_malformed_preferred_config_raises_instead_of_falling_back(self) -> None:
        """A broken new-path file must surface as a loud error, never a silent
        slide back to the old path's (possibly stale) content."""
        self.old_path.parent.mkdir(parents=True)
        self.old_path.write_text('[defaults.triage]\nurl = "http://old/v1/chat/completions"\n')
        self.new_path.parent.mkdir(parents=True)
        self.new_path.write_text("not [ valid toml")
        self.assertEqual(config.host_config_path(), self.new_path)
        with self.assertRaises(config.ConfigError):
            config.host_config()

    def test_dangling_preferred_symlink_is_an_error_not_a_fallback(self) -> None:
        self.old_path.parent.mkdir(parents=True)
        self.old_path.write_text('[defaults.triage]\nurl = "http://old/v1/chat/completions"\n')
        self.new_path.parent.mkdir(parents=True)
        self.new_path.symlink_to(self.new_path.parent / "does-not-exist.toml")
        self.assertEqual(config.host_config_path(), self.new_path)
        with self.assertRaises(config.ConfigError):
            config.host_config()

    def test_dangling_old_symlink_is_selected_and_raises_when_new_is_absent(self) -> None:
        self.old_path.parent.mkdir(parents=True)
        self.old_path.symlink_to(self.old_path.parent / "does-not-exist.toml")
        self.assertEqual(config.host_config_path(), self.old_path)
        with self.assertRaises(config.ConfigError):
            config.host_config()

    def test_custom_xdg_config_home_is_honored(self) -> None:
        other = self.xdg / "elsewhere"
        os.environ["XDG_CONFIG_HOME"] = str(other)
        expected = other / "factory" / "config.toml"
        self.assertEqual(config.host_config_path(), expected)

    def test_writer_behavior_reads_and_saves_correctly_against_old_path_only(self) -> None:
        """settings.py's state/save machinery must work unchanged whether the
        resolver landed on the old or new host path -- it only ever calls the
        one resolver, never constructs the path itself."""
        from factory import settings

        self.old_path.parent.mkdir(parents=True)
        self.old_path.write_text('[defaults.triage]\nurl = "http://old/v1/chat/completions"\n')

        with tempfile.TemporaryDirectory() as d:
            from tests.test_factory import make_repo

            repo = make_repo(Path(d))
            snapshot = settings._snapshot(repo)
            self.assertEqual(snapshot["ok"], True)
            revision = snapshot["revision"]
            result = settings.save(repo, {"revision": revision, "changes": {}})
            self.assertTrue(result["ok"], result)


if __name__ == "__main__":
    unittest.main()
