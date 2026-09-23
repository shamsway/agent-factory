"""Legacy `agent_factory` import-path compatibility: module identity, shared state,
and the old `python -m agent_factory.tf_plan_check` entrypoint.

Run: python -m unittest discover -s tests
"""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class LegacyImportCompatTest(unittest.TestCase):
    def test_version_matches(self) -> None:
        import agent_factory
        import factory

        self.assertEqual(agent_factory.__version__, factory.__version__)

    def test_submodules_are_the_same_object_not_a_copy(self) -> None:
        """A proxy that copies globals (e.g. `from factory.dispatch import *`) would
        diverge the moment either side's module-level state changes. These must be
        the identical module object, not a lookalike."""
        import factory.apply
        import factory.config
        import factory.deploy
        import factory.dispatch
        import factory.verify_secrets

        import agent_factory.apply
        import agent_factory.config
        import agent_factory.deploy
        import agent_factory.dispatch
        import agent_factory.verify_secrets

        self.assertIs(agent_factory.config, factory.config)
        self.assertIs(agent_factory.dispatch, factory.dispatch)
        self.assertIs(agent_factory.apply, factory.apply)
        self.assertIs(agent_factory.deploy, factory.deploy)
        self.assertIs(agent_factory.verify_secrets, factory.verify_secrets)

    def test_from_import_style_also_resolves_the_same_object(self) -> None:
        from agent_factory import config as legacy_config
        from factory import config as canonical_config

        self.assertIs(legacy_config, canonical_config)

    def test_state_set_through_one_import_path_is_visible_through_the_other(self) -> None:
        """The concrete failure a copied-globals proxy would produce: configure()
        through one name, read the result through the other."""
        import factory.dispatch

        import agent_factory.dispatch

        from factory.config import Config

        sentinel = Config(root=ROOT, repo="acme/sentinel-widgets")
        agent_factory.dispatch.configure(sentinel)
        try:
            self.assertIs(factory.dispatch.cfg, sentinel)
            self.assertEqual(factory.dispatch.REPO, "acme/sentinel-widgets")
        finally:
            factory.dispatch.configure(Config(root=ROOT, repo="acme/widgets"))

    def test_tf_plan_check_entrypoint_forwards_argv(self) -> None:
        env = {"PYTHONPATH": str(ROOT)}
        import os

        env = {**os.environ, **env}
        legacy = subprocess.run(
            [sys.executable, "-m", "agent_factory.tf_plan_check", "--help"],
            capture_output=True, text=True, env=env,
        )
        canonical = subprocess.run(
            [sys.executable, "-m", "factory.tf_plan_check", "--help"],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(legacy.returncode, 0, legacy.stderr)
        self.assertEqual(legacy.returncode, canonical.returncode)
        self.assertEqual(legacy.stdout, canonical.stdout)


if __name__ == "__main__":
    unittest.main()
