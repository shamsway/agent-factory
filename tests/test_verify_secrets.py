"""verify-secrets: unit env parsing and sync-status reporting.

Run: python -m unittest discover -s tests
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from agent_factory import config

from tests.test_factory import make_repo


class VerifySecretsTest(unittest.TestCase):
    def test_parse_environment_lines_ignores_other_unit_content(self) -> None:
        from agent_factory import verify_secrets

        unit_text = (
            "[Unit]\nDescription=agent-factory dispatcher for acme/widgets (one pass)\n\n"
            "[Service]\nType=oneshot\nWorkingDirectory=/home/t/widgets\n"
            "Environment=PATH=/usr/bin:/bin\n"
            "Environment=GH_TOKEN=ghp_abc123\n"
            "Environment=OP_SERVICE_ACCOUNT_TOKEN=ops_xyz==\n"
            "ExecStart=/usr/bin/python3 -m agent_factory dispatch\n"
        )
        self.assertEqual(
            verify_secrets.parse_environment_lines(unit_text),
            {"PATH": "/usr/bin:/bin", "GH_TOKEN": "ghp_abc123", "OP_SERVICE_ACCOUNT_TOKEN": "ops_xyz=="},
        )

    def test_sync_rows_flags_stale_and_missing_against_installed_units(self) -> None:
        """A key whose host-config value has moved on from what's baked into a unit reads STALE
        (the SHA-182 / 2026-09-13 rotation shape); a unit `systemctl` can't find reads not installed."""
        from agent_factory import verify_secrets

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), toml='[install]\nenv = { GH_TOKEN = "new-token", FOO = "bar" }\n')
            cfg = config.load(repo)

        installed = {
            f"{cfg.unit}.service": {"GH_TOKEN": "new-token", "FOO": "bar"},  # in sync
            f"{cfg.unit}-triage.service": {"GH_TOKEN": "old-token", "FOO": "bar"},  # stale
            f"{cfg.unit}-dashboard.service": None,  # never installed
        }
        rows = verify_secrets.sync_rows(cfg, unit_env_fn=lambda unit: installed[unit])

        by_unit_key = {(u, k): s for u, k, s in rows}
        self.assertEqual(by_unit_key[(f"{cfg.unit}.service", "GH_TOKEN")], "in sync")
        self.assertEqual(by_unit_key[(f"{cfg.unit}.service", "FOO")], "in sync")
        self.assertEqual(by_unit_key[(f"{cfg.unit}-triage.service", "GH_TOKEN")], "STALE -- rerun `factory install`")
        self.assertEqual(by_unit_key[(f"{cfg.unit}-dashboard.service", "*")], "not installed")

    def test_main_exits_nonzero_when_any_unit_is_stale(self) -> None:
        from unittest import mock

        from agent_factory import verify_secrets

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), toml='[install]\nenv = { GH_TOKEN = "new-token" }\n')
            original_cwd = Path.cwd()
            os.chdir(repo)
            self.addCleanup(os.chdir, original_cwd)

            def fake_unit_env(unit: str) -> dict[str, str] | None:
                return {"GH_TOKEN": "old-token"}

            with mock.patch.object(verify_secrets, "unit_env", side_effect=fake_unit_env):
                rc = verify_secrets.main([])
            self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
