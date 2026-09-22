"""verify-secrets: unit env parsing and sync-status reporting.

Run: python -m unittest discover -s tests
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from factory import config

from tests.test_factory import make_repo


class VerifySecretsTest(unittest.TestCase):
    def test_parse_environment_lines_ignores_other_unit_content(self) -> None:
        from factory import verify_secrets

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
        (the SHA-182 / 2026-09-13 rotation shape); a unit `systemctl` can't find reads not installed.
        Triage is retired as a standalone unit -- it runs inside the unified dispatcher
        service's `-` prefixed ExecStart -- so only the dispatcher and optional dashboard
        units are checked."""
        from factory import verify_secrets

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), toml='[install]\nenv = { GH_TOKEN = "new-token", FOO = "bar" }\n')
            cfg = config.load(repo)

        installed = {
            f"{cfg.unit}.service": {"GH_TOKEN": "old-token", "FOO": "bar"},  # GH_TOKEN stale
            f"{cfg.unit}-dashboard.service": None,  # never installed
        }
        rows = verify_secrets.sync_rows(cfg, unit_env_fn=lambda unit: installed[unit])

        by_unit_key = {(u, k): s for u, k, s in rows}
        self.assertEqual(by_unit_key[(f"{cfg.unit}.service", "GH_TOKEN")], "STALE -- rerun `factory install`")
        self.assertEqual(by_unit_key[(f"{cfg.unit}.service", "FOO")], "in sync")
        self.assertEqual(by_unit_key[(f"{cfg.unit}-dashboard.service", "*")], "not installed")

    def test_main_exits_nonzero_when_any_unit_is_stale(self) -> None:
        from unittest import mock

        from factory import verify_secrets

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

    def test_main_exits_nonzero_when_dispatcher_unit_is_missing(self) -> None:
        """A dispatcher unit that `systemctl` can't find is a real failure, not a benign
        'not installed' row -- there is nothing running the factory at all."""
        from unittest import mock

        from factory import verify_secrets

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), toml='[install]\nenv = { GH_TOKEN = "tok" }\n')
            original_cwd = Path.cwd()
            os.chdir(repo)
            self.addCleanup(os.chdir, original_cwd)

            with mock.patch.object(verify_secrets, "unit_env", return_value=None):
                rc = verify_secrets.main([])
            self.assertEqual(rc, 1)

    def test_main_tolerates_missing_dashboard_unit_when_dashboard_disabled(self) -> None:
        """The dashboard unit is optional: its absence alone must not fail the check
        when `[install].dashboard` was never turned on."""
        from unittest import mock

        from factory import verify_secrets

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), toml='[install]\nenv = { GH_TOKEN = "tok" }\n')
            cfg = config.load(repo)
            original_cwd = Path.cwd()
            os.chdir(repo)
            self.addCleanup(os.chdir, original_cwd)

            def fake_unit_env(unit: str) -> dict[str, str] | None:
                if unit == f"{cfg.unit}.service":
                    return {"GH_TOKEN": "tok"}
                return None  # dashboard unit not installed

            with mock.patch.object(verify_secrets, "unit_env", side_effect=fake_unit_env):
                rc = verify_secrets.main([])
            self.assertEqual(rc, 0)

    def test_main_exits_nonzero_on_live_auth_failure(self) -> None:
        """`--live` must turn a real credential failure into a nonzero exit, not just print it."""
        from unittest import mock

        from factory import verify_secrets

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), toml='[install]\nenv = { GH_TOKEN = "tok" }\n')
            original_cwd = Path.cwd()
            os.chdir(repo)
            self.addCleanup(os.chdir, original_cwd)

            with mock.patch.object(verify_secrets, "unit_env", return_value={"GH_TOKEN": "tok"}), \
                 mock.patch.dict(verify_secrets.LIVE_CHECKS, {"GH_TOKEN": lambda token: "auth FAILED"}):
                rc = verify_secrets.main(["--live"])
            self.assertEqual(rc, 1)

    def test_main_stays_zero_on_live_auth_success(self) -> None:
        from unittest import mock

        from factory import verify_secrets

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), toml='[install]\nenv = { GH_TOKEN = "tok" }\n')
            original_cwd = Path.cwd()
            os.chdir(repo)
            self.addCleanup(os.chdir, original_cwd)

            with mock.patch.object(verify_secrets, "unit_env", return_value={"GH_TOKEN": "tok"}), \
                 mock.patch.dict(verify_secrets.LIVE_CHECKS, {"GH_TOKEN": lambda token: "OK, scopes: repo"}):
                rc = verify_secrets.main(["--live"])
            self.assertEqual(rc, 0)

    def test_apply_isolation_uses_config_not_callers_environment(self) -> None:
        import io
        import json
        from contextlib import redirect_stdout
        from unittest import mock

        from factory import verify_secrets

        apply_token = "SECRET-apply-sentinel"
        install_token = "SECRET-install-sentinel"
        cases = (
            ({}, 0, []),
            ({"GH_TOKEN": apply_token}, 1, [{"key": "GH_TOKEN", "status": "leaked"}]),
            ({"GH_TOKEN": install_token}, 0, []),
        )
        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d))
            cfg = config.load(repo)
            for install_env, expected_rc, expected_isolation in cases:
                for scope in ("apply", "all"):
                    with self.subTest(install_env_keys=list(install_env), rc=expected_rc, scope=scope):
                        cfg.install["env"] = install_env
                        with mock.patch.object(cfg, "apply_env", {"GH_TOKEN": apply_token}), \
                             mock.patch.object(verify_secrets.config, "load", return_value=cfg), \
                             mock.patch.object(verify_secrets, "unit_env", return_value=install_env), \
                             mock.patch.dict(os.environ, {"GH_TOKEN": apply_token}):
                            output = io.StringIO()
                            with redirect_stdout(output):
                                rc = verify_secrets.main(["--scope", scope, "--json"])
                        self.assertEqual(rc, expected_rc)
                        self.assertNotIn("SECRET", output.getvalue())
                        report = json.loads(output.getvalue())
                        self.assertEqual(report["ok"], expected_rc == 0)
                        self.assertEqual(report["apply_isolation"], expected_isolation)


if __name__ == "__main__":
    unittest.main()
