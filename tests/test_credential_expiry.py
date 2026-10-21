"""Adapter credential rows carry machine-readable expiry; Factory marks expired ones."""

import datetime
import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from factory import config, deploy, inspection, onboard, verify_secrets

SECRET = "credential-sentinel-do-not-render"
NOW = datetime.datetime(2026, 10, 21, 12, 0, tzinfo=datetime.UTC)


def report_rows(rows, now=NOW):
    class Adapter(deploy.FakeDeployAdapter):
        def credential_checks(self, env, live):
            return rows
    return verify_secrets._adapter_report(Adapter(), {}, False, [SECRET], now=now)


class ExpiryFieldsTest(unittest.TestCase):
    def test_timestamps_are_normalized_to_utc(self):
        [row] = report_rows([{"key": "HARBOR_CLI_ROBOT", "status": "valid",
                              "expires_at": "2026-10-22T09:30:00-04:00",
                              "renewable_until": "2027-04-01T00:00:00Z",
                              "action": "harbor auth login example"}])
        self.assertEqual(row["expires_at"], "2026-10-22T13:30:00Z")
        self.assertEqual(row["renewable_until"], "2027-04-01T00:00:00Z")
        self.assertEqual(row["action"], "harbor auth login example")
        self.assertEqual(row["status"], "valid")

    def test_malformed_timestamps_reject_the_whole_report(self):
        for bad in ("tomorrow", "2026-10-22T09:30:00", 1792600000, "2026-10-22T09:30:00Z" + "x" * 40):
            with self.subTest(bad=bad), self.assertRaises((ValueError, TypeError)):
                report_rows([{"key": "K", "status": "valid", "expires_at": bad}])

    def test_factory_marks_a_past_expiry_expired(self):
        [row] = report_rows([{"key": "HOSTED_SESSION", "status": "valid", "expires_at": "2026-10-21T11:59:00Z"}])
        self.assertEqual(row["status"], "expired")
        self.assertIn("expired", verify_secrets.BAD_STATUSES)

    def test_an_action_carrying_a_secret_is_dropped_and_lines_are_folded(self):
        rows = report_rows([
            {"key": "A", "status": "valid", "action": f"login --password {SECRET}"},
            {"key": "B", "status": "valid", "action": "harbor auth\nlogin\x1b[31m  example"},
        ])
        self.assertNotIn("action", rows[0])
        self.assertNotIn(SECRET, json.dumps(rows))
        self.assertEqual(rows[1]["action"], "harbor auth login[31m example")

    def test_rows_without_expiry_are_unchanged(self):
        [row] = report_rows([{"key": "K", "status": "configured"}])
        self.assertEqual(row, {"key": "K", "status": "configured"})
        self.assertEqual(verify_secrets.expiry_text(row), "")

    def test_text_names_time_left_and_renewal(self):
        row = {"key": "K", "status": "valid", "expires_at": "2026-10-21T17:00:00Z", "action": "renew-it"}
        self.assertEqual(verify_secrets.expiry_text(row, NOW),
                         " -- expires 2026-10-21T17:00:00Z (in 5h) -- renew: renew-it")


class AdapterConfigTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.cfg = config.Config(Path(tmp.name), "example/repo")
        self.cfg.apply_enabled = True
        self.cfg.apply_env = {"HARBOR_PASSWORD": SECRET}
        self.cfg.targets = {"app": config.DeployTarget(name="app", dir="app", adapter="expiring")}

    def adapter(self, hours: float):
        expires = (datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=hours)).isoformat()

        class Expiring(deploy.FakeDeployAdapter):
            def credential_checks(self, env, live):
                return [{"key": "HARBOR_CLI_ROBOT", "status": "valid", "expires_at": expires,
                         "action": "harbor auth login example"}]
        return patch.dict(deploy.ADAPTERS, {"expiring": Expiring})

    def doctor_rows(self, hours: float, warn: float = 4.0):
        self.cfg.credential_warn_hours = warn
        rows = []
        with self.adapter(hours):
            onboard._credential_expiry_checks(self.cfg, lambda status, label, detail="", **_: rows.append((status, label, detail)))
        return rows

    def test_doctor_warns_inside_the_window_and_fails_once_expired(self):
        cases = {30.0: True, 3.0: None, -1.0: False}
        for hours, status in cases.items():
            with self.subTest(hours=hours):
                [(got, label, detail)] = self.doctor_rows(hours)
                self.assertIs(got, status)
                self.assertEqual(label, "credential expiry: expiring HARBOR_CLI_ROBOT")
                self.assertIn("renew: harbor auth login example", detail)
        [(got, _, _)] = self.doctor_rows(3.0, warn=2.0)
        self.assertIs(got, True)

    def test_verify_secrets_and_inspect_pass_fields_through(self):
        with self.adapter(-1.0), patch.dict(verify_secrets.LIVE_CHECKS, {}, clear=True):
            rows = verify_secrets.credential_rows(self.cfg, "apply", False)
            row = next(r for r in rows if r.get("adapter") == "expiring")
            self.assertEqual(row["status"], "expired")
            self.assertTrue(row["expires_at"].endswith("Z"))
            out = io.StringIO()
            with patch.object(config, "load", return_value=self.cfg), redirect_stdout(out):
                code = verify_secrets.main(["--scope", "apply", "--json"])
        self.assertEqual(code, 1)
        data = json.loads(out.getvalue())
        self.assertFalse(data["ok"])
        self.assertNotIn(SECRET, out.getvalue())
        self.assertTrue(hasattr(inspection, "verify_secrets"))  # inspect embeds these same rows

    def test_warn_hours_must_be_a_positive_number(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            with patch.dict("os.environ", {"XDG_CONFIG_HOME": str(root / "xdg")}):
                for bad in (0, -2, "4", True):
                    with self.subTest(bad=bad):
                        (root / config.CONFIG_NAME).write_text(
                            f"[repo]\nslug = \"acme/widgets\"\n[apply]\nenabled = true\ncredential_warn_hours = {json.dumps(bad)}\n")
                        with self.assertRaisesRegex(config.ConfigError, "credential_warn_hours"):
                            config.load(root)
                (root / config.CONFIG_NAME).write_text("[repo]\nslug = \"acme/widgets\"\n[apply]\nenabled = true\ncredential_warn_hours = 12\n")
                self.assertEqual(config.load(root).credential_warn_hours, 12.0)
                (root / config.CONFIG_NAME).write_text("[repo]\nslug = \"acme/widgets\"\n[apply]\nenabled = true\n")
                self.assertEqual(config.load(root).credential_warn_hours, 4.0)

if __name__ == "__main__":
    unittest.main()
