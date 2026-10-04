import sys
import unittest
from unittest.mock import patch

from factory.investigation_evidence import Projection
from factory import investigation_isolation as isolation


class IsolationTest(unittest.TestCase):
    def test_no_host_or_network_mounts(self):
        args = isolation.command(123)
        self.assertIn("--unshare-net", args)
        self.assertIn("--unshare-pid", args)
        self.assertIn("--disable-userns", args)
        self.assertIn("--clearenv", args)
        self.assertIn("--remount-ro", args)
        self.assertNotIn("/home", args)
        self.assertNotIn("/etc", args)
        self.assertNotIn("/run", args)
        self.assertEqual(args[-4:], ["/usr/bin/python3", "-I", "-S", "/worker.py"])

    def test_unsupported_platform_fails_closed(self):
        with patch.object(sys, "platform", "darwin"):
            with self.assertRaisesRegex(isolation.IsolationRefused, "isolation_unavailable"):
                isolation.run(Projection(b"{}"), b"pass")

    def test_input_and_timeout_budgets(self):
        with self.assertRaisesRegex(isolation.IsolationRefused, "input_budget"):
            isolation.run(Projection(b"{}"), b"x" * (isolation.MAX_CODE + 1))
        with self.assertRaisesRegex(isolation.IsolationRefused, "invalid_timeout"):
            isolation.run(Projection(b"{}"), b"pass", timeout=31)
        with self.assertRaisesRegex(isolation.IsolationRefused, "invalid_input"):
            isolation.run(b"{}", b"pass")


if __name__ == "__main__":
    unittest.main()
