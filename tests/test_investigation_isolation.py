import sys
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
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


    @unittest.skipUnless(sys.platform == "linux" and Path("/usr/bin/bwrap").exists(),
                         "requires Linux bubblewrap")
    def test_real_projection_boundary(self):
        probe = subprocess.run(["unshare", "--user", "--map-root-user", "--net", "true"],
                               capture_output=True)
        if probe.returncode:
            self.skipTest("runner prohibits unprivileged namespaces")
        with tempfile.TemporaryDirectory() as folder, socket.socket() as listener:
            sentinel = Path(folder) / "private"
            sentinel.write_text("synthetic-secret")
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            code = f"""import json,os,socket,sys
s=socket.socket();s.settimeout(.2)
print(json.dumps({{
 'input':sys.stdin.buffer.read()==b'{{}}',
 'file':not os.path.exists({str(sentinel)!r}),
 'env':'FACTORY_TEST_SECRET' not in os.environ,
 'network':s.connect_ex(('127.0.0.1',{listener.getsockname()[1]}))!=0,
 'home':not os.path.exists('/home'),
 'config':not os.path.exists('/etc')
}}))
""".encode()
            with patch.dict(os.environ, {"FACTORY_TEST_SECRET": "synthetic-secret"}):
                self.assertTrue(all(json.loads(isolation.run(Projection(b"{}"), code)).values()))
        with self.assertRaisesRegex(isolation.IsolationRefused, "output_budget"):
            isolation.run(Projection(b"{}"), b"print('x'*9000)")
        with self.assertRaisesRegex(isolation.IsolationRefused, "worker_timeout"):
            isolation.run(Projection(b"{}"), b"import time;time.sleep(10)", timeout=.2)

if __name__ == "__main__":
    unittest.main()
