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


def real_boundary(test):
    required = os.environ.get("FACTORY_REQUIRE_ISOLATION") == "1"
    if sys.platform != "linux" or not Path("/usr/bin/bwrap").exists():
        if required:
            test.fail("required Linux bubblewrap boundary unavailable")
        test.skipTest("requires Linux bubblewrap")
    try:
        probe = subprocess.run(["unshare", "--user", "--map-root-user", "--net", "true"],
                               capture_output=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        probe = None
    if probe is None or probe.returncode:
        if required:
            test.fail("required user/network namespaces unavailable")
        test.skipTest("runner prohibits unprivileged namespaces")


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


    def test_scope_limits_and_clean_environment(self):
        args = isolation.scope_command(123, "factory-test.scope", 1.2)
        self.assertEqual(args[0], "/usr/bin/systemd-run")
        self.assertIn("--scope", args)
        self.assertIn("--property=TasksMax=32", args)
        self.assertIn("--property=MemoryMax=268435456", args)
        self.assertIn("--property=MemorySwapMax=0", args)
        self.assertIn("--property=RuntimeMaxSec=2", args)
        self.assertIn(isolation.CGROUP_CHECK, args)
        with patch.dict(os.environ, {"GH_TOKEN": "synthetic-secret"}):
            self.assertEqual(set(isolation.scope_environment()),
                             {"XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"})

    def test_missing_controller_refuses_before_worker(self):
        real_boundary(self)
        # The bootstrap never launches the sentinel command outside its expected
        # scope, including when a controller reports 'max' or is unavailable.
        result = subprocess.run(["/usr/bin/python3", "-I", "-S", "-c",
                                 isolation.CGROUP_CHECK, "not-a-real-scope.scope",
                                 "/usr/bin/printf", "worker-started"], capture_output=True)
        self.assertEqual(result.returncode, 125)
        self.assertEqual(result.stdout, b"")

    def test_aggregate_tasks_and_memory(self):
        real_boundary(self)
        code = b"""import os,signal,json
children=[]
limited=False
try:
 for i in range(40):
  try: pid=os.fork()
  except BlockingIOError:
   limited=True;break
  if pid==0:
   signal.pause();os._exit(0)
  children.append(pid)
finally:
 for pid in children: os.kill(pid,signal.SIGKILL)
 for pid in children: os.waitpid(pid,0)
print(json.dumps({'limited':limited,'count':len(children)}))
"""
        result = json.loads(isolation.run(Projection(b"{}"), code, timeout=5))
        self.assertTrue(result["limited"])
        self.assertLess(result["count"], isolation.MAX_TASKS)
        # A single allocation below RLIMIT_AS but above the entire cgroup's
        # memory.max must terminate the worker, not exhaust the host.
        with self.assertRaisesRegex(isolation.IsolationRefused, "worker_failed"):
            isolation.run(Projection(b"{}"), b"x=bytearray(400*1024*1024)", timeout=5)
        self.assertEqual(isolation.run(Projection(b"{}"), b"print('alive')"), b"alive\n")

    def test_real_projection_boundary(self):
        real_boundary(self)
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
