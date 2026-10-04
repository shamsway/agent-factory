"""Unactivated Linux boundary for projection-only investigation workers.

The trusted publisher must validate the returned bytes. This runner grants no
network, repository, configuration, credential, or publication access.
"""
from __future__ import annotations

import fcntl
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import time
import uuid
import math

from .investigation_evidence import MAX_PROJECTION, Projection

MAX_CODE = 64 * 1024
MAX_OUTPUT = 8192
MAX_SECONDS = 30
MAX_TASKS = 32
MAX_MEMORY = 256 * 1024 * 1024

# Trusted bootstrap runs inside the scope before any worker starts. Read actual
# kernel limits, not just systemd properties: missing controllers fail closed.
CGROUP_CHECK = """import os,sys
from pathlib import Path
try:
    rows=Path('/proc/self/cgroup').read_text().splitlines()
    rows=[r[3:] for r in rows if r.startswith('0::')]
    assert len(rows)==1 and Path(rows[0]).name==sys.argv[1]
    root=Path('/sys/fs/cgroup') / rows[0].lstrip('/')
    for name,limit in [('pids.max',32),('memory.max',268435456),('memory.swap.max',0)]:
        actual=int((root/name).read_text().strip())
        assert 0 <= actual <= limit
    quota,period=(root/'cpu.max').read_text().split()
    assert 0 < int(quota) <= int(period)
except Exception:
    sys.exit(125)
os.execv(sys.argv[2],sys.argv[2:])
"""


def scope_command(code_fd: int, unit: str, timeout: float) -> list[str]:
    return ["/usr/bin/systemd-run", "--user", "--scope", "--quiet", "--collect",
            "--no-ask-password", "--expand-environment=no", "--unit=" + unit,
            "--property=TasksMax=" + str(MAX_TASKS),
            "--property=MemoryMax=" + str(MAX_MEMORY), "--property=MemorySwapMax=0",
            "--property=CPUQuota=100%", "--property=RuntimeMaxSec=" + str(math.ceil(timeout)),
            "/usr/bin/python3", "-I", "-S", "-c", CGROUP_CHECK, unit, *command(code_fd)]


def scope_environment() -> dict[str, str]:
    # Only the fixed local user-manager bus is reachable by the trusted launcher.
    # bubblewrap clears this again; the worker never sees the socket or variables.
    runtime = "/run/user/" + str(os.getuid())
    return {"XDG_RUNTIME_DIR": runtime,
            "DBUS_SESSION_BUS_ADDRESS": "unix:path=" + runtime + "/bus"}


class IsolationRefused(RuntimeError):
    """Closed operational reason codes; never expose subprocess diagnostics."""


def command(code_fd: int) -> list[str]:
    args = ["/usr/bin/bwrap", "--unshare-user", "--unshare-pid", "--unshare-net",
            "--unshare-ipc", "--unshare-uts", "--disable-userns", "--cap-drop", "ALL",
            "--die-with-parent", "--new-session", "--clearenv"]
    for name in ("bin", "lib", "lib64"):
        source = Path("/usr") / name
        if source.is_dir():
            args += ["--ro-bind", str(source), str(source), "--symlink", "usr/" + name,
                     "/" + name]
    args += ["--proc", "/proc", "--dev", "/dev", "--size", str(16 * 1024 * 1024),
             "--tmpfs", "/tmp", "--ro-bind-data", str(code_fd), "/worker.py",
             "--remount-ro", "/", "--chdir", "/", "--setenv", "PATH", "/usr/bin",
             "--setenv", "HOME", "/nonexistent", "--setenv", "LC_ALL", "C",
             "--setenv", "TMPDIR", "/tmp", "/usr/bin/prlimit", "--as=536870912",
             "--cpu=5", "--fsize=16384", "--nofile=32", "--", "/usr/bin/python3",
             "-I", "-S", "/worker.py"]
    return args


def _sealed(raw: bytes) -> int:
    fd = os.memfd_create("factory-investigation", os.MFD_ALLOW_SEALING)
    try:
        offset = 0
        while offset < len(raw):
            offset += os.write(fd, raw[offset:])
        os.lseek(fd, 0, os.SEEK_SET)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                    fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        return fd
    except BaseException:
        os.close(fd)
        raise


def run(projection: Projection, code: bytes, *, timeout: float = MAX_SECONDS) -> bytes:
    if not isinstance(projection, Projection) or not isinstance(code, bytes):
        raise IsolationRefused("invalid_input")
    if len(projection.payload) > MAX_PROJECTION or len(code) > MAX_CODE:
        raise IsolationRefused("input_budget")
    if type(timeout) not in (int, float) or not 0 < timeout <= MAX_SECONDS:
        raise IsolationRefused("invalid_timeout")
    if sys.platform != "linux" or not hasattr(os, "memfd_create"):
        raise IsolationRefused("isolation_unavailable")
    for name in ("bwrap", "python3", "prlimit", "systemd-run", "systemctl"):
        try:
            info = Path("/usr/bin", name).stat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise IsolationRefused("isolation_unavailable")
        except OSError:
            raise IsolationRefused("isolation_unavailable") from None
    data_fd = code_fd = None
    child = None
    unit = "factory-investigation-" + uuid.uuid4().hex + ".scope"
    environment = scope_environment()
    try:
        data_fd = _sealed(projection.payload)
        code_fd = _sealed(code)
        child = subprocess.Popen(scope_command(code_fd, unit, timeout), stdin=data_fd,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env=environment, close_fds=True,
                                 pass_fds=(code_fd,), start_new_session=True)
        deadline = time.monotonic() + timeout
        result = bytearray()
        total = 0
        with selectors.DefaultSelector() as selector:
            for stream in (child.stdout, child.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise IsolationRefused("worker_timeout")
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), MAX_OUTPUT + 1)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(chunk)
                    if total > MAX_OUTPUT:
                        raise IsolationRefused("output_budget")
                    if key.fileobj is child.stdout:
                        result.extend(chunk)
            try:
                status = child.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise IsolationRefused("worker_timeout") from None
        if status == 125:
            raise IsolationRefused("cgroup_unavailable")
        if status:
            raise IsolationRefused("worker_failed")
        return bytes(result)
    except OSError:
        raise IsolationRefused("isolation_unavailable") from None
    finally:
        if child is not None:
            # Kill the launcher group even after normal exit; the private PID
            # namespace and die-with-parent also terminate surviving descendants.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
            # Scope lifetime outlives the launcher if descendants remain. Stop
            # this generated unit only; never kill by user or command pattern.
            try:
                subprocess.run(["/usr/bin/systemctl", "--user", "stop", unit],
                               env=environment, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=5, check=False)
            except (OSError, subprocess.TimeoutExpired):
                # RuntimeMaxSec still bounds cleanup if the manager is unreachable.
                pass
            child.stdout.close()
            child.stderr.close()
        for fd in (data_fd, code_fd):
            if fd is not None:
                os.close(fd)
