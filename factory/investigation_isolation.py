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

from .investigation_evidence import MAX_PROJECTION, Projection

MAX_CODE = 64 * 1024
MAX_OUTPUT = 8192
MAX_SECONDS = 30


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
    for name in ("bwrap", "python3", "prlimit"):
        try:
            info = Path("/usr/bin", name).stat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise IsolationRefused("isolation_unavailable")
        except OSError:
            raise IsolationRefused("isolation_unavailable") from None
    data_fd = code_fd = None
    child = None
    try:
        data_fd = _sealed(projection.payload)
        code_fd = _sealed(code)
        child = subprocess.Popen(command(code_fd), stdin=data_fd, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env={}, close_fds=True,
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
            child.stdout.close()
            child.stderr.close()
        for fd in (data_fd, code_fd):
            if fd is not None:
                os.close(fd)
