"""A safer code tool: run untrusted Python in a separate, limited, throw-away process.

Layers (each can be switched off to see what it buys you):

    S1  AST denylist                                    SOFT  - catches lazy attacks, logs intent
    S2  Audit-hook guard inside the child (PEP 578):    SOFT  - blocks writes outside the work
        file writes outside the work dir, sockets,              dir, network and new processes,
        new processes                                           but code in the same process can
                                                                defeat it (PEP 578 says so)
    H1  Separate OS process                             HARD  - a crash or hang can't take the agent down
    H2  Scrubbed environment (allowlist, not denylist)  HARD  - no inherited secrets to steal
    H3  Fresh, empty temp work dir, deleted afterwards  HARD  - no project files; nothing persists
    H4  `python -I` isolated mode                       HARD  - ignores PYTHON* env vars, user
                                                                site-packages and the script folder
    H5  Wall-clock timeout, then kill                   HARD
    H6  Output size cap, then kill                      HARD
    H7  Kill switch: refuse new runs, kill running ones HARD
    (+) On Linux only: CPU-time and file-size rlimits.

What this lab CANNOT give you, cross-platform, with the standard library: a real
filesystem jail, network isolation, memory limits or a separate kernel. For that use
a container with no network, a read-only root and dropped capabilities, or gVisor,
or a Firecracker microVM (see the lesson). The tests prove where the line is.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

# --- S1: the same AST denylist as the vulnerable runner (labs never import siblings) ---
DENY_IMPORTS = {"os", "sys", "subprocess", "shutil", "socket", "ctypes", "importlib", "pathlib", "builtins"}
DENY_NAMES = {"eval", "exec", "open", "__import__", "compile", "globals", "locals"}
DENY_ATTRS = {"environ", "system", "popen", "remove", "rmtree"}


def denylist_problem(code: str) -> str | None:
    """A static check of the code's syntax tree. Easy to write - and easy to bypass."""
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return f"syntax error: {exc.msg}"
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in DENY_IMPORTS:
                    return f"import of {alias.name}"
        elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] in DENY_IMPORTS:
            return f"import from {node.module}"
        elif isinstance(node, ast.Name) and node.id in DENY_NAMES:
            return f"use of {node.id}"
        elif isinstance(node, ast.Attribute) and node.attr in DENY_ATTRS:
            return f"attribute .{node.attr}"
    return None


BOOTSTRAP = r'''
import os, sys
WORKDIR = os.path.realpath(os.getcwd())
GUARD_FS = {guard_fs}
BLOCK_NET = {block_net}

def _inside(path):
    try:
        full = os.path.realpath(os.fsdecode(path))
    except Exception:
        return False
    return full == WORKDIR or full.startswith(WORKDIR + os.sep)

def _hook(event, args):
    if GUARD_FS and event == "open":
        path, mode, flags = args
        if isinstance(path, int):
            return
        writing = (mode is not None and any(c in str(mode) for c in "wax+")) or (
            mode is None and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND))
        if writing and not _inside(path):
            raise PermissionError(f"sandbox: write outside work dir blocked: {{path}}")
    elif BLOCK_NET and event in ("socket.connect", "socket.getaddrinfo", "socket.bind"):
        raise PermissionError("sandbox: network access blocked")
    elif event in ("subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.startfile"):
        raise PermissionError("sandbox: starting processes is blocked")

if GUARD_FS or BLOCK_NET:
    sys.addaudithook(_hook)  # cannot be removed once added
with open("snippet.py", encoding="utf-8") as f:
    code = f.read()
exec(compile(code, "snippet.py", "exec"), {{"__name__": "__main__", "__builtins__": __builtins__}})
'''


def minimal_env() -> dict[str, str]:
    """An ALLOWLIST of environment variables. Nothing secret is inherited."""
    env: dict[str, str] = {}
    if sys.platform == "win32":  # Windows needs SYSTEMROOT for Python to start cleanly
        env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", r"C:\Windows")
    else:
        env["PATH"] = "/usr/bin:/bin"
    return env


def _posix_limits(cpu_seconds: int) -> None:  # pragma: no cover - runs only on Linux/macOS
    import resource

    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
    resource.setrlimit(resource.RLIMIT_FSIZE, (10_000_000, 10_000_000))  # 10 MB per file


class KillSwitch:
    """One switch for an operator (or a monitor) to stop all code execution now."""

    def __init__(self) -> None:
        self._tripped = threading.Event()
        self._lock = threading.Lock()
        self._running: set[subprocess.Popen] = set()
        self.reason = ""

    @property
    def tripped(self) -> bool:
        return self._tripped.is_set()

    def trip(self, reason: str) -> None:
        self.reason = reason
        self._tripped.set()
        with self._lock:
            for proc in list(self._running):
                proc.kill()

    def reset(self) -> None:  # only a human should call this, after review
        self._tripped.clear()

    def _register(self, proc: subprocess.Popen) -> None:
        with self._lock:
            self._running.add(proc)
            if self.tripped:  # tripped between our check and the process starting
                proc.kill()

    def _unregister(self, proc: subprocess.Popen) -> None:
        with self._lock:
            self._running.discard(proc)


@dataclass
class RunResult:
    status: str  # ok | error | blocked | timeout | output_capped | killed | refused
    stdout: str = ""
    returncode: int | None = None
    seconds: float = 0.0
    files: list[str] = field(default_factory=list)  # files the snippet created (then deleted)
    workdir: str = ""
    events: list[str] = field(default_factory=list)


class SubprocessSandbox:
    def __init__(self, *, denylist: bool = True, fs_guard: bool = True, block_network: bool = True,
                 scrub_env: bool = True, isolated_mode: bool = True, timeout: float = 2.0,
                 max_output: int = 64_000, host_env: dict[str, str] | None = None,
                 kill_switch: KillSwitch | None = None) -> None:
        self.denylist, self.fs_guard, self.block_network = denylist, fs_guard, block_network
        self.scrub_env, self.isolated_mode = scrub_env, isolated_mode
        self.timeout, self.max_output = timeout, max_output
        self.host_env = dict(os.environ if host_env is None else host_env)
        self.kill_switch = kill_switch or KillSwitch()

    def run(self, code: str) -> RunResult:
        if self.kill_switch.tripped:  # H7
            return RunResult("refused", events=[f"kill switch: {self.kill_switch.reason}"])
        if self.denylist:  # S1
            problem = denylist_problem(code)
            if problem:
                return RunResult("blocked", events=[f"denylist: {problem}"])

        with tempfile.TemporaryDirectory(prefix="agent-sbx-", ignore_cleanup_errors=True) as wd:  # H3
            Path(wd, "snippet.py").write_text(code, encoding="utf-8")
            Path(wd, "_bootstrap.py").write_text(
                BOOTSTRAP.format(guard_fs=self.fs_guard, block_net=self.block_network), encoding="utf-8")
            cmd = [sys.executable, "-B", "-X", "utf8"] + (["-I"] if self.isolated_mode else []) + ["_bootstrap.py"]
            kwargs: dict = {}
            if sys.platform != "win32":
                kwargs["preexec_fn"] = lambda: _posix_limits(int(self.timeout) + 1)
                kwargs["start_new_session"] = True
            start = time.monotonic()
            proc = subprocess.Popen(  # H1
                cmd, cwd=wd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                env=minimal_env() if self.scrub_env else self.host_env,  # H2
                **kwargs)
            self.kill_switch._register(proc)
            buf, capped = bytearray(), threading.Event()

            def pump() -> None:  # H6: read at most max_output bytes, then kill
                while chunk := proc.stdout.read1(8192):
                    room = self.max_output - len(buf)
                    buf.extend(chunk[:room])
                    if len(chunk) > room:
                        capped.set()
                        proc.kill()
                        break

            reader = threading.Thread(target=pump, daemon=True)
            reader.start()
            timed_out = False
            try:
                proc.wait(timeout=self.timeout)  # H5
            except subprocess.TimeoutExpired:
                timed_out = True
                proc.kill()
                proc.wait()
            finally:
                self.kill_switch._unregister(proc)
            reader.join(timeout=2)
            proc.stdout.close()
            seconds = time.monotonic() - start
            files = sorted(p.name for p in Path(wd).iterdir() if p.name not in ("snippet.py", "_bootstrap.py"))

        out = buf.decode("utf-8", errors="replace")
        result = RunResult("ok", out, proc.returncode, seconds, files, wd)
        if self.kill_switch.tripped:
            result.status = "killed"
            result.events.append(f"kill switch: {self.kill_switch.reason}")
        elif capped.is_set():
            result.status = "output_capped"
            result.events.append(f"output cap {self.max_output} bytes")
        elif timed_out:
            result.status = "timeout"
            result.events.append(f"timeout {self.timeout}s")
        elif proc.returncode != 0:
            last = (out.strip().splitlines() or [""])[-1]  # e.g. "PermissionError: sandbox: ..."
            result.status = "blocked" if "sandbox:" in last else "error"
            result.events.append(("guard: " if "sandbox:" in last else "error: ") + last)
        return result
