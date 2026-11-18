"""A deliberately weak "code tool" for an agent: run model-written Python.

ACME's data agent writes small Python snippets to answer questions ("sum this
column", "plot that"). An engineer wired up this runner. Its only protection is a
denylist that rejects snippets mentioning `os`, `open`, `eval` and friends.

DO NOT copy this pattern. Every line marked VULN is a mistake this lab teaches you
to find.

Run the scorecard from the repository root:
    python 05-agent-security/sandboxing/lab/demo.py
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field

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


@dataclass
class RunResult:
    status: str
    stdout: str = ""
    seconds: float = 0.0
    events: list[str] = field(default_factory=list)


class NaiveRunner:
    def __init__(self, workdir: str, host_env: dict[str, str] | None = None,
                 lab_fuse: float = 3.0) -> None:
        self.workdir = workdir          # VULN 1: runs inside the agent's own project folder
        self.host_env = dict(os.environ if host_env is None else host_env)
        self.lab_fuse = lab_fuse        # NOT a control: it only stops this lab from hanging

    def run(self, code: str) -> RunResult:
        # VULN 2: the denylist is the ONLY security layer. It is a soft layer.
        problem = denylist_problem(code)
        if problem:
            return RunResult("blocked", events=[f"denylist: {problem}"])
        start = time.monotonic()
        try:
            proc = subprocess.run(
                [sys.executable, "-c", code],
                cwd=self.workdir,
                env=self.host_env,       # VULN 3: inherits every secret in the agent's environment
                capture_output=True,     # VULN 4: no output cap - all of it lands in memory
                timeout=self.lab_fuse,   # VULN 5: in the "real" app there was no timeout at all
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            return RunResult("hung", seconds=time.monotonic() - start,
                             events=[f"no time limit; stopped by the {self.lab_fuse}s lab fuse"])
        # VULN 6: no kill switch, no network or file restrictions, no clean-up.
        out = (proc.stdout + proc.stderr).decode("utf-8", errors="replace")
        return RunResult("ok" if proc.returncode == 0 else "error", out, time.monotonic() - start)
