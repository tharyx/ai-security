"""Compact SCA and SAST scanners used by the simulated pre-commit hooks.

These are small on purpose (see the `sca` and `sast` labs for the fuller versions).
Each scanner takes the staged files (path -> text) and returns a list of messages.
"""

from __future__ import annotations

import ast
import json
import re

ADVISORIES = json.loads("""[
  {"id": "EXAMPLE-2026-0001", "package": "examplelib", "fixed": "1.4.2", "severity": "high"},
  {"id": "EXAMPLE-2026-0002", "package": "yaml-lite", "fixed": "0.6.0", "severity": "critical"}
]""")


def _v(s: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", s))


def sca_check(files: dict[str, str]) -> list[str]:
    msgs = []
    for path, text in files.items():
        if not path.endswith((".lock", "requirements.txt")):
            continue
        for line in text.splitlines():
            m = re.match(r"^\s*([A-Za-z0-9_.\-]+)==([0-9][0-9.]*)", line)
            if not m:
                continue
            for adv in ADVISORIES:
                if adv["package"] == m.group(1).lower() and _v(m.group(2)) < _v(adv["fixed"]):
                    msgs.append(f"{path}: {adv['id']} [{adv['severity']}] {m.group(1)}=={m.group(2)} (fixed in {adv['fixed']})")
    return msgs


def sast_check(files: dict[str, str]) -> list[str]:
    msgs = []
    for path, text in files.items():
        if not path.endswith(".py"):
            continue
        try:
            tree = ast.parse(text)
        except SyntaxError as e:
            msgs.append(f"{path}:{e.lineno}: syntax error, cannot scan")
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = ast.unparse(node.func)
                if fn in ("eval", "exec", "os.system"):
                    msgs.append(f"{path}:{node.lineno}: {fn}() call")
                if fn == "yaml.load" and not any(k.arg == "Loader" for k in node.keywords) and len(node.args) < 2:
                    msgs.append(f"{path}:{node.lineno}: yaml.load without Loader")
                if fn.startswith("subprocess.") and any(k.arg == "shell" and getattr(k.value, "value", None) is True for k in node.keywords):
                    msgs.append(f"{path}:{node.lineno}: shell=True")
                if fn.endswith(".execute") and node.args and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp)):
                    msgs.append(f"{path}:{node.lineno}: SQL built with string formatting")
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                for t in node.targets:
                    if isinstance(t, ast.Name) and re.search(r"(password|secret|token|api_key)", t.id, re.I) and len(node.value.value) >= 6:
                        msgs.append(f"{path}:{node.lineno}: hardcoded secret in '{t.id}'")
    return msgs
