"""A small AST-based static analysis tool (SAST) for AI application code.

    python scanner.py sample_app/vulnerable_app.py

It parses Python into a syntax tree and never runs the code. It looks for mistakes that are
common in AI projects. This is the same idea as Bandit and Semgrep, in about 150 lines:

  AIC001  unsafe deserialization   pickle.load(s), joblib.load, torch.load without weights_only=True, yaml.load
  AIC002  model output reaches a dangerous sink   eval/exec/os.system/subprocess on text from llm.complete(...)
  AIC003  dynamic code execution   eval/exec with a non-literal argument
  AIC004  shell command            subprocess.* with shell=True, os.system
  AIC005  hardcoded secret         key/token/password names assigned a string literal
  AIC006  trust_remote_code=True   downloaded repo code is executed when the model loads
  AIC007  TLS verification off     requests.* with verify=False
  AIC008  unpinned model download  from_pretrained(...) without revision= (supply chain; low severity)

Limits (say these out loud in an interview): it is a pattern checker. It misses aliases
(``from pickle import load as l``), data that flows through many functions, and anything
dynamic. A clean scan is not a proof of safety. Use real tools in CI too.
"""

from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass
from pathlib import Path

SECRET_NAME = re.compile(r"(api[_-]?key|secret|token|passw(or)?d|credential)", re.I)
FAKE_PLACEHOLDER = re.compile(r"^(changeme|example|<.*>|\$\{.*\}|x+)$", re.I)
MODEL_CALLS = {"complete", "generate", "chat", "invoke", "predict"}
SEVERITY = {"AIC001": "HIGH", "AIC002": "CRITICAL", "AIC003": "HIGH", "AIC004": "HIGH", "AIC005": "MEDIUM",
            "AIC006": "HIGH", "AIC007": "MEDIUM", "AIC008": "LOW"}


@dataclass(frozen=True)
class Finding:
    rule: str
    line: int
    message: str

    @property
    def severity(self) -> str:
        return SEVERITY[self.rule]

    def __str__(self) -> str:
        return f"line {self.line:<3} {self.rule} {self.severity:<8} {self.message}"


def dotted(node: ast.AST) -> str:
    """'pickle.load' for the call func ``pickle.load``; '' when it is not a plain name chain."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def kwarg(call: ast.Call, name: str):
    return next((k.value for k in call.keywords if k.arg == name), None)


def is_true(node) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def is_false(node) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


class Visitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.tainted: set[str] = set()

    def add(self, rule: str, node: ast.AST, msg: str) -> None:
        self.findings.append(Finding(rule, node.lineno, msg))

    # -- taint: names assigned from a model call
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        saved, self.tainted = self.tainted, set()  # taint is per function
        self.generic_visit(node)
        self.tainted = saved

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Call) and dotted(node.value.func).split(".")[-1] in MODEL_CALLS:
            self.tainted |= {t.id for t in node.targets if isinstance(t, ast.Name)}
        for t in node.targets:  # AIC005 hardcoded secrets
            if (isinstance(t, ast.Name) and SECRET_NAME.search(t.id)
                    and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
                    and len(node.value.value) >= 8 and not FAKE_PLACEHOLDER.match(node.value.value)):
                self.add("AIC005", node, f"hardcoded secret in '{t.id}'")
        self.generic_visit(node)

    def uses_taint(self, call: ast.Call) -> bool:
        names = {n.id for a in call.args for n in ast.walk(a) if isinstance(n, ast.Name)}
        return bool(names & self.tainted)

    def visit_Call(self, node: ast.Call) -> None:
        name = dotted(node.func)
        last = name.split(".")[-1]
        # AIC001
        if name in {"pickle.load", "pickle.loads", "cPickle.load", "dill.load", "joblib.load"}:
            self.add("AIC001", node, f"{name}() runs code from the file")
        if name == "torch.load" and not is_true(kwarg(node, "weights_only")):
            self.add("AIC001", node, "torch.load() without weights_only=True")
        if name == "yaml.load":
            loader = kwarg(node, "Loader")
            if loader is None or dotted(loader) in {"yaml.Loader", "yaml.UnsafeLoader", "yaml.FullLoader"}:
                self.add("AIC001", node, "yaml.load() without SafeLoader; use yaml.safe_load")
        # AIC002 / AIC003 / AIC004
        sink = name in {"eval", "exec", "os.system", "os.popen"} or name.startswith("subprocess.")
        if sink and self.uses_taint(node):
            self.add("AIC002", node, f"model output flows into {name}()")
        if name in {"eval", "exec"} and node.args and not isinstance(node.args[0], ast.Constant):
            self.add("AIC003", node, f"{name}() with a non-literal argument")
        if name in {"os.system", "os.popen"} or (name.startswith("subprocess.") and is_true(kwarg(node, "shell"))):
            self.add("AIC004", node, f"{name}() uses a shell")
        # AIC006 / AIC008
        if is_true(kwarg(node, "trust_remote_code")):
            self.add("AIC006", node, "trust_remote_code=True executes code from the model repo")
        if last == "from_pretrained" and kwarg(node, "revision") is None:
            self.add("AIC008", node, "from_pretrained() without revision= (pin a commit hash)")
        # AIC007
        if name.startswith("requests.") and is_false(kwarg(node, "verify")):
            self.add("AIC007", node, "TLS certificate verification disabled")
        self.generic_visit(node)


def scan_source(source: str) -> list[Finding]:
    tree = ast.parse(source)
    v = Visitor()
    v.visit(tree)
    return sorted(v.findings, key=lambda f: (f.line, f.rule))


def scan_file(path: str | Path) -> list[Finding]:
    return scan_source(Path(path).read_text(encoding="utf-8"))


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    total = 0
    for p in argv:
        findings = scan_file(p)
        for f in findings:
            print(f"{p}: {f}")
        total += len(findings)
    print(f"\n{total} finding(s)")
    return 1 if total else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
