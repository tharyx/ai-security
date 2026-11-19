"""Tiny SAST: an AST scanner with a little taint tracking (Python source only).

It PARSES source with `ast`; it never imports or runs the code it scans.
Real SAST (Semgrep, Bandit, CodeQL, SonarQube) has far more rules and real data-flow analysis.
Expect false positives and false negatives here; the point is to see how rules are built.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

SECRET_NAMES = ("password", "passwd", "secret", "token", "api_key", "apikey", "private_key")
SANITIZERS = {"escape", "quote", "validate_url", "safe_join", "int", "secure_filename", "float"}
SEV = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    rule: str
    severity: str
    line: int
    cwe: str
    message: str


def dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def uses_request(node: ast.AST) -> bool:
    return any(isinstance(n, ast.Name) and n.id == "request" for n in ast.walk(node))


def is_const_str(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def is_dynamic_string(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format"


class Scanner(ast.NodeVisitor):
    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.tainted: set[str] = set()

    def add(self, rule: str, sev: str, node: ast.AST, cwe: str, msg: str) -> None:
        self.findings.append(Finding(rule, sev, getattr(node, "lineno", 0), cwe, msg))

    def is_tainted(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call) and dotted(node.func).split(".")[-1] in SANITIZERS:
            return False
        return uses_request(node) or bool(names_in(node) & self.tainted)

    # --- taint propagation and hardcoded secrets ---
    def visit_Assign(self, node: ast.Assign) -> None:
        for t in node.targets:
            if isinstance(t, ast.Name):
                if self.is_tainted(node.value):
                    self.tainted.add(t.id)
                else:
                    self.tainted.discard(t.id)
                if any(s in t.id.lower() for s in SECRET_NAMES) and is_const_str(node.value) and len(node.value.value) >= 6:
                    self.add("SAST004", "high", node, "CWE-798", f"hardcoded secret in variable '{t.id}'")
        self.generic_visit(node)

    # --- calls ---
    def visit_Call(self, node: ast.Call) -> None:
        name = dotted(node.func)
        last = name.split(".")[-1]
        kw = {k.arg: k.value for k in node.keywords if k.arg}
        args_tainted = any(self.is_tainted(a) for a in [*node.args, *kw.values()])

        if name in ("eval", "exec"):
            self.add("SAST001", "critical" if args_tainted else "high", node, "CWE-95", f"{name}() on dynamic input")
        if name in ("os.system", "os.popen") or (name.startswith("subprocess.") and isinstance(kw.get("shell"), ast.Constant) and kw["shell"].value is True):
            self.add("SAST002", "critical" if args_tainted else "high", node, "CWE-78", "shell command execution")
        if name in ("pickle.loads", "pickle.load", "marshal.loads"):
            self.add("SAST003", "high", node, "CWE-502", f"{name} on untrusted data can run code")
        if name == "yaml.load" and "Loader" not in kw and len(node.args) < 2:
            self.add("SAST003", "high", node, "CWE-502", "yaml.load without a safe Loader")
        if last == "execute" and node.args and is_dynamic_string(node.args[0]):
            self.add("SAST005", "critical" if args_tainted else "high", node, "CWE-89", "SQL built by string formatting; use parameters")
        if name in ("hashlib.md5", "hashlib.sha1"):
            self.add("SAST006", "medium", node, "CWE-328", f"{name} is weak; do not use it for passwords or signatures")
        if name.startswith("requests.") and isinstance(kw.get("verify"), ast.Constant) and kw["verify"].value is False:
            self.add("SAST007", "high", node, "CWE-295", "TLS verification disabled")
        if last == "run" and isinstance(kw.get("debug"), ast.Constant) and kw["debug"].value is True:
            self.add("SAST008", "medium", node, "CWE-489", "debug mode enabled")
        if last in ("render_template_string", "Markup") and node.args and not is_const_str(node.args[0]) and self.is_tainted(node.args[0]):
            self.add("SAST009", "high", node, "CWE-79", f"{last}() with user-controlled text (XSS or template injection)")
        if name == "open" and node.args and self.is_tainted(node.args[0]):
            self.add("SAST010", "high", node, "CWE-22", "file path comes from the request (path traversal)")
        if name in ("requests.get", "requests.post", "urllib.request.urlopen", "urlopen") and node.args and self.is_tainted(node.args[0]):
            self.add("SAST011", "high", node, "CWE-918", "outbound request to a user-controlled URL (SSRF)")
        if name == "tempfile.mktemp":
            self.add("SAST012", "low", node, "CWE-377", "mktemp is racy; use mkstemp or NamedTemporaryFile")
        self.generic_visit(node)


def scan_source(source: str) -> list[Finding]:
    tree = ast.parse(source)
    s = Scanner()
    s.visit(tree)
    return sorted(s.findings, key=lambda f: (f.line, f.rule))


def exit_code(findings: list[Finding], fail_on: str = "high") -> int:
    return 1 if any(SEV[f.severity] >= SEV[fail_on] for f in findings) else 0
