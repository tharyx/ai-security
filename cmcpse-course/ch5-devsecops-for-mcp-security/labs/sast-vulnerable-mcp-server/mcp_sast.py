"""AST-based SAST for MCP server code. Six MCP-specific rules plus the secret scanner.

Rules
  MCP001  shell execution (os.system, shell=True, eval/exec) reachable from a tool
  MCP002  path built from input without canonicalization AND a containment check
  MCP003  outbound fetch of a non-constant URL with no allowlist / validation call (SSRF)
  MCP004  secret (or secret variable) inside a tool description
  MCP005  server bound to all interfaces (0.0.0.0 or ::)
  MCP006  exception text or traceback returned to the client
  SECRET  hardcoded secret (from secret_scan.py)

The code is only parsed, never imported or run.

Usage:  python mcp_sast.py <dir-or-file> [--json]     (exit code 1 when anything is found)
"""

from __future__ import annotations

import ast
import importlib.util
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

RULES = {
    "MCP001": ("high", "Shell execution: user text can become a command (MCP05 command injection)"),
    "MCP002": ("high", "Path join without canonicalization and containment check (path traversal)"),
    "MCP003": ("high", "Outbound fetch of a non-constant URL without an allowlist (SSRF)"),
    "MCP004": ("high", "Secret inside a tool description (visible to every client and model)"),
    "MCP005": ("medium", "Server bound to all interfaces (reachable from the whole network)"),
    "MCP006": ("medium", "Exception text or traceback returned to the client (information leak)"),
    "SECRET": ("high", "Hardcoded secret"),
}

SHELL_CALLS = {"os.system", "os.popen", "eval", "exec", "subprocess.getoutput", "subprocess.getstatusoutput"}
FETCH_CALLS = {
    "urllib.request.urlopen", "urlopen", "requests.get", "requests.post", "requests.request",
    "httpx.get", "httpx.post", "httpx.request",
}
GUARD_WORDS = ("valid", "check", "allow", "safe", "ssrf")
CANON_CALLS = {"resolve", "realpath"}
CONTAIN_CALLS = {"is_relative_to", "relative_to", "commonpath", "startswith"}
SECRET_WORDS = ("api_key", "apikey", "secret", "token", "password", "passwd")
ALL_INTERFACES = {"0.0.0.0", "::"}
SAFE_EXC_ATTRS = {"public_message", "code"}


@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    line: int
    message: str

    def __str__(self) -> str:
        return f"{self.file}:{self.line}: {self.rule} [{self.severity}] {self.message}"


def _load_sibling(name: str):
    path = Path(__file__).with_name(f"{name}.py")
    spec = importlib.util.spec_from_file_location(f"mcp_sast_{name}", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def dotted(node: ast.AST) -> str:
    """Return 'os.path.join' for an attribute chain, 'eval' for a name, '' otherwise."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _is_const(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant)


def _walk_function(func: ast.AST):
    """Walk a function body without descending into nested function definitions."""
    stack = list(ast.iter_child_nodes(func))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            stack.extend(ast.iter_child_nodes(node))


def _call_names(nodes) -> set[str]:
    names: set[str] = set()
    for node in nodes:
        if isinstance(node, ast.Call):
            full = dotted(node.func)
            names.add(full)
            if isinstance(node.func, ast.Attribute):
                names.add(node.func.attr)
    return names


def _rule_shell(tree: ast.AST, fname: str) -> list[Finding]:
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = dotted(node.func)
        shell_true = name.startswith("subprocess.") and any(
            kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords
        )
        dynamic_eval = name in {"eval", "exec"} and node.args and not _is_const(node.args[0])
        if shell_true or dynamic_eval or name in {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"}:
            out.append(Finding("MCP001", RULES["MCP001"][0], fname, node.lineno, f"{name}(...) {RULES['MCP001'][1]}"))
    return out


def _rule_paths(tree: ast.AST, fname: str) -> list[Finding]:
    out = []
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = list(_walk_function(func))
        params = {a.arg for a in func.args.args + func.args.kwonlyargs}
        uses_path = any(
            (isinstance(n, ast.Name) and n.id == "Path") or dotted(n) == "pathlib.Path" for n in body
        )
        risky_line = None
        for node in body:
            if isinstance(node, ast.Call) and dotted(node.func) == "os.path.join" and any(not _is_const(a) for a in node.args):
                risky_line = risky_line or node.lineno
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div) and uses_path and not _is_const(node.right):
                risky_line = risky_line or node.lineno
            elif (
                isinstance(node, ast.Call)
                and dotted(node.func) == "open"
                and node.args
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id in params
            ):
                risky_line = risky_line or node.lineno
        if risky_line is None:
            continue
        names = _call_names(body)
        if CANON_CALLS & names and CONTAIN_CALLS & names:
            continue
        out.append(Finding("MCP002", RULES["MCP002"][0], fname, risky_line, f"in {func.name}(): {RULES['MCP002'][1]}"))
    return out


def _rule_ssrf(tree: ast.AST, fname: str) -> list[Finding]:
    out = []
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = list(_walk_function(func))
        fetch = [
            n for n in body
            if isinstance(n, ast.Call) and dotted(n.func) in FETCH_CALLS and n.args and not _is_const(n.args[0])
        ]
        if not fetch:
            continue
        names = {n.lower() for n in _call_names(body)}
        names |= {n.id.lower() for n in body if isinstance(n, ast.Name)}
        if any(word in name for name in names for word in GUARD_WORDS):
            continue
        out.append(Finding("MCP003", RULES["MCP003"][0], fname, fetch[0].lineno, f"in {func.name}(): {RULES['MCP003'][1]}"))
    return out


def _description_values(tree: ast.AST):
    """Yield (line, node) for every value used as a tool description."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and key.value == "description":
                    yield value.lineno, value
        elif isinstance(node, ast.keyword) and node.arg == "description":
            yield node.value.lineno, node.value


def _rule_description_secrets(tree: ast.AST, fname: str, secret_scan) -> list[Finding]:
    out = []
    for line, value in _description_values(tree):
        text, bad = "", False
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            text = value.value
        elif isinstance(value, ast.JoinedStr):
            for part in value.values:
                if isinstance(part, ast.Constant):
                    text += str(part.value)
                else:
                    ref = ast.unparse(part).lower()
                    bad = bad or any(word in ref for word in SECRET_WORDS)
        if text and secret_scan.scan_text(text, fname):
            bad = True
        if text and any(w in text.lower() for w in ("api key:", "password:", "token:", "secret:")):
            bad = True
        if bad:
            out.append(Finding("MCP004", RULES["MCP004"][0], fname, line, RULES["MCP004"][1]))
    return out


def _rule_bind(tree: ast.AST, fname: str) -> list[Finding]:
    return [
        Finding("MCP005", RULES["MCP005"][0], fname, node.lineno, f"{node.value!r}: {RULES['MCP005'][1]}")
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in ALL_INTERFACES
    ]


def _leaks(node: ast.AST, exc_name: str | None) -> bool:
    """True if `node` uses the caught exception (or a traceback) in a value that is returned."""
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == exc_name:
        if node.attr in SAFE_EXC_ATTRS:
            return False
    if isinstance(node, ast.Call) and dotted(node.func).split(".")[-1] in {"format_exc", "format_exception", "print_exc"}:
        return True
    if isinstance(node, ast.Name) and exc_name and node.id == exc_name:
        return True
    return any(_leaks(child, exc_name) for child in ast.iter_child_nodes(node))


def _rule_verbose_errors(tree: ast.AST, fname: str) -> list[Finding]:
    out = []
    for handler in ast.walk(tree):
        if not isinstance(handler, ast.ExceptHandler):
            continue
        for node in ast.walk(handler):
            if isinstance(node, ast.Return) and node.value is not None and _leaks(node.value, handler.name):
                out.append(Finding("MCP006", RULES["MCP006"][0], fname, node.lineno, RULES["MCP006"][1]))
                break
    return out


def scan_source(source: str, filename: str = "<source>") -> list[Finding]:
    """Scan one Python source string with the six AST rules (no secret scan of the whole file)."""
    tree = ast.parse(source, filename=filename)
    secret_scan = _load_sibling("secret_scan")
    findings = (
        _rule_shell(tree, filename)
        + _rule_paths(tree, filename)
        + _rule_ssrf(tree, filename)
        + _rule_description_secrets(tree, filename, secret_scan)
        + _rule_bind(tree, filename)
        + _rule_verbose_errors(tree, filename)
    )
    return sorted(findings, key=lambda f: (f.line, f.rule))


def scan_tree(root: str | Path, include_secrets: bool = True) -> list[Finding]:
    root = Path(root)
    files = [root] if root.is_file() else sorted(root.rglob("*.py"))
    base = root.parent if root.is_file() else root
    findings: list[Finding] = []
    for path in files:
        if "__pycache__" in path.parts:
            continue
        name = str(path.relative_to(base)).replace("\\", "/")
        findings.extend(scan_source(path.read_text(encoding="utf-8"), name))
    if include_secrets:
        secret_scan = _load_sibling("secret_scan")
        for s in secret_scan.scan_tree(root):
            findings.append(Finding("SECRET", RULES["SECRET"][0], s.file, s.line, f"{s.kind} {s.preview} ({'FAKE fixture' if s.fake else 'treat as real'})"))
    return findings


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    findings = scan_tree(argv[0])
    if "--json" in argv:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        for finding in findings:
            print(finding)
        print(f"{len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
