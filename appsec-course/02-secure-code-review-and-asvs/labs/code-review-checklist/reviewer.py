"""A small secure-code-review assistant: checklist rules over Python and template files.

It mixes two techniques real tools use:
- line regexes (fast, noisy; like grep or simple Semgrep patterns), and
- the Python AST (understands structure: "an f-string reaches .execute()").

It does NOT replace a human reviewer. It produces a checklist report a reviewer then confirms,
and a gate (exit code) for CI. ASVS references are chapter-level for ASVS 5.0 (verify at source).
"""

from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass
from pathlib import Path

CATEGORIES = [
    "Injection (SQL)",
    "Input validation",
    "Output encoding",
    "Authentication",
    "Authorization",
    "Security misconfiguration",
]


@dataclass(frozen=True)
class Finding:
    rule: str
    category: str
    severity: str
    file: str
    line: int
    message: str
    asvs: str


RULE_META = {
    "SQL001": ("Injection (SQL)", "high", "V1 Encoding and Sanitization",
               "SQL built from strings reaches execute(); use bind parameters"),
    "VAL001": ("Input validation", "medium", "V2 Validation and Business Logic",
               "re.match() without an end anchor accepts trailing junk; use re.fullmatch()"),
    "XSS001": ("Output encoding", "high", "V1 Encoding and Sanitization",
               "HTML built with untrusted values and no escape()"),
    "XSS002": ("Output encoding", "high", "V3 Web Frontend Security",
               "auto-escaping switched off or a dangerous DOM sink"),
    "AUTH001": ("Authentication", "high", "V6 Authentication / V11 Cryptography",
                "fast unsalted hash (MD5/SHA-1) used; use Argon2id, scrypt, bcrypt or PBKDF2"),
    "AUTH002": ("Authentication", "medium", "V6 Authentication / V11 Cryptography",
                "secret compared with ==; use hmac.compare_digest()"),
    "AUTH003": ("Authentication", "high", "V13 Configuration",
                "hard-coded secret; load it from a secrets manager or the environment"),
    "AUTHZ001": ("Authorization", "high", "V8 Authorization",
                 "route has no authentication/authorization decorator"),
    "AUTHZ002": ("Authorization", "high", "V8 Authorization",
                 "object fetched by id without an owner filter (possible IDOR/BOLA)"),
    "CONF001": ("Security misconfiguration", "high", "V13 Configuration", "debug mode enabled"),
    "CONF002": ("Security misconfiguration", "medium", "V13 Configuration / V4 API and Web Service",
                "wildcard host or CORS origin"),
    "CONF003": ("Security misconfiguration", "medium", "V7 Session Management / V3 Web Frontend Security",
                "session cookie without Secure or HttpOnly"),
    "CONF004": ("Security misconfiguration", "high", "V12 Secure Communication",
                "TLS certificate verification disabled (verify=False)"),
}

LINE_RULES = [
    ("VAL001", re.compile(r"re\.match\(\s*r?[\"'](?P<pat>[^\"']*)[\"']")),
    ("XSS002", re.compile(r"\|\s*safe\b|\{%\s*autoescape\s+false|\binnerHTML\s*=|document\.write\(|"
                          r"\bMarkup\(|\bmark_safe\(")),
    ("AUTH001", re.compile(r"hashlib\.(md5|sha1)\(|hashlib\.new\(\s*[\"'](md5|sha1)")),
    ("AUTH002", re.compile(r"(token|password|secret|api_?key|pw_hash)\w*[\"'\]\)]*\s*==|"
                           r"==\s*\w*(token|password|secret|pw_hash)", re.I)),
    ("AUTH003", re.compile(r"^\s*\w*(SECRET_KEY|PASSWORD|API_KEY|TOKEN)\s*=\s*[\"'][^\"']+[\"']")),
    ("CONF001", re.compile(r"^\s*DEBUG\s*=\s*True\b|\.run\([^)]*debug\s*=\s*True")),
    ("CONF002", re.compile(r"(ALLOWED_HOSTS|CORS\w*)\s*=\s*\[?\s*[\"']\*[\"']")),
    ("CONF003", re.compile(r"SESSION_COOKIE_(SECURE|HTTPONLY)\s*=\s*False")),
    ("CONF004", re.compile(r"verify\s*=\s*False")),
]

PUBLIC_ROUTES = {"/", "/login", "/search", "/health"}
AUTH_DECORATORS = {"login_required", "require_role", "roles_required", "permission_required"}
ESCAPERS = {"escape", "quote_html", "escape_html"}


def _make(rule: str, file: str, line: int, extra: str = "") -> Finding:
    cat, sev, asvs, msg = RULE_META[rule]
    return Finding(rule, cat, sev, file, line, msg + (f" ({extra})" if extra else ""), asvs)


def _is_string_building(node) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format")


def _call_name(node) -> str:
    f = node.func if isinstance(node, ast.Call) else node
    if isinstance(f, ast.Attribute):
        return f.attr
    if isinstance(f, ast.Name):
        return f.id
    return ""


def _html_with_unescaped_value(node) -> bool:
    if isinstance(node, ast.JoinedStr):
        consts = "".join(v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str))
        if "<" not in consts:
            return False
        return any(isinstance(v, ast.FormattedValue)
                   and not (isinstance(v.value, ast.Call) and _call_name(v.value) in ESCAPERS)
                   for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        left = node.left
        return isinstance(left, ast.Constant) and isinstance(left.value, str) and "<" in left.value
    return False


def review_python_ast(src: str, file: str) -> list:
    findings = []
    tree = ast.parse(src)
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        # --- SQL001: string-built SQL reaching execute(), directly or through a variable
        tainted = set()
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign) and _is_string_building(node.value):
                tainted |= {t.id for t in node.targets if isinstance(t, ast.Name)}
        for node in ast.walk(fn):
            if isinstance(node, ast.Call) and _call_name(node) in ("execute", "executemany", "raw") and node.args:
                arg = node.args[0]
                if _is_string_building(arg) or (isinstance(arg, ast.Name) and arg.id in tainted):
                    findings.append(_make("SQL001", file, node.lineno, f"in {fn.name}()"))
        # --- XSS001: HTML assembled with unescaped values
        for node in ast.walk(fn):
            if _html_with_unescaped_value(node):
                findings.append(_make("XSS001", file, node.lineno, f"in {fn.name}()"))
        # --- AUTHZ001: route without an auth decorator
        route, decorators = None, set()
        for d in fn.decorator_list:
            name = _call_name(d) if isinstance(d, ast.Call) else (d.id if isinstance(d, ast.Name) else "")
            decorators.add(name)
            if name == "route" and isinstance(d, ast.Call) and d.args and isinstance(d.args[0], ast.Constant):
                route = d.args[0].value
        if route and route not in PUBLIC_ROUTES and not decorators & AUTH_DECORATORS:
            findings.append(_make("AUTHZ001", file, fn.lineno, f"{route} in {fn.name}()"))
    # --- AUTHZ002: SELECT ... WHERE id = ? with no owner column
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            s = node.value.upper()
            if "SELECT" in s and re.search(r"WHERE\s+ID\s*=", s) and not re.search(r"USER_ID|OWNER", s):
                findings.append(_make("AUTHZ002", file, node.lineno))
    return findings


def review_lines(src: str, file: str) -> list:
    findings = []
    for no, line in enumerate(src.splitlines(), 1):
        if line.lstrip().startswith("#") or line.lstrip().startswith("<!--"):
            continue
        for rule, rx in LINE_RULES:
            m = rx.search(line)
            if not m:
                continue
            if rule == "VAL001" and (m.group("pat").endswith("$") or m.group("pat").endswith(r"\Z")):
                continue
            if rule == "AUTH003" and "environ" in line:
                continue
            findings.append(_make(rule, file, no))
    return findings


def review_file(path: Path, root: Path) -> list:
    src = path.read_text(encoding="utf-8")
    rel = path.relative_to(root).as_posix()
    out = review_lines(src, rel)
    if path.suffix == ".py":
        out += review_python_ast(src, rel)
    return out


def review_tree(root: Path) -> list:
    root = Path(root)
    findings = []
    for p in sorted(root.rglob("*")):
        if p.suffix in (".py", ".html", ".js") and p.is_file():
            findings += review_file(p, root)
    return sorted(set(findings), key=lambda f: (f.file, f.line, f.rule))


def checklist(findings: list) -> dict:
    """Category -> 'PASS' or 'FAIL' (a reviewer still confirms each FAIL)."""
    failed = {f.category for f in findings}
    return {c: ("FAIL" if c in failed else "PASS") for c in CATEGORIES}


def report(findings: list, title: str = "Secure code review") -> str:
    lines = [f"# {title}", "", "| Checklist area | Result |", "|---|---|"]
    for cat, res in checklist(findings).items():
        lines.append(f"| {cat} | {res} |")
    lines += ["", "| Rule | Sev | Location | Finding | ASVS 5.0 chapter (verify) |", "|---|---|---|---|---|"]
    for f in findings:
        lines.append(f"| {f.rule} | {f.severity} | {f.file}:{f.line} | {f.message} | {f.asvs} |")
    return "\n".join(lines)


def gate(findings: list) -> int:
    return 1 if any(f.severity == "high" for f in findings) else 0


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "fixtures" / "vulnerable"
    fs = review_tree(target)
    print(report(fs))
    sys.exit(gate(fs))
