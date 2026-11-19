"""bandit_lite: a small Bandit-like framework (offline, standard library only).

It copies the SHAPE of Bandit's plugin API so you learn the real thing faster:
  * a check is a function that receives a `Context` and returns an `Issue` (or None);
  * decorators declare which AST node types it wants (`@checks("Call")`) and its id (`@test_id("E901")`);
  * `# nosec` and `# nosec E901` comments suppress findings;
  * severity and confidence are separate, and CWE is attached.
The real Bandit differs in details (import paths, Issue fields, plugin discovery through
entry points). See the 'real Bandit plugin' section of the lab README, and verify against the docs
of the Bandit version you use.
The scanner PARSES code with ast. It never imports or executes it.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

HIGH, MEDIUM, LOW = "HIGH", "MEDIUM", "LOW"
RANK = {LOW: 1, MEDIUM: 2, HIGH: 3}


# ------------------------------------------------------------------ decorators and registry

def checks(*node_types: str):
    def deco(fn):
        fn._checks = node_types
        return fn
    return deco


def test_id(ident: str):
    def deco(fn):
        fn._test_id = ident
        return fn
    return deco


test_id.__test__ = False       # tell pytest this helper is not a test


def load_checks(module) -> list[Callable]:
    """Plugin discovery. Real Bandit finds plugins through Python entry points; here we scan a module."""
    return [f for f in vars(module).values() if callable(f) and hasattr(f, "_checks") and hasattr(f, "_test_id")]


@dataclass
class Issue:
    severity: str
    confidence: str
    cwe: int
    text: str
    test_id: str = ""
    lineno: int = 0
    filename: str = ""
    code: str = ""


# ------------------------------------------------------------------ context

class Context:
    """What a check sees. Mirrors the most useful properties of Bandit's context object."""

    def __init__(self, node: ast.AST, filename: str, aliases: dict[str, str], function: ast.AST | None,
                 consts: dict[str, ast.AST]):
        self.node, self.filename, self.aliases, self.function, self.module_consts = node, filename, aliases, function, consts

    # --- calls
    @property
    def call_function_name_qual(self) -> str:
        """Dotted name of the callee with import aliases resolved: `import corp_http as h; h.get()` -> corp_http.get"""
        if not isinstance(self.node, ast.Call):
            return ""
        parts, cur = [], self.node.func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(self.aliases.get(cur.id, cur.id))
            return ".".join(reversed(parts))
        return ""

    @property
    def call_function_name(self) -> str:
        return self.call_function_name_qual.rsplit(".", 1)[-1]

    @property
    def call_args(self) -> list[ast.AST]:
        return list(self.node.args) if isinstance(self.node, ast.Call) else []

    @property
    def call_keywords(self) -> dict[str, ast.AST]:
        return {k.arg: k.value for k in self.node.keywords if k.arg} if isinstance(self.node, ast.Call) else {}

    @property
    def has_kwargs_splat(self) -> bool:
        return isinstance(self.node, ast.Call) and any(k.arg is None for k in self.node.keywords)

    # --- functions
    @property
    def function_name(self) -> str:
        return getattr(self.node, "name", "")

    @property
    def decorators(self) -> list[str]:
        out = []
        for d in getattr(self.node, "decorator_list", []):
            d = d.func if isinstance(d, ast.Call) else d
            out.append(ast.unparse(d))
        return out

    # --- helpers
    def local_assignments(self) -> dict[str, ast.AST]:
        """Latest simple `name = expr` inside the enclosing function (enough for the lab, not a data-flow engine)."""
        env: dict[str, ast.AST] = {}
        if self.function is not None:
            for n in ast.walk(self.function):
                if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                    env[n.targets[0].id] = n.value
        return env


# ------------------------------------------------------------------ manager

NOSEC = re.compile(r"#\s*nosec(?:\s+([A-Za-z0-9_, ]+))?")


def _aliases(tree: ast.AST) -> dict[str, str]:
    out: dict[str, str] = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                out[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(n, ast.ImportFrom) and n.module:
            for a in n.names:
                out[a.asname or a.name] = f"{n.module}.{a.name}"
    return out


def _functions_by_node(tree: ast.AST) -> dict[ast.AST, ast.AST | None]:
    owner: dict[ast.AST, ast.AST | None] = {}

    def visit(node, fn):
        for child in ast.iter_child_nodes(node):
            cur = child if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else fn
            owner[child] = cur if cur is not child else fn
            visit(child, cur)

    visit(tree, None)
    return owner


def scan_source(source: str, filename: str, plugins: list[Callable]) -> list[Issue]:
    tree = ast.parse(source, filename)
    lines = source.splitlines()
    aliases = _aliases(tree)
    owner = _functions_by_node(tree)
    consts: dict[str, ast.AST] = {}
    for n in tree.body:
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            consts[n.targets[0].id] = n.value
    issues: list[Issue] = []
    for node in ast.walk(tree):
        kind = type(node).__name__
        for plugin in plugins:
            if kind not in plugin._checks:
                continue
            ctx = Context(node, filename, aliases, owner.get(node), consts)
            res = plugin(ctx)
            if res is None:
                continue
            res.test_id, res.filename = plugin._test_id, filename
            res.lineno = getattr(node, "lineno", 0)
            res.code = lines[res.lineno - 1].strip() if 0 < res.lineno <= len(lines) else ""
            m = NOSEC.search(lines[res.lineno - 1]) if 0 < res.lineno <= len(lines) else None
            if m and (not m.group(1) or res.test_id in [x.strip() for x in m.group(1).split(",")]):
                continue
            issues.append(res)
    return sorted(issues, key=lambda i: (i.filename, i.lineno, i.test_id))


def scan_path(root: Path, plugins: list[Callable]) -> list[Issue]:
    root = Path(root)
    files = [root] if root.is_file() else sorted(root.rglob("*.py"))
    out: list[Issue] = []
    for p in files:
        rel = p.name if root.is_file() else p.relative_to(root).as_posix()
        out += scan_source(p.read_text(encoding="utf-8"), rel, plugins)
    return out


# ------------------------------------------------------------------ built-in checks (a few of Bandit's, simplified)

def _is_const_str(n: ast.AST) -> bool:
    return isinstance(n, ast.Constant) and isinstance(n.value, str)


@checks("Assert")
@test_id("B101")
def assert_used(ctx):
    return Issue(LOW, HIGH, 703, "Use of assert detected; it is removed when Python runs with -O.")


@checks("Call")
@test_id("B307")
def eval_used(ctx):
    if ctx.call_function_name_qual in ("eval", "exec"):
        return Issue(MEDIUM, HIGH, 78, f"Use of {ctx.call_function_name}() is insecure.")


@checks("Call")
@test_id("B301")
def pickle_used(ctx):
    if ctx.call_function_name_qual in ("pickle.loads", "pickle.load"):
        return Issue(MEDIUM, HIGH, 502, "Pickle can run code while loading untrusted data.")


@checks("Call")
@test_id("B324")
def weak_hash(ctx):
    if ctx.call_function_name_qual in ("hashlib.md5", "hashlib.sha1"):
        return Issue(HIGH, HIGH, 327, f"Use of weak hash {ctx.call_function_name}.")


@checks("Call")
@test_id("B501")
def verify_false(ctx):
    v = ctx.call_keywords.get("verify")
    if ctx.call_function_name_qual.split(".")[0] in ("requests", "httpx") and isinstance(v, ast.Constant) and v.value is False:
        return Issue(HIGH, HIGH, 295, "Certificate validation is disabled.")


@checks("Call")
@test_id("B506")
def yaml_load(ctx):
    if ctx.call_function_name_qual == "yaml.load" and "Loader" not in ctx.call_keywords:
        return Issue(MEDIUM, HIGH, 20, "yaml.load without a safe Loader can build arbitrary objects.")


@checks("Call")
@test_id("B602")
def shell_true(ctx):
    v = ctx.call_keywords.get("shell")
    if ctx.call_function_name_qual.startswith("subprocess.") and isinstance(v, ast.Constant) and v.value is True:
        return Issue(HIGH, HIGH if not (ctx.call_args and _is_const_str(ctx.call_args[0])) else LOW, 78,
                     "subprocess call with shell=True.")


@checks("BinOp", "JoinedStr", "Call")
@test_id("B608")
def sql_string_building(ctx):
    """Naive on purpose: any SQL-looking string that is BUILT instead of constant. This mirrors the real
    B608, which is a known source of false positives (constants and ints are fine to concatenate)."""
    n = ctx.node
    text = None
    if isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Add, ast.Mod)):
        left = n.left
        text = left.value if _is_const_str(left) else None
    elif isinstance(n, ast.JoinedStr):
        text = "".join(v.value for v in n.values if isinstance(v, ast.Constant) and isinstance(v.value, str))
    elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "format" and _is_const_str(n.func.value):
        text = n.func.value.value
    if text and re.match(r"\s*(select|insert|update|delete)\b", text, re.I):
        return Issue(MEDIUM, LOW, 89, "Possible SQL injection vector through string-based query construction.")
