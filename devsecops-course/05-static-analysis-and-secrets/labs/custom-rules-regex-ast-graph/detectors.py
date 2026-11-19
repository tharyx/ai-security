"""The same rule ("SQL built from user input reaches execute()") written three ways.

  regex  : one pattern per line of text. Cheap, fast, blind to structure.
  ast    : looks at the shape of the call's first argument. Sees structure, not data flow.
  graph  : a tiny taint tracker (source -> propagation -> sink, sanitizers, branches, helper summaries).
           A teaching model of what CodeQL and Semgrep taint mode do. Not a real engine.
All three only PARSE the fixture; nothing is executed.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

# ------------------------------------------------------------------ shared helpers


@dataclass
class Hit:
    detector: str
    line: int
    function: str
    why: str


def function_ranges(tree: ast.AST) -> list[tuple[str, int, int]]:
    return [(n.name, n.lineno, n.end_lineno or n.lineno) for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def function_of(ranges, line: int) -> str:
    inside = [r for r in ranges if r[1] <= line <= r[2]]
    return min(inside, key=lambda r: r[2] - r[1])[0] if inside else ""


def dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def is_sink(call: ast.Call) -> bool:
    return isinstance(call.func, ast.Attribute) and call.func.attr in ("execute", "executemany")


# ------------------------------------------------------------------ 1. regex

# execute( then, on the same line: an f-string, OR a string literal followed by + or %, OR .format(
REGEX = re.compile(r"""\.execute\(\s*(?:f["']|["'][^"']*["']\s*[+%]|[^,)]*\.format\()""")


def detect_regex(source: str) -> list[Hit]:
    ranges = function_ranges(ast.parse(source))
    return [Hit("regex", n, function_of(ranges, n), "pattern matched on this line")
            for n, line in enumerate(source.splitlines(), 1) if REGEX.search(line)]


# ------------------------------------------------------------------ 2. ast


def _literal(n: ast.AST) -> bool:
    if isinstance(n, ast.Constant):
        return True
    if isinstance(n, ast.BinOp):
        return _literal(n.left) and _literal(n.right)      # constant folding: "a" + "b"
    return False


def detect_ast(source: str) -> list[Hit]:
    tree = ast.parse(source)
    ranges = function_ranges(tree)
    hits = []
    for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call) and is_sink(n)):
        if not call.args:
            continue
        a = call.args[0]
        built = (isinstance(a, ast.BinOp) and isinstance(a.op, (ast.Add, ast.Mod))) or isinstance(a, ast.JoinedStr) or (
            isinstance(a, ast.Call) and isinstance(a.func, ast.Attribute) and a.func.attr == "format")
        if built and not _literal(a):
            hits.append(Hit("ast", call.lineno, function_of(ranges, call.lineno),
                            f"first argument is built with {type(a).__name__} from a non-constant"))
    return hits


# ------------------------------------------------------------------ 3. graph (taint tracking)

SOURCE_PREFIXES = ("request.args", "request.form", "request.values", "request.json", "request.get_json",
                   "request.cookies", "request.data", "input", "sys.argv")
SANITIZERS = {"int", "float", "bool", "len", "escape_sql", "quote_ident"}

Path_ = list[str]


class Taint:
    """Flow-sensitive inside a function, with if/else merging and one level of helper summaries."""

    def __init__(self, tree: ast.Module):
        self.tree = tree
        self.ranges = function_ranges(tree)
        self.funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
        self.summary: dict[str, bool] = {}          # helper returns tainted data when its arguments are tainted
        self.hits: list[Hit] = []
        for name, fn in self.funcs.items():
            if fn.args.args:
                self.summary[name] = self._analyse(fn, params_tainted=True, report=False)

    # -- expressions
    def expr(self, e: ast.AST, env: dict[str, Path_]) -> Path_ | None:
        if e is None or isinstance(e, ast.Constant):
            return None
        if isinstance(e, ast.Name):
            return env.get(e.id)
        if isinstance(e, (ast.Attribute, ast.Subscript)):
            base = e.value
            d = dotted(base if isinstance(e, ast.Subscript) else e)
            if d.startswith(SOURCE_PREFIXES):
                return [f"source {d} (line {e.lineno})"]
            return self.expr(base, env)
        if isinstance(e, ast.Call):
            name = dotted(e.func)
            if name.startswith(SOURCE_PREFIXES):
                return [f"source {name}() (line {e.lineno})"]
            if name in SANITIZERS:
                return None
            args = [self.expr(a, env) for a in e.args] + [self.expr(k.value, env) for k in e.keywords]
            recv = self.expr(e.func.value, env) if isinstance(e.func, ast.Attribute) else None
            if name in self.summary:
                return next((p + [f"through {name}() (line {e.lineno})"] for p in args if p and self.summary[name]), None)
            return next((p for p in args + [recv] if p), None)       # unknown call: propagate conservatively
        if isinstance(e, ast.BinOp):
            return self.expr(e.left, env) or self.expr(e.right, env)
        if isinstance(e, ast.JoinedStr):
            return next((p for v in e.values if isinstance(v, ast.FormattedValue) and (p := self.expr(v.value, env))), None)
        if isinstance(e, (ast.Tuple, ast.List, ast.Set)):
            return next((p for x in e.elts if (p := self.expr(x, env))), None)
        if isinstance(e, ast.IfExp):
            return self.expr(e.body, env) or self.expr(e.orelse, env)
        if isinstance(e, ast.BoolOp):
            return next((p for x in e.values if (p := self.expr(x, env))), None)
        return None

    # -- statements
    def _sinks(self, node: ast.AST, env, report: bool):
        for c in ast.walk(node):
            if isinstance(c, ast.Call) and is_sink(c) and c.args and report:
                path = self.expr(c.args[0], env)
                if path:
                    self.hits.append(Hit("graph", c.lineno, function_of(self.ranges, c.lineno),
                                         " -> ".join(path + [f"sink execute() (line {c.lineno})"])))

    def _block(self, body, env, report) -> bool:
        returns_taint = False
        for st in body:
            if isinstance(st, (ast.FunctionDef, ast.ClassDef)):
                continue
            if isinstance(st, ast.If):
                self._sinks(st.test, env, report)
                a, b = dict(env), dict(env)
                ra = self._block(st.body, a, report)
                rb = self._block(st.orelse, b, report)
                returns_taint |= ra or rb
                env.clear()
                for k in set(a) | set(b):
                    if k in a or k in b:
                        env[k] = a.get(k) or b.get(k)       # tainted on either path stays tainted
                continue
            self._sinks(st, env, report)
            if isinstance(st, ast.Assign):
                t = self.expr(st.value, env)
                for target in st.targets:
                    if isinstance(target, ast.Name):
                        if t:
                            env[target.id] = t + [f"{target.id} = ... (line {st.lineno})"]
                        else:
                            env.pop(target.id, None)         # overwritten with a clean value: taint is killed
            elif isinstance(st, ast.AugAssign) and isinstance(st.target, ast.Name):
                t = self.expr(st.value, env)
                if t:
                    env[st.target.id] = t
            elif isinstance(st, ast.Return) and st.value is not None:
                returns_taint |= bool(self.expr(st.value, env))
            elif isinstance(st, (ast.For, ast.While, ast.With, ast.Try)):
                for attr in ("body", "orelse", "finalbody"):
                    returns_taint |= self._block(getattr(st, attr, []), env, report)
        return returns_taint

    def _analyse(self, fn: ast.FunctionDef, params_tainted: bool, report: bool) -> bool:
        env: dict[str, Path_] = {a.arg: [f"parameter {a.arg}"] for a in fn.args.args} if params_tainted else {}
        return self._block(fn.body, env, report)

    def run(self) -> list[Hit]:
        for fn in self.funcs.values():
            if not fn.args.args:                 # entry points with no parameters read sources directly
                self._analyse(fn, params_tainted=False, report=True)
        return sorted(self.hits, key=lambda h: h.line)


def detect_graph(source: str) -> list[Hit]:
    return Taint(ast.parse(source)).run()


# ------------------------------------------------------------------ scoring

TRUTH = re.compile(r"#\s*truth:\s*(vuln|safe)")
DETECTORS = {"regex": detect_regex, "ast": detect_ast, "graph": detect_graph}


def ground_truth(source: str) -> dict[str, str]:
    lines = source.splitlines()
    out = {}
    for n in ast.walk(ast.parse(source)):
        if isinstance(n, ast.FunctionDef):
            m = TRUTH.search(lines[n.lineno - 1])
            if m:
                out[n.name] = m.group(1)
    return out


def score(source: str, detector: str) -> dict:
    truth = ground_truth(source)
    flagged = {h.function for h in DETECTORS[detector](source)} & set(truth)
    vuln = {k for k, v in truth.items() if v == "vuln"}
    tp, fp, fn = flagged & vuln, flagged - vuln, vuln - flagged
    p = len(tp) / (len(tp) + len(fp)) if tp or fp else 1.0
    r = len(tp) / (len(tp) + len(fn)) if tp or fn else 1.0
    return {"tp": sorted(tp), "fp": sorted(fp), "fn": sorted(fn), "precision": round(p, 2), "recall": round(r, 2)}
