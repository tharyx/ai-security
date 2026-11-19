"""Four ENTERPRISE-specific checks written against the bandit_lite API.

Each rule exists because a generic scanner is noisy or blind for our own code:
  E901  corpdb.execute() with a query that is built from non-constant input (SQL injection)
  E902  calls through our corp_http wrapper without a timeout (availability)
  E903  secrets passed to logging calls (information exposure)
  E904  delete_*/admin_*/purge_* functions without a role decorator (missing authorization)
The care taken to avoid false positives is the point of the lab: read the comments.
"""
from __future__ import annotations

import ast
import re

from aisec_lab import load_lab_module

bl = load_lab_module(__file__, "bandit_lite")
Issue, checks, test_id = bl.Issue, bl.checks, bl.test_id

SQL_CALLS = {"corpdb.execute", "corpdb.executemany", "corpdb.query"}
SAFE_CASTS = {"int", "float", "len", "bool"}


def dynamic_sql(expr: ast.AST, env: dict, consts: dict, depth: int = 0) -> bool:
    """True when the SQL text depends on something that is not a constant or a numeric cast."""
    if depth > 6:
        return True
    if isinstance(expr, ast.Constant):
        return False
    if isinstance(expr, ast.Name):
        if expr.id in env:
            return dynamic_sql(env[expr.id], env, consts, depth + 1)
        if expr.id.isupper() and isinstance(consts.get(expr.id), ast.Constant):
            return False                      # module-level CONSTANT: not attacker controlled
        return True                           # a parameter or something we cannot see: assume dynamic
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
        return dynamic_sql(expr.left, env, consts, depth + 1) or dynamic_sql(expr.right, env, consts, depth + 1)
    if isinstance(expr, ast.Tuple):
        return any(dynamic_sql(e, env, consts, depth + 1) for e in expr.elts)
    if isinstance(expr, ast.JoinedStr):
        return any(dynamic_sql(v.value, env, consts, depth + 1) for v in expr.values if isinstance(v, ast.FormattedValue))
    if isinstance(expr, ast.Call):
        if isinstance(expr.func, ast.Name) and expr.func.id in SAFE_CASTS:
            return False                      # int(x) cannot carry a quote
        if isinstance(expr.func, ast.Attribute) and expr.func.attr == "format" and isinstance(expr.func.value, ast.Constant):
            return any(dynamic_sql(a, env, consts, depth + 1) for a in expr.args) or \
                any(dynamic_sql(k.value, env, consts, depth + 1) for k in expr.keywords)
    return True


@checks("Call")
@test_id("E901")
def corpdb_dynamic_query(ctx):
    if ctx.call_function_name_qual in SQL_CALLS and ctx.call_args:
        if dynamic_sql(ctx.call_args[0], ctx.local_assignments(), ctx.module_consts):
            return Issue(bl.HIGH, bl.HIGH, 89, "corpdb query text is built from non-constant input; pass values as parameters.")


@checks("Call")
@test_id("E902")
def corp_http_without_timeout(ctx):
    q = ctx.call_function_name_qual
    if q.startswith("corp_http.client.") and ctx.call_function_name in {"get", "post", "put", "delete"}:
        if "timeout" not in ctx.call_keywords and not ctx.has_kwargs_splat:
            return Issue(bl.MEDIUM, bl.HIGH, 400, "corp_http call without a timeout can hang a worker forever.")


SECRET_WORDS = re.compile(r"(password|passwd|secret|token|api_?key|ssn|card_?number|cvv)", re.I)
HARMLESS_SUFFIX = re.compile(r"_(count|len|length|ttl|type|expiry|name)$", re.I)
MASKERS = {"mask", "redact", "hash_value"}
LOG_LEVELS = {"debug", "info", "warning", "error", "exception", "critical"}


def _identifiers(expr: ast.AST):
    """Names, attribute names and constant subscript keys. String LITERALS are deliberately ignored,
    and anything wrapped in mask()/redact() is skipped."""
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name) and expr.func.id in MASKERS:
        return
    if isinstance(expr, ast.Name):
        yield expr.id
    elif isinstance(expr, ast.Attribute):
        yield expr.attr
        yield from _identifiers(expr.value)
    elif isinstance(expr, ast.Subscript):
        if isinstance(expr.slice, ast.Constant) and isinstance(expr.slice.value, str):
            yield expr.slice.value
        yield from _identifiers(expr.value)
    else:
        for child in ast.iter_child_nodes(expr):
            yield from _identifiers(child)


@checks("Call")
@test_id("E903")
def secret_in_log(ctx):
    q = ctx.call_function_name_qual
    if ctx.call_function_name in LOG_LEVELS and q.split(".")[0] in {"logger", "logging", "log"}:
        for arg in ctx.call_args[1:] + list(ctx.call_keywords.values()) + ctx.call_args[:1]:
            for ident in _identifiers(arg):
                if SECRET_WORDS.search(ident) and not HARMLESS_SUFFIX.search(ident):
                    return Issue(bl.MEDIUM, bl.HIGH, 532, f"'{ident}' looks like a secret and is written to the log.")


PRIVILEGED_PREFIXES = ("delete_", "admin_", "purge_")
ROLE_DECORATORS = {"require_role", "requires_admin"}


@checks("FunctionDef", "AsyncFunctionDef")
@test_id("E904")
def privileged_function_without_role(ctx):
    if ctx.function_name.startswith(PRIVILEGED_PREFIXES):
        if not any(d.split("(")[0].split(".")[-1] in ROLE_DECORATORS for d in ctx.decorators):
            return Issue(bl.HIGH, bl.MEDIUM, 862, f"{ctx.function_name}() has no role check decorator.")
