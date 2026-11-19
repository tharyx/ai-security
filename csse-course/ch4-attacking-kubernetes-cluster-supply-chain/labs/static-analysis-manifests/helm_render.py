"""A tiny Helm-style template renderer (values substitution, quote/default/upper, if/else/end).

It is NOT Helm: no Sprig library, no `include`, `range`, `with` or `toYaml`, and templates using them raise. It is
enough to render the lab chart and run the static checks on the RESULT, which is the real lesson: scan what the
chart renders to, not just the template source, because values change the output.
"""
from __future__ import annotations

import re
import shlex
from pathlib import Path

import yaml

ACTION = re.compile(r"\{\{(-?)\s*(.*?)\s*(-?)\}\}", re.S)


class TemplateError(Exception):
    pass


def deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in (override or {}).items():
        out[k] = deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def lookup(path: str, ctx: dict):
    cur = ctx
    for part in path.lstrip(".").split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def literal_or_path(token: str, ctx: dict):
    if token.startswith(('"', "'")):
        return token[1:-1]
    if re.fullmatch(r"-?\d+", token):
        return int(token)
    if token in ("true", "false"):
        return token == "true"
    if token.startswith("."):
        return lookup(token, ctx)
    raise TemplateError(f"unsupported token {token!r}")


def apply_func(name: str, args: list, piped=None, has_piped=False):
    vals = args + ([piped] if has_piped else [])
    if name == "quote":
        return '"' + str(vals[0]).replace('"', '\\"') + '"'
    if name == "upper":
        return str(vals[0]).upper()
    if name == "default":
        fallback, value = vals[0], vals[1] if len(vals) > 1 else None
        return value if value not in (None, "", 0, False) else fallback
    if name == "not":
        return not vals[0]
    raise TemplateError(f"unsupported function {name!r}")


def eval_expr(expr: str, ctx: dict):
    stages = [s.strip() for s in expr.split("|")]
    value, have = None, False
    for i, stage in enumerate(stages):
        tokens = shlex.split(stage, posix=False)
        head = tokens[0]
        if head in ("quote", "upper", "default", "not"):
            args = [literal_or_path(t, ctx) for t in tokens[1:]]
            value = apply_func(head, args, value, have)
        elif i == 0 and len(tokens) == 1:
            value = literal_or_path(head, ctx)
        else:
            raise TemplateError(f"unsupported expression {stage!r} (this mini renderer has no Sprig)")
        have = True
    return value


def render(template: str, ctx: dict) -> str:
    """Handle {{ expr }}, {{- trimming -}}, and {{ if X }} ... {{ else }} ... {{ end }} (nesting allowed)."""
    parts, pos = [], 0
    for m in ACTION.finditer(template):
        text = template[pos:m.start()]
        if m.group(1):
            text = text.rstrip()
        parts.append(("text", text))
        parts.append(("act", m.group(2)))
        if m.group(3):
            # right trim applies to the following text
            parts.append(("trim", ""))
        pos = m.end()
    parts.append(("text", template[pos:]))
    # apply right-trim markers
    cleaned = []
    trim_next = False
    for kind, val in parts:
        if kind == "trim":
            trim_next = True
            continue
        if kind == "text" and trim_next:
            val = val.lstrip()
        trim_next = False
        cleaned.append((kind, val))
    out, stack = [], [True]  # stack of "currently emitting"
    branch_taken: list[bool] = []
    for kind, val in cleaned:
        if kind == "text":
            if all(stack):
                out.append(val)
            continue
        if val.startswith("if "):
            cond = bool(eval_expr(val[3:], ctx)) if all(stack) else False
            branch_taken.append(cond)
            stack.append(cond)
        elif val == "else":
            stack[-1] = (not branch_taken[-1]) and all(stack[:-1])
        elif val == "end":
            stack.pop()
            branch_taken.pop()
        elif val.startswith("/*"):
            continue
        elif all(stack):
            v = eval_expr(val, ctx)
            out.append("" if v is None else str(v))
    if len(stack) != 1:
        raise TemplateError("unclosed if block")
    return "".join(out)


def render_chart(chart_dir: str | Path, overrides: dict | None = None, release: str = "demo", namespace: str = "default") -> list[dict]:
    chart_dir = Path(chart_dir)
    meta = yaml.safe_load((chart_dir / "Chart.yaml").read_text())
    values = deep_merge(yaml.safe_load((chart_dir / "values.yaml").read_text()) or {}, overrides or {})
    ctx = {"Values": values, "Release": {"Name": release, "Namespace": namespace}, "Chart": {"Name": meta["name"], "Version": meta["version"]}}
    docs: list[dict] = []
    for tpl in sorted((chart_dir / "templates").glob("*.yaml")):
        text = render(tpl.read_text(), ctx)
        docs += [d for d in yaml.safe_load_all(text) if d]
    return docs
