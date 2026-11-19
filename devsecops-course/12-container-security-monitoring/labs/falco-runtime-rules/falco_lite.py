"""A tiny interpreter for a SUBSET of Falco's rule language (not Falco itself).

Supports: list / macro / rule items; conditions with and, or, not, parentheses,
comparisons (=, !=, <, >, <=, >=, contains, icontains, startswith, endswith, in),
macro and list references; %field substitution in `output`. Fields are read from flat
JSON events. Real Falco has far more fields, exceptions, and a kernel/eBPF event source:
verify syntax at https://falco.org/docs/ (Falco is a CNCF graduated project).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

import yaml

TOKEN = re.compile(r"""\s*(\(|\)|,|!=|<=|>=|=|<|>|"[^"]*"|'[^']*'|[^\s(),=!<>]+)""")
OPS = {"=", "!=", "<", ">", "<=", ">=", "contains", "icontains", "startswith", "endswith", "in"}


def tokenize(s: str) -> list[str]:
    pos, out = 0, []
    s = s.strip()
    while pos < len(s):
        m = TOKEN.match(s, pos)
        if not m:
            raise ValueError(f"bad token at {s[pos:pos + 10]!r}")
        out.append(m.group(1))
        pos = m.end()
    return out


class Parser:
    def __init__(self, tokens, macros, lists):
        self.t, self.i, self.macros, self.lists = tokens, 0, macros, lists

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    def eat(self, want=None):
        tok = self.peek()
        if tok is None or (want is not None and tok != want):
            raise ValueError(f"expected {want!r} got {tok!r}")
        self.i += 1
        return tok

    def parse(self):
        node = self.or_()
        if self.peek() is not None:
            raise ValueError(f"unexpected {self.peek()!r}")
        return node

    def or_(self):
        node = self.and_()
        while self.peek() == "or":
            self.eat()
            node = ("or", node, self.and_())
        return node

    def and_(self):
        node = self.not_()
        while self.peek() == "and":
            self.eat()
            node = ("and", node, self.not_())
        return node

    def not_(self):
        if self.peek() == "not":
            self.eat()
            return ("not", self.not_())
        return self.atom()

    def atom(self):
        tok = self.eat()
        if tok == "(":
            node = self.or_()
            self.eat(")")
            return node
        if "." not in tok and tok in self.macros:  # macro reference
            return Parser(tokenize(self.macros[tok]), self.macros, self.lists).parse()
        op = self.eat()
        if op not in OPS:
            raise ValueError(f"unknown operator {op!r} after {tok!r}")
        if op == "in":
            self.eat("(")
            vals = []
            while self.peek() != ")":
                v = self.eat()
                if v == ",":
                    continue
                vals += self.lists[v] if v in self.lists else [_unq(v)]
            self.eat(")")
            return ("in", tok, vals)
        return ("cmp", tok, op, _unq(self.eat()))


def _unq(v: str) -> str:
    return v[1:-1] if len(v) >= 2 and v[0] in "\"'" and v[-1] == v[0] else v


def _norm(v):
    return str(v).lower() if isinstance(v, bool) else str(v)


def evaluate(node, ev: dict) -> bool:
    kind = node[0]
    if kind == "and":
        return evaluate(node[1], ev) and evaluate(node[2], ev)
    if kind == "or":
        return evaluate(node[1], ev) or evaluate(node[2], ev)
    if kind == "not":
        return not evaluate(node[1], ev)
    field = node[1]
    if field not in ev:
        return False
    val = _norm(ev[field])
    if kind == "in":
        return val in [str(x) for x in node[2]]
    op, want = node[2], node[3]
    if op == "=":
        return val == want
    if op == "!=":
        return val != want
    if op == "contains":
        return want in val
    if op == "icontains":
        return want.lower() in val.lower()
    if op == "startswith":
        return val.startswith(want)
    if op == "endswith":
        return val.endswith(want)
    try:
        a, b = float(val), float(want)
    except ValueError:
        return False
    return {"<": a < b, ">": a > b, "<=": a <= b, ">=": a >= b}[op]


@dataclass
class Rule:
    name: str
    desc: str
    priority: str
    output: str
    ast: tuple
    tags: list


def load(yaml_text: str) -> list[Rule]:
    items = yaml.safe_load(yaml_text)
    lists = {i["list"]: [str(x) for x in i["items"]] for i in items if "list" in i}
    macros = {i["macro"]: i["condition"] for i in items if "macro" in i}
    rules = []
    for i in items:
        if "rule" in i:
            ast = Parser(tokenize(i["condition"]), macros, lists).parse()
            rules.append(Rule(i["rule"], i.get("desc", ""), i.get("priority", "WARNING"), i.get("output", i["rule"]), ast, i.get("tags", [])))
    return rules


def render(out: str, ev: dict) -> str:
    return re.sub(r"%([\w.]+)", lambda m: str(ev.get(m.group(1), "<NA>")), out)


def run(rules: list[Rule], events: list[dict]) -> list[dict]:
    alerts = []
    for n, ev in enumerate(events, 1):
        for r in rules:
            if evaluate(r.ast, ev):
                alerts.append({"n": n, "rule": r.name, "priority": r.priority, "text": render(r.output, ev)})
    return alerts
