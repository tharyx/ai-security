"""Diagrams as code, UML as code and attack trees as code, in pure Python.

* PlantUML text for UML sequence, class and use/misuse case diagrams (render with PlantUML, optional)
* a small PlantUML linter so a broken diagram fails CI instead of failing silently
* attack trees written in an indented text DSL, evaluated (cheapest path, probability)
  and rendered as Mermaid or Graphviz DOT
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field


def _alias(name: str) -> str:
    return re.sub(r"\W", "_", name)


# ------------------------------------------------------------------ UML as code
def sequence_diagram(title: str, participants: list[tuple[str, str]], messages: list[tuple[str, str, str]]) -> str:
    """participants: (kind, name) with kind in actor/participant/database; messages: (from, to, text)."""
    out = ["@startuml", f"title {title}"]
    out += [f'{kind} "{name}" as {_alias(name)}' for kind, name in participants]
    for a, b, text in messages:
        arrow = "-->" if text.startswith("return") else "->"
        out.append(f"{_alias(a)} {arrow} {_alias(b)}: {text}")
    out.append("@enduml")
    return "\n".join(out)


def class_diagram(classes: dict[str, list[str]], relations: list[tuple[str, str, str]]) -> str:
    """classes: name -> ['- field: type', '+ method()']; relations: (a, arrow, b) e.g. ('Order', '-->', 'Customer')."""
    out = ["@startuml"]
    for name, members in classes.items():
        out.append(f"class {name} {{")
        out += [f"  {m}" for m in members]
        out.append("}")
    out += [f"{a} {arrow} {b}" for a, arrow, b in relations]
    out.append("@enduml")
    return "\n".join(out)


def misuse_case_diagram(actors: list[str], attackers: list[str], use_cases: list[str],
                        misuse_cases: list[tuple[str, str]], links: list[tuple[str, str]]) -> str:
    """Use cases plus misuse (abuse) cases. misuse_cases: (name, threatens use case).

    Misuse cases are drawn in a dark style; '<<threatens>>' and '<<mitigates>>' edges follow
    Sindre and Opdahl's misuse case notation (PlantUML has no built-in misuse case shape).
    """
    out = ["@startuml", "left to right direction", "skinparam usecase {", "  BackgroundColor<<misuse>> Black",
           "  FontColor<<misuse>> White", "}"]
    out += [f'actor "{a}" as {_alias(a)}' for a in actors]
    out += [f'actor "{a}" as {_alias(a)} #black' for a in attackers]
    out += [f'usecase "{u}" as {_alias(u)}' for u in use_cases]
    out += [f'usecase "{m}" as {_alias(m)} <<misuse>>' for m, _ in misuse_cases]
    for a, b in links:
        out.append(f"{_alias(a)} --> {_alias(b)}")
    for m, target in misuse_cases:
        out.append(f"{_alias(m)} ..> {_alias(target)} : <<threatens>>")
    out.append("@enduml")
    return "\n".join(out)


DECL = re.compile(r'^(actor|participant|database|entity|usecase|class)\s+(?:"[^"]+"\s+as\s+)?(\w+)')
ARROW = re.compile(r"^(\w+)\s+[-.]+>{1,2}\s+(\w+)")


def lint_plantuml(text: str) -> list[str]:
    """Return problems: missing start/end, undeclared participants, duplicate aliases."""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    problems = []
    if not lines or lines[0] != "@startuml":
        problems.append("first line must be @startuml")
    if not lines or lines[-1] != "@enduml":
        problems.append("last line must be @enduml")
    declared: list[str] = []
    for ln in lines:
        m = DECL.match(ln)
        if m:
            if m.group(2) in declared:
                problems.append(f"duplicate alias: {m.group(2)}")
            declared.append(m.group(2))
    for ln in lines:
        m = ARROW.match(ln)
        if m:
            for name in m.groups():
                if name not in declared:
                    problems.append(f"undeclared participant: {name}")
    return problems


# ------------------------------------------------------------------ attack trees as code
@dataclass
class Node:
    label: str
    gate: str = "LEAF"  # OR, AND, LEAF
    cost: float = 0.0
    p: float = 0.0
    id: str = ""
    children: list["Node"] = field(default_factory=list)
    blocked: bool = False


LINE = re.compile(r"^(?P<indent> *)(?P<gate>OR|AND|LEAF):\s*(?P<label>[^\[]+?)\s*(?:\[(?P<attrs>[^\]]*)\])?\s*$")


def parse_tree(text: str) -> Node:
    """Indented DSL: two spaces per level. `LEAF: label [id=L1, cost=200, p=0.3]`."""
    root, stack = None, []  # stack of (indent, node)
    for n, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        m = LINE.match(raw)
        if not m:
            raise ValueError(f"line {n}: cannot parse {raw.strip()!r}")
        attrs = dict(kv.split("=", 1) for kv in (m["attrs"] or "").replace(" ", "").split(",") if kv)
        node = Node(m["label"], m["gate"], float(attrs.get("cost", 0)), float(attrs.get("p", 0)), attrs.get("id", ""))
        if node.gate == "LEAF" and not node.id:
            raise ValueError(f"line {n}: leaf needs an id")
        indent = len(m["indent"])
        while stack and stack[-1][0] >= indent:
            stack.pop()
        if stack:
            if stack[-1][1].gate == "LEAF":
                raise ValueError(f"line {n}: a LEAF cannot have children")
            stack[-1][1].children.append(node)
        elif root is None:
            root = node
        else:
            raise ValueError(f"line {n}: second root node")
        stack.append((indent, node))
    if root is None:
        raise ValueError("empty tree")
    return root


def leaves(node: Node) -> list[Node]:
    return [node] if node.gate == "LEAF" else [x for c in node.children for x in leaves(c)]


def cheapest(node: Node) -> tuple[float, list[str]]:
    """Cheapest attack: OR = min over children, AND = sum of children. Blocked leaf = infinite cost."""
    if node.gate == "LEAF":
        return (math.inf, []) if node.blocked else (node.cost, [node.id])
    results = [cheapest(c) for c in node.children]
    if node.gate == "OR":
        return min(results, key=lambda r: r[0])
    total = sum(r[0] for r in results)
    return (total, [i for r in results for i in r[1]]) if total != math.inf else (math.inf, [])


def probability(node: Node) -> float:
    """Success probability with independent leaves: OR = 1 - prod(1 - p), AND = prod(p)."""
    if node.gate == "LEAF":
        return 0.0 if node.blocked else node.p
    ps = [probability(c) for c in node.children]
    if node.gate == "AND":
        return math.prod(ps)
    return 1 - math.prod(1 - p for p in ps)


def mitigate(root: Node, blocked_ids: set[str]) -> Node:
    """Mark leaves as blocked (a control makes this step infeasible). Unknown ids are an error."""
    known = {leaf.id for leaf in leaves(root)}
    unknown = blocked_ids - known
    if unknown:
        raise KeyError(f"unknown leaf ids: {sorted(unknown)}")
    for leaf in leaves(root):
        leaf.blocked = leaf.id in blocked_ids
    return root


def to_mermaid(root: Node) -> str:
    out = ["graph TD"]
    counter = [0]

    def walk(n: Node) -> str:
        counter[0] += 1
        nid = n.id or f"N{counter[0]}"
        text = n.label + (f"<br/>cost {n.cost:g}, p {n.p:g}" if n.gate == "LEAF" else f"<br/>{n.gate}")
        out.append(f'  {nid}["{text}"]' if n.gate != "AND" else f'  {nid}{{"{text}"}}')
        if n.blocked:
            out.append(f"  class {nid} blocked")
        for c in n.children:
            out.append(f"  {nid} --> {walk(c)}")
        return nid

    walk(root)
    out.append("  classDef blocked fill:#dcfce7,stroke:#16a34a,stroke-dasharray: 4")
    return "\n".join(out)


def to_dot(root: Node) -> str:
    out = ["digraph attack_tree {", "  node [fontname=Arial];"]
    counter = [0]

    def walk(n: Node) -> str:
        counter[0] += 1
        nid = n.id or f"N{counter[0]}"
        shape = {"AND": "box", "OR": "ellipse"}.get(n.gate, "note")
        style = ', style=dashed' if n.blocked else ""
        out.append(f'  {nid} [label="{n.label}\\n{n.gate}", shape={shape}{style}];')
        for c in n.children:
            out.append(f"  {nid} -> {walk(c)};")
        return nid

    walk(root)
    out.append("}")
    return "\n".join(out)
