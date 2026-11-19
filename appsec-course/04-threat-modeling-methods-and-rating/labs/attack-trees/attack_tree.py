"""Attack tree evaluator (Schneier-style AND/OR trees) with cost, probability and controls.

* LEAF: one attacker step with an estimated cost (attacker effort, any unit) and a
  probability of success. ``mitigated_by`` lists controls that block the step.
* OR:  the attacker needs ANY child. Cost = cheapest child. P = 1 - prod(1 - p_child)
  (assumes independent children: a simplification, say so in reviews).
* AND: the attacker needs ALL children. Cost = sum. P = product.

Analysis: cheapest attack, all minimal attack scenarios (cut sets), scenarios within an
attacker budget, and which single control raises the attacker's cheapest cost the most.
Standard library only.
"""
from __future__ import annotations

import itertools
import json
import math
from dataclasses import dataclass, field
from pathlib import Path

INF = math.inf


@dataclass
class Node:
    id: str
    label: str
    kind: str = "LEAF"
    cost: float = 0
    prob: float = 0.0
    children: list["Node"] = field(default_factory=list)
    mitigated_by: list[str] = field(default_factory=list)


def from_dict(d: dict) -> Node:
    kids = [from_dict(c) for c in d.get("children", [])]
    return Node(d["id"], d["label"], d.get("kind", "LEAF"), d.get("cost", 0), d.get("prob", 0.0),
                kids, d.get("mitigated_by", []))


def load(path: str | Path) -> Node:
    return from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def walk(node: Node):
    yield node
    for c in node.children:
        yield from walk(c)


def validate(root: Node) -> list[str]:
    errs, seen = [], set()
    for n in walk(root):
        if n.id in seen:
            errs.append(f"{n.id}: DUPLICATE_ID")
        seen.add(n.id)
        if n.kind not in ("LEAF", "AND", "OR"):
            errs.append(f"{n.id}: BAD_KIND")
        if n.kind == "LEAF" and n.children:
            errs.append(f"{n.id}: LEAF_WITH_CHILDREN")
        if n.kind in ("AND", "OR") and len(n.children) < 2:
            errs.append(f"{n.id}: GATE_NEEDS_TWO_CHILDREN")
        if n.kind == "LEAF" and not (0.0 <= n.prob <= 1.0):
            errs.append(f"{n.id}: PROB_OUT_OF_RANGE")
    return errs


def evaluate(node: Node, controls=frozenset()) -> tuple[float, float]:
    """Return (cheapest cost, probability of success) for this subtree."""
    if node.kind == "LEAF":
        if set(node.mitigated_by) & set(controls):
            return INF, 0.0
        return node.cost, node.prob
    results = [evaluate(c, controls) for c in node.children]
    if node.kind == "OR":
        return min(r[0] for r in results), 1 - math.prod(1 - r[1] for r in results)
    return sum(r[0] for r in results), math.prod(r[1] for r in results)


def cheapest_path(node: Node, controls=frozenset()) -> list[str]:
    """Leaf labels of the cheapest attack. Empty if every route is blocked."""
    if evaluate(node, controls)[0] == INF:
        return []
    if node.kind == "LEAF":
        return [node.label]
    if node.kind == "OR":
        best = min(node.children, key=lambda c: evaluate(c, controls)[0])
        return cheapest_path(best, controls)
    return [step for c in node.children for step in cheapest_path(c, controls)]


def scenarios(node: Node) -> list[frozenset]:
    """Minimal attack scenarios: sets of leaf ids that together reach the goal."""
    if node.kind == "LEAF":
        return [frozenset([node.id])]
    child_sets = [scenarios(c) for c in node.children]
    if node.kind == "OR":
        return [s for group in child_sets for s in group]
    return [frozenset().union(*combo) for combo in itertools.product(*child_sets)]


def within_budget(root: Node, budget: float, controls=frozenset()) -> list[tuple[float, list[str]]]:
    leaves = {n.id: n for n in walk(root) if n.kind == "LEAF"}
    out = []
    for sc in scenarios(root):
        if any(set(leaves[i].mitigated_by) & set(controls) for i in sc):
            continue
        cost = sum(leaves[i].cost for i in sc)
        if cost <= budget:
            out.append((cost, sorted(leaves[i].label for i in sc)))
    return sorted(out)


def best_single_control(root: Node, candidates: list[str]) -> tuple[str, float]:
    """The control that raises the attacker's cheapest cost the most (ties: lower probability)."""
    scored = []
    for c in candidates:
        cost, prob = evaluate(root, {c})
        scored.append((-cost, prob, c))
    scored.sort()
    neg_cost, _, name = scored[0]
    return name, -neg_cost


def render(node: Node, controls=frozenset(), depth: int = 0) -> str:
    cost, prob = evaluate(node, controls)
    cost_s = "blocked" if cost == INF else f"cost {cost:g}"
    line = f"{'  ' * depth}[{node.kind}] {node.label} ({cost_s}, p={prob:.2f})"
    return "\n".join([line] + [render(c, controls, depth + 1) for c in node.children])
