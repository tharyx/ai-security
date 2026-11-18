"""Attack trees as code (lesson 03, threat-modeling methods).

An attack tree puts the attacker's goal at the root and breaks it into ways to reach it.
    OR node  - any child is enough      P = 1 - product(1 - P(child))   cost = min(child)
    AND node - every child is needed    P = product(P(child))           cost = sum(child)
    leaf     - one attacker step, with an estimated success probability and cost

Mark a leaf as *mitigated* and it becomes impossible (P = 0, cost = infinity). Only HARD
controls can do that. A SOFT control (a classifier, a prompt rule) only lowers a leaf's
probability, so we model it as a new, lower probability instead.

The tree below is HelpDesk Copilot v0 from the lesson-02 to lesson-04 lab, with
made-up, explainable numbers. The point is not the numbers; it is to see
    1. which single hard control lowers the root probability the most, and
    2. why a soft control on "the model follows the injection" barely moves the root.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Literal


@dataclass
class Node:
    id: str
    label: str
    kind: Literal["AND", "OR", "LEAF"] = "LEAF"
    p: float = 0.0              # leaf: probability the step succeeds (0..1)
    cost: float = 0.0           # leaf: attacker effort, in made-up "days"
    control: str = ""           # leaf: the HARD control that would make the step impossible
    children: list[Node] = field(default_factory=list)

    def leaves(self) -> list[Node]:
        if self.kind == "LEAF":
            return [self]
        return [leaf for c in self.children for leaf in c.leaves()]


def probability(node: Node, mitigated: frozenset[str] = frozenset(),
                overrides: dict[str, float] | None = None) -> float:
    """Success probability of the node, with some leaves mitigated (hard) or re-estimated (soft)."""
    overrides = overrides or {}
    if node.kind == "LEAF":
        if node.id in mitigated:
            return 0.0
        return overrides.get(node.id, node.p)
    ps = [probability(c, mitigated, overrides) for c in node.children]
    if node.kind == "AND":
        return math.prod(ps)
    return 1 - math.prod(1 - p for p in ps)


def cheapest_cost(node: Node, mitigated: frozenset[str] = frozenset()) -> float:
    """Cheapest total attacker effort to reach this node (inf if impossible)."""
    if node.kind == "LEAF":
        return math.inf if node.id in mitigated else node.cost
    costs = [cheapest_cost(c, mitigated) for c in node.children]
    return sum(costs) if node.kind == "AND" else min(costs)


def cheapest_path(node: Node, mitigated: frozenset[str] = frozenset()) -> list[str]:
    """Leaf ids on the cheapest attack (empty if the node cannot be reached)."""
    if cheapest_cost(node, mitigated) == math.inf:
        return []
    if node.kind == "LEAF":
        return [node.id]
    if node.kind == "AND":
        return [leaf for c in node.children for leaf in cheapest_path(c, mitigated)]
    best = min(node.children, key=lambda c: cheapest_cost(c, mitigated))
    return cheapest_path(best, mitigated)


def rank_controls(root: Node) -> list[tuple[str, str, float]]:
    """For each leaf with a hard control: (leaf id, control, root probability if applied).

    Sorted best first. This answers "which single control buys the most?".
    """
    rows = [(leaf.id, leaf.control, probability(root, frozenset({leaf.id})))
            for leaf in root.leaves() if leaf.control]
    return sorted(rows, key=lambda r: (r[2], r[0]))


def helpdesk_tree() -> Node:
    """Root goal: steal customer data through HelpDesk Copilot v0."""
    leaf = Node
    injection = Node("inject", "Indirect prompt injection via inbound email", "AND", children=[
        leaf("send_mail", "Send an email with hidden instructions", p=0.95, cost=0.1,
             control="quarantine: the model with tools never reads raw email"),
        leaf("model_follows", "The model follows the injected text", p=0.5, cost=1,
             control=""),  # no hard control exists for this step: it is model behaviour
        Node("channel", "Get the data out", "OR", children=[
            leaf("send_tool", "Model calls send_email to an outside address", p=0.9, cost=0.5,
                 control="tool broker: fixed recipients + human approval"),
            leaf("md_image", "Model writes a markdown image URL with the data", p=0.8, cost=0.5,
                 control="output: image and link allowlist"),
            leaf("fetch_tool", "Model calls http_fetch with the data in the URL", p=0.8, cost=0.5,
                 control="egress proxy: allowlisted domains only"),
        ]),
    ])
    logs = Node("logs", "Read secrets and PII from shared logs", "AND", children=[
        leaf("log_access", "Get access to the shared log platform", p=0.2, cost=10,
             control="restrict log access to the security team"),
        leaf("data_in_logs", "Prompts with PII and the API key are logged", p=0.9, cost=0,
             control="redaction before logging; no secrets in prompts"),
    ])
    rag = leaf("rag_no_acl", "Ask the bot; retrieval returns another tenant's chunks", p=0.6,
               cost=0.5, control="retriever: tenant and ACL filter before ranking")
    return Node("root", "Steal customer data through HelpDesk Copilot", "OR",
                children=[injection, logs, rag])
