"""A tiny policy decision point (PDP) with Rego-like rules stored as JSON.

The API code (the policy enforcement point, PEP) only asks:
    decide(subject, action, resource, env) -> Decision
and never contains `if user.role == ...` logic itself. Changing who may do what
means editing and testing the policy file, not the service code.

Rule shape (see fixtures/policy.json):
    {"id": "...", "effect": "allow" | "deny", "actions": ["trip:read", "*"],
     "when": [["resource.owner_id", "==", "subject.id"], ...]}   # all must hold
Operands that start with subject./resource./env./action are references;
anything else is a literal. Deny overrides allow; default is deny.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

OPS = {
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
    "in": lambda a, b: b is not None and a in b,
    "not_in": lambda a, b: b is None or a not in b,
    ">=": lambda a, b: a is not None and b is not None and a >= b,
    "<=": lambda a, b: a is not None and b is not None and a <= b,
}
REF_ROOTS = ("subject.", "resource.", "env.")


class PolicyError(ValueError):
    pass


@dataclass
class Decision:
    allow: bool
    matched: list[str] = field(default_factory=list)
    reason: str = ""


def _resolve(operand, ctx: dict):
    if isinstance(operand, str):
        if operand == "action":
            return ctx["action"]
        if operand.startswith(REF_ROOTS):
            root, _, path = operand.partition(".")
            cur = ctx[root]
            for part in path.split("."):
                cur = cur.get(part) if isinstance(cur, dict) else None
            return cur
    return operand


def load_policy(path) -> dict:
    policy = json.loads(Path(path).read_text(encoding="utf-8"))
    lint(policy)
    return policy


def lint(policy: dict) -> None:
    """Fail fast on typos: an unknown operator would otherwise silently never match."""
    if policy.get("default") not in ("deny", "allow"):
        raise PolicyError("default must be 'deny' or 'allow'")
    ids = set()
    for rule in policy["rules"]:
        if rule["id"] in ids:
            raise PolicyError(f"duplicate rule id {rule['id']}")
        ids.add(rule["id"])
        if rule["effect"] not in ("allow", "deny"):
            raise PolicyError(f"{rule['id']}: bad effect")
        for cond in rule.get("when", []):
            if len(cond) != 3 or cond[1] not in OPS:
                raise PolicyError(f"{rule['id']}: bad condition {cond}")


def decide(policy: dict, subject: dict, action: str, resource: dict, env: dict | None = None) -> Decision:
    ctx = {"subject": subject, "resource": resource, "env": env or {}, "action": action}
    allows, denies = [], []
    for rule in policy["rules"]:
        if action not in rule["actions"] and "*" not in rule["actions"]:
            continue
        if all(OPS[op](_resolve(left, ctx), _resolve(right, ctx)) for left, op, right in rule.get("when", [])):
            (denies if rule["effect"] == "deny" else allows).append(rule["id"])
    if denies:
        return Decision(False, denies, "explicit deny overrides allow")
    if allows:
        return Decision(True, allows, "allowed by rule")
    return Decision(policy["default"] == "allow", [], f"no rule matched; default {policy['default']}")


def run_policy_tests(policy: dict, cases: list[dict]) -> list[str]:
    """Like `opa test`: every case states the expected decision. Returns failures."""
    failures = []
    for c in cases:
        d = decide(policy, c["subject"], c["action"], c["resource"], c.get("env"))
        if d.allow != c["expect"]:
            failures.append(f"{c['name']}: expected {c['expect']} got {d.allow} ({d.reason})")
    return failures


# ------------------------------------------------------------ the API (PEP)

TRIPS = {
    "t-1": {"id": "t-1", "owner_id": "u-alice", "region": "south", "pickup": "12.97,77.59"},
    "t-2": {"id": "t-2", "owner_id": "u-bob", "region": "north", "pickup": "28.61,77.20"},
}


def hardcoded_get_trip(subject: dict, trip_id: str):
    """Anti-pattern: authorization mixed into the handler, easy to forget in the next handler."""
    trip = TRIPS.get(trip_id)
    if trip is None:
        return 404, None
    if "admin" in subject["roles"] or trip["owner_id"] == subject["id"]:
        return 200, trip
    return 403, None


def pep_get_trip(policy: dict, subject: dict, trip_id: str, env: dict | None = None):
    """Decoupled: the handler asks the PDP and enforces the answer."""
    trip = TRIPS.get(trip_id)
    if trip is None:
        return 404, None, None
    d = decide(policy, subject, "trip:read", trip, env)
    return (200 if d.allow else 403), (trip if d.allow else None), d
