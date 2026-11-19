"""Human-approval checkpoints for destructive or irreversible agent actions.

Properties implemented (and tested):
  * classify: shell, git, payment, email, delete actions; unknown types FAIL CLOSED
  * the approval screen shows the EXACT action (canonical text, nothing summarised away)
  * the approval is BOUND to the sha256 of the canonical action: change one byte, it no longer applies
  * TIMEOUT MEANS DENY: no decision in time = denied; an approval also expires
  * an approval is SINGLE USE
Nothing here runs a command; the executor is a callback that records the call.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Callable

SHELL_DESTRUCTIVE = [
    (r"\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+", "recursive or forced delete"),
    (r"\bdel\s+/[sqf]", "windows recursive delete"),
    (r"\bmkfs\b|\bformat\s+[a-z]:", "format a disk"),
    (r"\bdd\s+.*\bof=", "raw disk write"),
    (r"\bchmod\s+-R\s+777", "world-writable recursive chmod"),
    (r"\bdrop\s+(table|database)\b|\btruncate\s+table\b", "database destruction"),
    (r"\|\s*(sh|bash|zsh)\b", "pipe into a shell"),
    (r">\s*/dev/(sd|nvme)", "write to a block device"),
]
GIT_DESTRUCTIVE = [
    (lambda a: "push" in a and any(x in a for x in ("--force", "-f", "--force-with-lease")), "force push rewrites remote history"),
    (lambda a: "reset" in a and "--hard" in a, "hard reset discards work"),
    (lambda a: "clean" in a and any(x.startswith("-") and "f" in x for x in a), "git clean deletes untracked files"),
    (lambda a: "branch" in a and "-D" in a, "force delete branch"),
]


def classify(action: dict) -> dict:
    kind = action.get("type")
    reasons: list[str] = []
    if kind == "shell":
        cmd = action.get("command", "")
        reasons = [why for rx, why in SHELL_DESTRUCTIVE if re.search(rx, cmd, re.IGNORECASE)]
    elif kind == "git":
        args = action.get("args", [])
        reasons = [why for fn, why in GIT_DESTRUCTIVE if fn(args)]
    elif kind == "payment":
        reasons = ["moves money (irreversible)"]
    elif kind == "email":
        reasons = ["sends a message to a third party (irreversible)"]
    elif kind == "delete":
        reasons = ["deletes data"]
    elif kind in ("read_file", "list_dir", "run_tests"):
        return {"risk": "safe", "reasons": []}
    else:
        return {"risk": "unknown", "reasons": [f"unknown action type {kind!r}: fail closed"]}
    return {"risk": "needs_approval" if reasons else "safe", "reasons": reasons}


def canonical(action: dict) -> str:
    return json.dumps(action, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def action_hash(action: dict) -> str:
    return hashlib.sha256(canonical(action).encode()).hexdigest()


def render(action: dict) -> str:
    """What the human sees: the exact action, plus warnings about hidden characters."""
    text = canonical(action)
    warnings = []
    raw = json.dumps(action, ensure_ascii=False)
    if any(ord(c) > 126 or ord(c) < 32 for c in raw):
        warnings.append("WARNING: contains non-ASCII or control characters (shown escaped above)")
    return f"ACTION  : {text}\nHASH    : {action_hash(action)[:16]}...\n" + "\n".join(warnings)


@dataclass
class Request:
    id: int
    action_hash: str
    rendered: str
    created: float
    decision: str | None = None        # "approved" | "denied"
    decided_at: float | None = None
    used: bool = False


class ApprovalGate:
    def __init__(self, clock: Callable[[], float] = time.monotonic, decision_timeout: float = 60.0, approval_ttl: float = 120.0):
        self.clock, self.decision_timeout, self.approval_ttl = clock, decision_timeout, approval_ttl
        self.requests: dict[int, Request] = {}
        self.audit: list[str] = []
        self._next = 1

    def request(self, action: dict) -> Request:
        r = Request(self._next, action_hash(action), render(action), self.clock())
        self.requests[r.id] = r
        self._next += 1
        self.audit.append(f"request {r.id} {r.action_hash[:12]}")
        return r

    def decide(self, request_id: int, approve: bool, approver: str) -> None:
        r = self.requests[request_id]
        if r.decision is None and self.clock() - r.created <= self.decision_timeout:
            r.decision, r.decided_at = ("approved" if approve else "denied"), self.clock()
            self.audit.append(f"{r.decision} {r.id} by {approver}")

    def check(self, action: dict, request_id: int) -> tuple[bool, str]:
        r = self.requests.get(request_id)
        if r is None:
            return False, "no such approval"
        if r.used:
            return False, "approval already used"
        if r.decision is None:
            if self.clock() - r.created > self.decision_timeout:
                return False, "timed out: no decision (timeout means deny)"
            return False, "pending"
        if r.decision != "approved":
            return False, "denied by human"
        if self.clock() - (r.decided_at or 0) > self.approval_ttl:
            return False, "approval expired"
        if action_hash(action) != r.action_hash:
            self.audit.append(f"MISMATCH {r.id}")
            return False, "action differs from what was approved"
        r.used = True
        return True, "ok"


def execute(action: dict, gate: ApprovalGate, runner: Callable[[dict], None], request_id: int | None = None) -> tuple[bool, str]:
    """Run `action` only if it is safe, or a valid approval for exactly this action exists."""
    risk = classify(action)["risk"]
    if risk == "safe":
        runner(action)
        return True, "safe"
    if request_id is None:
        return False, "approval required"
    ok, why = gate.check(action, request_id)
    if ok:
        runner(action)
    return ok, why
