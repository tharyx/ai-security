"""A human-in-the-loop (HITL) approval gate inside a multi-agent workflow.

HITL  = a human must approve BEFORE the action runs (blocking). For high or
        irreversible consequences.
HOTL  = the action runs, a human watches and can veto/undo within a window
        (non-blocking). For medium risk with a reliable undo.
Low risk runs automatically, but is still logged.

Gate rules implemented:
  * risk comes from a fixed table (not from the model); unknown actions = high,
  * content-driven ("tainted") actions are raised one level,
  * an approval is bound to the exact action hash, expires, and is single-use,
  * the approver must not be the requesting user or the requesting agent,
  * irreversible actions need TWO distinct approvers,
  * a cap on pending cards per agent stops approval-fatigue flooding.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

RISK = {
    "read_doc": "low",
    "draft_email": "low",
    "send_email": "medium",
    "update_record": "medium",
    "transfer_funds": "high",
    "delete_data": "irreversible",
}
ORDER = ["low", "medium", "high", "irreversible"]
APPROVAL_TTL = 300
MAX_PENDING_PER_AGENT = 3


class GateError(Exception):
    pass


@dataclass
class World:
    sent: list[dict] = field(default_factory=list)
    records: dict[str, str] = field(default_factory=lambda: {"r1": "v0"})
    transfers: list[dict] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)

    def do(self, action: str, args: dict) -> dict | None:
        undo = None
        if action == "send_email":
            self.sent.append(args)
            undo = {"unsend": len(self.sent) - 1}
        elif action == "update_record":
            undo = {"restore": (args["id"], self.records.get(args["id"]))}
            self.records[args["id"]] = args["value"]
        elif action == "transfer_funds":
            self.transfers.append(args)
        elif action == "delete_data":
            self.deleted.append(args["what"])
        return undo

    def undo(self, undo: dict) -> None:
        if "unsend" in undo:
            self.sent[undo["unsend"]] = {"cancelled": True}
        if "restore" in undo:
            k, old = undo["restore"]
            self.records[k] = old


def action_hash(action: str, args: dict) -> str:
    return hashlib.sha256(json.dumps([action, args], sort_keys=True).encode()).hexdigest()


@dataclass
class Card:
    id: int
    action: str
    args: dict
    hash: str
    risk: str
    requester_user: str
    agent: str
    chain: list[str]
    created: float
    approvals: list[str] = field(default_factory=list)
    status: str = "pending"  # pending | executed | denied | expired | vetoed
    undo: dict | None = None


@dataclass
class Gate:
    world: World
    needed: dict = field(default_factory=lambda: {"high": 1, "irreversible": 2})
    cards: list[Card] = field(default_factory=list)
    audit: list[str] = field(default_factory=list)

    def effective_risk(self, action: str, tainted: bool) -> str:
        r = RISK.get(action, "high")
        if tainted and r != "irreversible":
            r = ORDER[min(ORDER.index(r) + 1, len(ORDER) - 1)]
        return r

    def submit(self, action: str, args: dict, *, user: str, agent: str, chain: list[str], now: float, tainted: bool = False) -> Card:
        risk = self.effective_risk(action, tainted)
        pending = [c for c in self.cards if c.agent == agent and c.status == "pending"]
        if risk in ("high", "irreversible") and len(pending) >= MAX_PENDING_PER_AGENT:
            raise GateError("too many pending approvals for this agent: possible flooding, rejected")
        card = Card(len(self.cards) + 1, action, dict(args), action_hash(action, args), risk, user, agent, list(chain), now)
        self.cards.append(card)
        if risk == "low":
            card.undo = self.world.do(action, args)
            card.status = "executed"
            self.audit.append(f"auto {action} by {agent}")
        elif risk == "medium":  # HOTL: run now, human may veto in a window
            card.undo = self.world.do(action, args)
            card.status = "executed"
            self.audit.append(f"hotl {action} by {agent} (veto window open)")
        else:  # HITL: blocked until approved
            self.audit.append(f"blocked {action} by {agent} awaiting approval")
        return card

    def approve(self, card_id: int, approver: str, seen_hash: str, now: float) -> Card:
        card = self.cards[card_id - 1]
        if card.status != "pending":
            raise GateError(f"card is {card.status}: approval is single-use")
        if now - card.created > APPROVAL_TTL:
            card.status = "expired"
            raise GateError("approval window expired")
        if action_hash(card.action, card.args) != seen_hash or card.hash != seen_hash:
            raise GateError("what you approved is not what would run (hash mismatch)")
        if approver in (card.requester_user, card.agent) or approver in card.chain:
            raise GateError("approver must be independent of the requester and the agents")
        if approver in card.approvals:
            raise GateError("same approver cannot approve twice")
        card.approvals.append(approver)
        if len(card.approvals) >= self.needed[card.risk]:
            card.undo = self.world.do(card.action, card.args)
            card.status = "executed"
            self.audit.append(f"executed {card.action} approved by {card.approvals}")
        return card

    def deny(self, card_id: int, approver: str) -> None:
        self.cards[card_id - 1].status = "denied"
        self.audit.append(f"denied by {approver}")

    def veto(self, card_id: int, human: str) -> None:
        """HOTL: a human undoes a medium-risk action that already ran."""
        card = self.cards[card_id - 1]
        if card.risk != "medium" or card.status != "executed" or not card.undo:
            raise GateError("nothing to veto")
        self.world.undo(card.undo)
        card.status = "vetoed"
        self.audit.append(f"veto by {human}")


class Workflow:
    """planner -> executor. The executor can only act through the gate."""

    def __init__(self, gate: Gate, user: str) -> None:
        self.gate, self.user = gate, user

    def run(self, steps: list[tuple[str, dict]], now: float, tainted: bool = False) -> list[Card]:
        return [
            self.gate.submit(a, args, user=self.user, agent="executor", chain=["planner", "executor"], now=now, tainted=tainted)
            for a, args in steps
        ]
