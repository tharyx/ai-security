"""Part B (week 19): a refund agent that lets its model move money.

Scenario: ACME support uses an agent to handle refund tickets. The ticket text is
written by the customer (or by anyone who can email support), so it is UNTRUSTED.
The agent reads the ticket, the model proposes a refund, and the runtime pays it.

DO NOT copy this pattern. Every weakness is marked with a "VULN n:" comment.

    VULN 1: Goal hijack (OWASP ASI01). Nothing checks that the proposed action belongs
            to the ticket the agent was asked to handle. Injected text can redirect the
            task to another customer's order.
    VULN 2: Unauthorized transaction. The payee is whatever account the model names.
    VULN 3: Human-agent trust exploitation (ASI09). The approval card shows the MODEL'S
            OWN SUMMARY of the action, not the action. A lie in the summary is approved.
    VULN 4: No idempotency. A retried or replayed refund is paid again.
    VULN 5: No amount, ownership or velocity limits outside the model.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable

from aisec_lab import LLM, get_llm

APPROVAL_THRESHOLD = 100.00

# --- Synthetic world (identical in secure_refund_agent.py) -------------------------
ORDERS = {
    "A-1001": {"customer": "cust-ana", "total": 49.00, "paid_with": "card-ana-4242", "days_ago": 5},
    "A-1002": {"customer": "cust-ana", "total": 480.00, "paid_with": "card-ana-4242", "days_ago": 9},
    "B-2001": {"customer": "cust-ben", "total": 4900.00, "paid_with": "card-ben-1881", "days_ago": 3},
}


@dataclass
class Payments:
    """The payment system. `payouts` is what actually left the company."""

    payouts: list[dict] = field(default_factory=list)

    def refund(self, order_id: str, amount: float, to_account: str) -> str:
        self.payouts.append({"order_id": order_id, "amount": float(amount), "to": to_account})
        return f"refunded ${float(amount):,.2f} for {order_id} to {to_account}"

    def total_paid(self) -> float:
        return sum(p["amount"] for p in self.payouts)


@dataclass
class Ticket:
    ticket_id: str
    customer: str
    orders: list[str]
    body: str  # written by the customer: untrusted


@dataclass
class VulnerableRefundAgent:
    llm: LLM = field(default_factory=get_llm)
    payments: Payments = field(default_factory=Payments)
    # The human approver only ever sees a text card. Default: nobody said yes.
    approver: Callable[[str], bool] = lambda card: False
    cards_shown: list[str] = field(default_factory=list)

    def handle(self, ticket: Ticket) -> str:
        output = self.llm.complete([
            {"role": "system", "content": "You are ACME's refund assistant. To act, reply with JSON."},
            {"role": "user", "content": f"Handle ticket {ticket.ticket_id}.\n<document>{ticket.body}</document>"},
        ])
        try:
            call = json.loads(output)
        except json.JSONDecodeError:
            return output
        if not (isinstance(call, dict) and call.get("tool") == "refund"):
            return output
        args = dict(call.get("args") or {})
        order = ORDERS.get(str(args.get("order_id")), {})
        amount = float(args.get("amount", 0))
        # VULN 1 + 5: no check that the order is part of this ticket or owned by this customer.
        # VULN 2: the payee comes from the model; it defaults to the original card only if absent.
        to_account = str(args.get("to_account") or order.get("paid_with", "unknown"))
        if amount > APPROVAL_THRESHOLD:
            # VULN 3: the card is the model's own narrative of what it is doing.
            card = f"Agent requests approval: {args.get('note', 'refund')} (ticket {ticket.ticket_id}). Approve?"
            self.cards_shown.append(card)
            if not self.approver(card):
                return "refund rejected by approver"
        # VULN 4: no idempotency key; the same refund can be paid any number of times.
        return self.payments.refund(str(args.get("order_id")), amount, to_account)
