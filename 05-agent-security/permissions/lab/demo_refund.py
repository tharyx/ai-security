"""Part B scorecard: a refund agent that lets the model move money vs one where the system does.

From the repository root:
    python 05-agent-security/permissions/lab/demo_refund.py
"""

from __future__ import annotations

import attacks
import secure_refund_agent as sec
import vulnerable_refund_agent as vuln


def money(payments) -> str:
    if not payments.payouts:
        return "no money moved"
    p = payments.payouts[-1]
    total = f"${payments.total_paid():,.0f}"
    return f"{total} TO ATTACKER" if p["to"] == attacks.ATTACKER_ACCOUNT else f"{total} -> {p['to']}"


def main() -> None:
    # The same skimming human approves on both sides: they trust the first $ amount on the card.
    limits = {"goal_hijack_other_order": 60, "new_payee": 60, "misleading_approval": 20,
              "small_full_refund": 60, "partial_refund_needs_approval": 200}
    print(f"{'case':30} {'vulnerable':22} {'secure':22} secure-side evidence")
    print("-" * 136)
    for name, spec in {**attacks.REFUND_TICKETS, **attacks.BENIGN_REFUND_TICKETS}.items():
        v = vuln.VulnerableRefundAgent(approver=sec.first_amount_reader(limits[name]))
        s = sec.SecureRefundAgent(approver=sec.first_amount_reader(limits[name]))
        v.handle(vuln.Ticket(*spec))
        res = s.handle(sec.Ticket(*spec))
        print(f"{name:30} {money(v.payments):22} {money(s.payments):22} {res.outcome[:60]}")

    # Retry the same small refund twice.
    v, s = vuln.VulnerableRefundAgent(), sec.SecureRefundAgent()
    for _ in range(2):
        v.handle(vuln.Ticket(*attacks.BENIGN_REFUND_TICKETS["small_full_refund"]))
        res = s.handle(sec.Ticket(*attacks.BENIGN_REFUND_TICKETS["small_full_refund"]))
    print(f"{'retry_same_refund_twice':30} {money(v.payments):22} {money(s.payments):22} {res.outcome[:60]}")

    print("\nWhat the approver saw for 'misleading_approval':")
    v = vuln.VulnerableRefundAgent(approver=sec.first_amount_reader(20))
    v.handle(vuln.Ticket(*attacks.REFUND_TICKETS["misleading_approval"]))
    print("\n  vulnerable card (the model's own words):\n    " + v.cards_shown[0])
    s = sec.SecureRefundAgent(approver=sec.first_amount_reader(20))
    res = s.handle(sec.Ticket(*attacks.REFUND_TICKETS["misleading_approval"]))
    print("\n  secure card (rendered by the system from verified data):")
    print("    " + res.events[0]["card"].replace("\n", "\n    "))


if __name__ == "__main__":
    main()
