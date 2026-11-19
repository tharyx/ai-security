"""Run: .venv/Scripts/python caisp-course/ch7-emerging-threats-governance-compliance/labs/ai-worm-simulation/demo.py"""
from worm_sim import START, Defenses, simulate


def human(msg):  # a careful human spots the odd note
    return START not in msg.body


cases = [
    ("no defenses", Defenses(), None),
    ("rate limit (1 msg/agent)", Defenses(max_messages=1), None),
    ("taint (no fan-out)", Defenses(taint=True), None),
    ("replication block", Defenses(replication_block=True), None),
    ("approval, nobody approves", Defenses(approval=True), None),
    ("approval, careful human", Defenses(approval=True), human),
    ("all hard layers", Defenses(taint=True, replication_block=True, approval=True), human),
]
print(f"{'case':28} {'infected agents, rounds 1-6':30} msgs held benign")
for label, d, ap in cases:
    r = simulate(defenses=d, approver=ap)
    print(f"{label:28} {str(r.infected_per_round):30} {r.messages:4} {r.held:4} {r.benign_replies:4}")
