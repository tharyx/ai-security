"""From repo root:
    .venv/Scripts/python devsecops-course/08-iac-configuration-and-compliance-as-code/labs/ansible-golden-image-hardening/demo.py
"""
from pathlib import Path

import applier as ap

HERE = Path(__file__).parent
state = ap.load_state(HERE / "fixtures" / "host_weak.json")
role = HERE / "fixtures" / "role"

before = ap.run_checks(state)
print(f"BEFORE: score {ap.score(before)}%  failed: {[r['id'] for r in before if r['status'] == 'fail']}")

first = ap.apply_role(state, role)
print(f"\nApply run 1: {first.changed} changed, {first.ok} already correct")
for c in first.changes[:6]:
    print(f"  changed: {c}")
print("  ...")

after = ap.run_checks(state)
print(f"\nAFTER:  score {ap.score(after)}%  failed: {[r['id'] for r in after if r['status'] == 'fail']}")

second = ap.apply_role(state, role)
print(f"\nApply run 2 (idempotency): {second.changed} changed, {second.ok} already correct")

state["sysctl"]["net.ipv4.ip_forward"] = "1"  # simulate drift
drift = ap.apply_role(state, role)
print(f"After drift: {drift.changed} changed -> {drift.changes}")
