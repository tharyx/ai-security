"""Run Wazuh-style Docker rules over event fixtures. From repo root:
    .venv/Scripts/python devsecops-course/12-container-security-monitoring/labs/wazuh-docker-monitoring/demo.py
"""
import json
from pathlib import Path

import wazuh_lite as w

HERE = Path(__file__).parent
rules = w.load_rules((HERE / "local_rules.xml").read_text())
events = [json.loads(l) for l in (HERE / "events.jsonl").read_text().splitlines() if l.strip()]
print(f"{len(rules)} rules, {len(events)} events")
for a in w.run(rules, events, min_level=3):
    print(f"t={a['ts']} level {a['level']:>2} rule {a['rule']} [{a['target']}] {a['description']}")
print("--- only level >= 7 (what you would page on) ---")
for a in w.run(rules, events, min_level=7):
    print(f"t={a['ts']} level {a['level']:>2} rule {a['rule']} {a['description']}")
