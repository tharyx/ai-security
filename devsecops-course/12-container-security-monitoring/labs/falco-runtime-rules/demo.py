"""Run Falco-subset rules over a syscall-event fixture. From repo root:
    .venv/Scripts/python devsecops-course/12-container-security-monitoring/labs/falco-runtime-rules/demo.py
"""
import json
from pathlib import Path

import falco_lite as f

HERE = Path(__file__).parent
rules = f.load((HERE / "rules.yaml").read_text())
events = [json.loads(l) for l in (HERE / "events.jsonl").read_text().splitlines() if l.strip()]
print(f"{len(rules)} rules, {len(events)} events")
for a in f.run(rules, events):
    print(f"event {a['n']:>2} {a['priority']:<8} {a['rule']}: {a['text']}")
