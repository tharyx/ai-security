"""Run Tracee-style signatures over an eBPF-event fixture. From repo root:
    .venv/Scripts/python devsecops-course/12-container-security-monitoring/labs/tracee-runtime/demo.py
"""
import json
from pathlib import Path

import tracee_lite as t

events = [json.loads(l) for l in (Path(__file__).parent / "events.jsonl").read_text().splitlines() if l.strip()]
for a in t.run(events):
    print(f"t={a['ts']} sev={a['severity']} {a['id']} {a['name']} [container {a['container']}]: {a['msg']}")
