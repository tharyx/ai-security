"""Audit Harbor-style project policy and test pulls. From repo root:
    .venv/Scripts/python devsecops-course/11-defending-containers-at-scale/labs/harbor-secure-by-default/demo.py
"""
import json
from pathlib import Path

import project_policy as pp

FIX = Path(__file__).parent / "fixtures"
for n in ("project_default.json", "project_hardened.json"):
    p = json.loads((FIX / n).read_text())
    print(f"== {n}: {len(pp.audit_project(p))} finding(s)")
    for f in pp.audit_project(p):
        print("  -", f)
    for img in ({"max_severity": "low", "signed": True, "scanned": True},
                {"max_severity": "critical", "signed": True, "scanned": True},
                {"max_severity": "low", "signed": False, "scanned": True}):
        print("  pull", img, "->", pp.may_pull(p, img))
