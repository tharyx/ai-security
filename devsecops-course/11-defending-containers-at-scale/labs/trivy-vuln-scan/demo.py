"""Parse a Trivy report and gate it. From repo root:
    .venv/Scripts/python devsecops-course/11-defending-containers-at-scale/labs/trivy-vuln-scan/demo.py
"""
import json
from pathlib import Path

import trivy_report as t

FIX = Path(__file__).parent / "fixtures"
rep = json.loads((FIX / "trivy-report.json").read_text())
print("summary:", t.summary(rep))
print("secrets:", [s["RuleID"] for s in t.secrets(rep)], "| failed misconfigs:", [m["ID"] for m in t.misconfigs(rep)])
for label, kw in [("HIGH gate", {}), ("CRITICAL gate", {"fail_on": "CRITICAL"}),
                  ("HIGH + ignore-unfixed + trivyignore", {"ignore_unfixed": True,
                   "ignore_ids": t.parse_ignore((FIX / "trivyignore.txt").read_text())})]:
    ok, why = t.gate(rep, **kw)
    print(f"-- {label}: {'PASS' if ok else 'FAIL'} ({len(why)} reasons)")
    for w in why:
        print("   ", w)
