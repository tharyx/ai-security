"""Lint a bad and a good Dockerfile; write SARIF. From repo root:
    .venv/Scripts/python devsecops-course/11-defending-containers-at-scale/labs/hadolint-static-analysis/demo.py
"""
import json
from pathlib import Path

import hadolint_lite as h

FIX = Path(__file__).parent / "fixtures"
for name in ("Dockerfile.bad", "Dockerfile.good"):
    found = h.lint((FIX / name).read_text())
    print(f"== {name}: {len(found)} finding(s); gate(fail_on=error) passes: {h.gate(found)}")
    for x in found:
        print(f"  line {x.line:>2} {x.rule:<8} [{x.level}] {x.message}")
sarif = h.to_sarif(h.lint((FIX / "Dockerfile.bad").read_text()), "Dockerfile.bad")
print("== SARIF:", sarif["version"], "results =", len(sarif["runs"][0]["results"]))
print(json.dumps(sarif["runs"][0]["results"][0]))
