"""Audit a bad and a good bundle. From repo root:
    .venv/Scripts/python devsecops-course/11-defending-containers-at-scale/labs/cis-docker-compliance/demo.py
"""
import json
from pathlib import Path

import cis_audit as c

FIX = Path(__file__).parent / "fixtures"
for name in ("bundle_bad.json", "bundle_good.json"):
    res = c.audit(json.loads((FIX / name).read_text()))
    print(f"== {name}: score {c.score(res)}% (weighted {c.weighted_score(res)}%), gate(high) exit code {c.exit_code(res)}")
    print("   by section:", {k: f"{p}/{t}" for k, (p, t) in c.by_section(res).items()})
    if name.endswith("bad.json"):
        print(c.report(res, only_failures=True))
