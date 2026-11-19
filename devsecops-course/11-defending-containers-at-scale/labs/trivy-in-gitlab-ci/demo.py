"""Validate good and bad GitLab CI fixtures. From repo root:
    .venv/Scripts/python devsecops-course/11-defending-containers-at-scale/labs/trivy-in-gitlab-ci/demo.py
"""
from pathlib import Path

import ci_validate as v

FIX = Path(__file__).parent / "fixtures"
for name in ("gitlab-ci.good.yml", "gitlab-ci.bad.yml"):
    probs = v.validate((FIX / name).read_text())
    print(f"== {name}: {len(probs)} problem(s)")
    for p in probs:
        print("  -", p)
