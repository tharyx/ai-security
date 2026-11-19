"""Validate a good and a broken Deployment+Service+Ingress set. From repo root:
    .venv/Scripts/python csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/working-with-kubernetes/demo.py
"""
from pathlib import Path

import validate as v

FIX = Path(__file__).parent / "fixtures"
for name in ("good.yaml", "broken.yaml"):
    issues = v.validate(v.load(FIX / name))
    print(f"== {name}: {len(issues)} issue(s) ==")
    for i in issues:
        print(f"  [{i.severity:6}] {i.code} {i.where}: {i.message}")
