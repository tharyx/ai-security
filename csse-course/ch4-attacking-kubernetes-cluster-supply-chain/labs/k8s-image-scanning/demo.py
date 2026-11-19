"""Scan every image in a manifest against a local DB. From repo root:
    .venv/Scripts/python csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/k8s-image-scanning/demo.py
"""
from pathlib import Path

import yaml

import image_scan as isc

FIX = Path(__file__).parent / "fixtures"
docs = [d for d in yaml.safe_load_all((FIX / "deploy.yaml").read_text()) if d]
db = isc.load_db(FIX / "vulndb.json")
reports = isc.scan_manifests(docs, db)
for r in reports:
    short = r.ref if len(r.ref) < 60 else r.ref[:40] + "..." + r.ref[-12:]
    print(f"{short}\n   used by {r.where}\n   counts {r.counts}")
    for p in r.problems:
        print("   PROBLEM:", p)
    if r.vulns:
        print("   fixable:", isc.fixable(r))
print("GATE:", "PASS" if isc.gate(reports) else "FAIL")
