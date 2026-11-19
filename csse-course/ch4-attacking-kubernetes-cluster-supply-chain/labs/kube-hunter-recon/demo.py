"""Recon report from a simulated inventory. From repo root:
    .venv/Scripts/python csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/kube-hunter-recon/demo.py
"""
from pathlib import Path

import recon

print(recon.report(recon.load(Path(__file__).parent / "fixtures/cluster_endpoints.json")))
