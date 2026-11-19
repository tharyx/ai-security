"""Which identities and pods can reach Secrets? From repo root:
    .venv/Scripts/python csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/stealing-k8s-secrets/demo.py
"""
from pathlib import Path

import yaml

import secret_paths as sp

docs = [d for d in yaml.safe_load_all((Path(__file__).parent / "fixtures/rbac.yaml").read_text()) if d]
print("== RBAC paths to secrets ==")
for p in sp.analyse(docs):
    print(f"  [{p.severity:8}] {p.subject:22} ns={p.namespace:9} {p.path_id}: {p.why}")
print("== pods whose token carries that power ==")
for line in sp.pod_paths(docs):
    print(" ", line)
