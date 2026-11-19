"""Privileged pods, escape paths and Pod Security levels. From repo root:
    .venv/Scripts/python csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/privileged-pods/demo.py
"""
from pathlib import Path

import pod_escape as pe

path = Path(__file__).parent / "fixtures/pods.yaml"
for name, info in pe.analyse_file(path).items():
    print(f"{name:20} PSS level: {info['level']:10} escapes: {info['escapes']}")
    for v in info["baseline"][:3]:
        print(f"    blocks baseline : {v}")
print("module-06 linter rule IDs on the same file:", sorted(pe.lint06(path))[:8], "...")
print("PSA label that enforces 'restricted': pod-security.kubernetes.io/enforce=restricted")
