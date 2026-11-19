"""Secrets: base64, etcd encryption and consumption. From repo root:
    .venv/Scripts/python csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/k8s-secrets/demo.py
"""
from pathlib import Path

import yaml

import secrets_check as sc

FIX = Path(__file__).parent / "fixtures"
secret = yaml.safe_load((FIX / "secret.yaml").read_text())
print("decoded Secret (no key needed):", sc.decode_secret(secret))
print("committed to Git?             :", sc.secrets_in_git([secret]))
for name in ("encryption-config-bad.yaml", "encryption-config-good.yaml"):
    print(f"== {name} ==")
    for fid, sev, msg in sc.audit_encryption_config((FIX / name).read_text()) or [("-", "-", "no findings")]:
        print(f"  [{sev:8}] {fid} {msg}")
for pod in yaml.safe_load_all((FIX / "pods.yaml").read_text()):
    print(f"== pod {pod['metadata']['name']} ==")
    print("  uses  :", sc.secret_consumption(pod))
    for a in sc.consumption_advice(pod) or ["no advice: read-only volume, mode 0400"]:
        print("  advice:", a)
