"""Insecure versus hardened kubelet (simulated). From repo root:
    .venv/Scripts/python csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/kubelet-api/demo.py
"""
from pathlib import Path

import kubelet_sim as ks

FIX = Path(__file__).parent / "fixtures"
PODS = [{"namespace": "shop", "name": "web-1", "image": "registry.corp.example/shop/web:1.4"},
        {"namespace": "payments", "name": "pay-1", "image": "registry.corp.example/pay/api:2.0"}]
for name in ("kubelet-insecure.yaml", "kubelet-hardened.yaml"):
    cfg = ks.load_config((FIX / name).read_text())
    k = ks.Kubelet(cfg, PODS, allowed={"prometheus": {"nodes/metrics"}})
    print(f"== {name} ==")
    for f in ks.audit_config(cfg):
        print(f"  [{f.severity:8}] {f.rule_id} {f.message}")
    print("  anonymous GET  /pods :", k.handle("GET", "/pods"))
    print("  anonymous POST /run  :", k.handle("POST", "/run/payments/pay-1/api", body={"cmd": "id"}))
    print("  read-only port 10255 :", k.handle("GET", "/pods", port=10255)[0])
    print("  prometheus /metrics  :", k.handle("GET", "/metrics", user="prometheus")[0])
    print("  prometheus /pods     :", k.handle("GET", "/pods", user="prometheus"))
