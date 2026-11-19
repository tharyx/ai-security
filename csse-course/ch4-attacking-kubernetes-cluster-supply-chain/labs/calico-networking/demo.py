"""Reachability with and without default deny. From repo root:
    .venv/Scripts/python csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/calico-networking/demo.py
"""
from pathlib import Path

import yaml

import netpol as np_

FIX = Path(__file__).parent / "fixtures"
c = yaml.safe_load((FIX / "cluster.yaml").read_text())
policies = list(yaml.safe_load_all((FIX / "policies.yaml").read_text()))
pods = [np_.Pod(p["name"], p["namespace"], p["labels"]) for p in c["pods"]]
by = {p.name: p for p in pods}

for title, pols in [("no policies (flat network)", []), ("default deny + allow rules", policies)]:
    cl = np_.Cluster(pods, c["namespaces"], pols)
    print(f"== {title} ==")
    print("  not isolated for ingress:", np_.exposed_pods(cl))
    for src, dst, port in [("web", "api", 8080), ("web", "db", 5432), ("api", "db", 5432), ("rogue", "db", 5432), ("rogue", "web", 80), ("web", "payments-api", 443)]:
        print(f"  {src:6} -> {dst:12} :{port:<5} {'ALLOW' if cl.can_reach(by[src], by[dst], port) else 'deny'}")
