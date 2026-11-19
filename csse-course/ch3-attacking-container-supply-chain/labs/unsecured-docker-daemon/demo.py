"""Audit an insecure and a hardened daemon.json. From repo root:
    .venv/Scripts/python csse-course/ch3-attacking-container-supply-chain/labs/unsecured-docker-daemon/demo.py
"""
import json
from pathlib import Path

import daemon_audit as da

FIX = Path(__file__).parent / "fixtures"
for name in ("daemon_insecure.json", "daemon_secure.json"):
    cfg = json.loads((FIX / name).read_text())
    findings = da.audit(cfg)
    print(f"== {name}: {len(findings)} finding(s) ==")
    for f in findings:
        print(f"  [{f.severity:8}] {f.rule_id} {f.message}")
    d = da.FakeDaemon(cfg)
    print("  anonymous GET /version ->", d.get_version())
print("== listening sockets ==")
for f in da.scan_listeners((FIX / "listeners.txt").read_text()):
    print(f"  [{f.severity:8}] {f.rule_id} {f.message}")
print("== docker.sock permissions ==")
for f in da.socket_findings("0666", "users"):
    print(f"  [{f.severity:8}] {f.rule_id} {f.message}")
