"""Audit a build server before and after hardening. From repo root:
    .venv/Scripts/python devsecops-course/11-defending-containers-at-scale/labs/audit-docker-daemon-host/demo.py
"""
import json
from pathlib import Path

import audit_host as a

FIX = Path(__file__).parent / "fixtures"
for name in ("buildserver_before.json", "buildserver_after.json"):
    b = json.loads((FIX / name).read_text())
    r = a.run(b)
    print(f"== {name}: score {r['score']}% weighted {r['weighted']}% gate exit={r['exit_code']}")
    print("   failed:", ", ".join(r["failed"]) or "none")
    for line in r["remediation"]:
        print("   fix ->", line)
info = a.parse_docker_info((FIX / "docker_info.txt").read_text())
print("== docker info parsed:", info)
print("== cross-check:", a.cross_check(json.loads((FIX / "buildserver_after.json").read_text()), info) or "consistent")
