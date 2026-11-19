"""Check userns-remap, TCP socket and fd socket on fixtures. From repo root:
    .venv/Scripts/python devsecops-course/11-defending-containers-at-scale/labs/userns-remap-and-socket/demo.py
"""
import json
from datetime import date
from pathlib import Path

import daemon_checks as d

FIX = Path(__file__).parent / "fixtures"
bad = json.loads((FIX / "daemon_bad.json").read_text())
good = json.loads((FIX / "daemon_good.json").read_text())
subuid = (FIX / "subuid").read_text()
print("== BAD daemon.json")
print("userns:", d.check_userns(bad, subuid, subuid))
for sev, msg in d.check_tcp(bad):
    print(f"tcp   : [{sev}] {msg}")
print("fd    :", d.check_fd(bad, (FIX / "docker.socket.bad").read_text()))
print("== GOOD daemon.json")
print("userns:", d.check_userns(good, subuid, subuid) or "OK")
print("tcp   :", d.check_tcp(good) or "OK")
print("fd    :", d.check_fd(good, (FIX / "docker.socket.good").read_text()) or "OK")
print("== userns with missing subuid range:", d.check_userns(good, (FIX / "subuid_missing").read_text(), subuid))
cert = json.loads((FIX / "client_cert.json").read_text())
print("== client cert today:", d.check_client_cert(cert, {"ci-runner-01"}, date(2026, 11, 19)) or "OK")
print("== client cert in 2028:", d.check_client_cert(cert, {"ci-runner-01"}, date(2028, 1, 1)))
