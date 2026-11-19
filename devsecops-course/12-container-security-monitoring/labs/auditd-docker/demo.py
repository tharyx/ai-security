"""Lint the rules and scan the audit log fixture. From repo root:
    .venv/Scripts/python devsecops-course/12-container-security-monitoring/labs/auditd-docker/demo.py
"""
from pathlib import Path

import auditd_tool as a

HERE = Path(__file__).parent
rules = a.parse_rules((HERE / "docker.rules").read_text())
print(f"{len(rules)} rules parsed; lint: {a.lint(rules) or 'OK'}")
print("lint of a weak ruleset:", a.lint(a.parse_rules("-w /usr/bin/docker\n-w /etc/docker -p r -k cfg\n"))[:4], "...")
events = a.parse_log((HERE / "audit.log").read_text())
print(f"{len(events)} audit events")
for al in a.detect(events):
    print(f"[{al['severity']}] {al['rule']} (event {al['serial']}): {al['detail']}")
