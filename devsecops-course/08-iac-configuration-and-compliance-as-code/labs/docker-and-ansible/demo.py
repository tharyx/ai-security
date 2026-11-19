"""From repo root:
    .venv/Scripts/python devsecops-course/08-iac-configuration-and-compliance-as-code/labs/docker-and-ansible/demo.py
"""
from pathlib import Path

import playbook_linter as pl

FIX = Path(__file__).parent / "fixtures"
for name in ("playbook_docker_host.yml", "playbook_docker_host_bad.yml"):
    found = pl.lint_file(FIX / name)
    print(f"== {name}: {pl.verdict(found)} ({len(found)} finding(s)) ==")
    for f in found:
        print(f"  [{f.severity:8}] {f.rule_id} {f.where}: {f.message}")
