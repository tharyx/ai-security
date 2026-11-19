"""From repo root:
    .venv/Scripts/python devsecops-course/08-iac-configuration-and-compliance-as-code/labs/ansible-pci-dss-hardening/demo.py
"""
from pathlib import Path

import pci_mapper as pm

FIX = Path(__file__).parent / "fixtures"
tasks = pm.load_tasks(FIX / "pci_hardening_playbook.yml")
mapping = pm.load_mapping(FIX / "pci_mapping.yml")
print(pm.render_text(pm.coverage(tasks, mapping)))
