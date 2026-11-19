"""From repo root:
    .venv/Scripts/python devsecops-course/08-iac-configuration-and-compliance-as-code/labs/openscap-results/demo.py
"""
from pathlib import Path

import scap_results as sr

FIX = Path(__file__).parent / "fixtures"
before = sr.parse_results(FIX / "arf_before.xml")
after = sr.parse_results(FIX / "arf_after.xml")
print("=== BEFORE remediation ===")
print(sr.render(before))
print("\n=== AFTER remediation ===")
print(sr.render(after))
print("\n=== Comparison ===")
print(sr.compare(before, after))
