"""Scan the fixture, propose fixes, scan again.

    python caisp-course/ch4-ai-attacks-and-defenses-devops/labs/third-party-vulns/demo.py
"""

from __future__ import annotations

from pathlib import Path

import analyzer as a

text = (Path(__file__).with_name("requirements.txt")).read_text(encoding="utf-8")
db = a.load_db()
findings = a.scan(a.parse_requirements(text), db)
print("== Before ==")
for f in findings:
    print(f)
fixes = a.propose_fixes(findings)
print("\n== Proposed fixes ==")
for name, version in fixes.items():
    print(f"{name} -> {version}")
fixed = a.apply_fixes(text, fixes)
print("\n== Fixed requirements ==")
print(fixed, end="")
print(f"\nFindings after the fix: {len(a.scan(a.parse_requirements(fixed), db))}")
