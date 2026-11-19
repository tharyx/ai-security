"""Scan the vulnerable sample app and the fixed version.

    python caisp-course/ch4-ai-attacks-and-defenses-devops/labs/ai-code-weaknesses/demo.py
"""

from __future__ import annotations

from pathlib import Path

from scanner import scan_file

here = Path(__file__).resolve().parent
for name in ("vulnerable_app.py", "fixed_app.py"):
    findings = scan_file(here / "sample_app" / name)
    print(f"== {name}: {len(findings)} finding(s) ==")
    for f in findings:
        print(f"  {f}")
