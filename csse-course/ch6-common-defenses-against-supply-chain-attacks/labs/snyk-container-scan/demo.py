"""Demo: scan the fixture image."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import snyk_lite as s  # noqa: E402

issues = s.scan(s.IMAGE)
for i in issues:
    print(f"[{i['severity']:8}] {i['id']} {i['package']}@{i['version']} ({i['from']})")
print("advice:")
for a in s.fix_advice(issues):
    print("  -", a)
print("recommended base image:", s.recommend_base(s.IMAGE["base"]))
print("gate high:", "PASS" if s.gate(issues) else "FAIL", "| gate critical:", "PASS" if s.gate(issues, "critical") else "FAIL")
