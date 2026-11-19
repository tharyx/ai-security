"""Demo: audit the fixture estate."""

import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import audit  # noqa: E402

findings = audit.audit(audit.load(HERE / "fixtures" / "estate.json"))
for f in findings:
    print(f"[{f.severity:8}] {f.rule:22} {f.resource:34} {f.detail[:70]}")
print(dict(Counter(f.severity for f in findings)))
