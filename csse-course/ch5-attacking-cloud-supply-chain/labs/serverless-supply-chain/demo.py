"""Demo: audit the serverless fixtures."""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import audit  # noqa: E402

doc = audit.load(HERE / "fixtures" / "functions.json")
for f in audit.audit(doc):
    print(f"[{f.severity:8}] {f.rule:19} {f.function:12} {f.detail[:75]}")
print()
for fn in doc["functions"]:
    print(f"{fn['name']:12} blast radius: {audit.blast_radius(fn)}")
