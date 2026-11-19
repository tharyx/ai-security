"""Demo: vet a benign skill and a ClawHavoc-style malicious sample (nothing is executed)."""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import vet  # noqa: E402

for name in ("notes-helper", "githuub-helper"):
    r = vet.vet(HERE / "fixtures" / name)
    print(f"== {r['name']}: {r['verdict']} ==")
    for f in r["findings"] or []:
        print(f"  [{f.severity:8}] {f.check:16} {f.detail}")
    if not r["findings"]:
        print("  no findings")
