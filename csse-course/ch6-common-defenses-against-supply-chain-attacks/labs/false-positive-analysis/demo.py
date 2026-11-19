"""Demo: triage with a suppression file (fixed 'today' so the output is reproducible)."""

import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fpa  # noqa: E402

today = date(2026, 11, 19)
res = fpa.triage(fpa.FINDINGS, fpa.load_suppressions(fpa.SUPPRESSIONS_YAML), today)
print("ACTIVE:")
for f in res["active"]:
    print(f"  [{f['severity']:8}] {f['rule']:22} {f['path']}")
print("SUPPRESSED:", [(f["rule"], f["suppressed_by"]) for f in res["suppressed"]])
print("NOTES:")
for n in res["notes"]:
    print("  -", n)
print(fpa.metrics(res))
