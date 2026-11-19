"""Compare a 'spreadsheet' risk register with a governed one. Offline, fictional data."""
import sys
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import risk_register as rr  # noqa: E402

TODAY = date(2026, 11, 19)  # fixed so the output is stable
for name in ("register_spreadsheet.json", "register_governed.json"):
    risks = rr.load(HERE / "fixtures" / name)
    print(f"=== {name} (as of {TODAY}) ===")
    print(rr.report(risks, today=TODAY))
    print()

print("Treatment suggestions (heuristic, a reviewer still decides):")
for lik, imp, optional in [(2, 2, False), (4, 4, True), (2, 5, False), (4, 4, False)]:
    print(f"  likelihood {lik}, impact {imp}, optional activity={optional}: "
          f"{rr.suggest_treatment(lik, imp, optional_activity=optional)}")
