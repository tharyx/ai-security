"""Demo: risk register scorer and SoA gap checker.

Run from the repo root:
    .venv/Scripts/python cybersecurity-track/04-risk-management-and-iso27001/lab/demo.py
"""

import sys
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import risk_register as rr  # noqa: E402
import soa_checker as sc  # noqa: E402

AS_OF = date(2026, 11, 18)

print("=== Part 1: risk register (YAML), appetite = residual 9, as of 2026-11-18 ===")
risks = rr.load_yaml((HERE / "samples" / "risks.yaml").read_text())
print(rr.format_table(rr.assess(risks, AS_OF, appetite=9)))

print("\n=== Part 1b: risk register (CSV) ===")
print(rr.format_table(rr.assess(rr.load_csv((HERE / "samples" / "risks.csv").read_text()), AS_OF)))

print("\n=== Part 2: SoA gap check (11 listed controls plus 2 expected but missing) ===")
entries = sc.load_soa((HERE / "samples" / "soa.yaml").read_text())
scope = [e.control_id for e in entries if e.control_id != "8.99"] + ["5.7", "8.8"]
gaps = sc.check(entries, expected=scope)
print(sc.format_gaps(gaps))
print("Summary:", sc.summary(entries, gaps, scope))

print(f"\nFull Annex A has {len(sc.annex_a_ids())} controls. "
      f"This SoA would leave {len(sc.check(entries)) - 1} gaps against all 93 "
      f"(plus 1 unknown-ID row).")
