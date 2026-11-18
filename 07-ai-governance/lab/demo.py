"""Governance scorecard: the spreadsheet register vs the governed register.

From the repository root:
    python 07-ai-governance/lab/demo.py            # both fixture sets
    python 07-ai-governance/lab/demo.py --details  # also print every finding

The date is fixed (AS_OF) so the output is the same every run.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import date
from pathlib import Path

import yaml

import risk_register
from secure_register import GovernedRegister, discover_shadow_ai, governance_kpis
from vulnerable_register import SpreadsheetRegister, naive_residual

AS_OF = date(2026, 11, 15)
FIX = Path(__file__).with_name("fixtures")


def load_yaml(name: str) -> list[dict]:
    return yaml.safe_load((FIX / name).read_text(encoding="utf-8"))


def short_codes(codes: list[str]) -> str:
    counts = Counter(codes)
    return ",".join(c if n == 1 else f"{c}x{n}" for c, n in sorted(counts.items())) or "-"


def register_section(label: str, systems_file: str, risks_file: str, details: bool) -> None:
    raw = load_yaml(systems_file)
    risks = risk_register.load_csv(FIX / risks_file)
    sheet = SpreadsheetRegister()
    gov = GovernedRegister(as_of=AS_OF)
    rows = {r.system_id: r for r in sheet.load(raw)}
    results = gov.load(raw, risks)

    print(f"\n=== AI system register: {label} fixtures ({systems_file}) ===")
    print(f"{'system':7} {'name':30} {'declared':11} {'computed':11} {'spreadsheet':12} {'governed':9} findings")
    print("-" * 112)
    for a in results:
        print(f"{a.system_id:7} {a.name[:30]:30} {str(a.declared_tier):11} {a.tier:11} "
              f"{rows[a.system_id].decision:12} {a.decision:9} "
              f"{short_codes([f.code for f in a.findings])}"
              + (f"  (waived: {short_codes([f.key for f in a.waived])})" if a.waived else ""))
        if details:
            for f in a.findings:
                print(f"{'':9}{f.severity:8} {f.code} {f.message}")
    print("governance KPIs:", governance_kpis(results))

    print(f"\n--- risk register ({risks_file}) ---")
    print(f"{'risk':6} {'system':7} {'inherent':14} {'spreadsheet':12} {'scored residual':18} findings")
    for r in risk_register.score_register(risks, AS_OF):
        row = next(x for x in risks if x["risk_id"] == r.risk_id)
        print(f"{r.risk_id:6} {r.system_id:7} {r.inherent:>4.0f} {r.inherent_rating:9} {naive_residual(row):12} "
              f"{r.residual:>5.1f} {r.residual_rating:12} {short_codes([f.code for f in r.findings])}")
        if details:
            for f in r.findings:
                print(f"{'':9}{f.severity:8} {f.code} {f.message}")
    print("risk KPIs:", risk_register.register_kpis(risk_register.score_register(risks, AS_OF)))

    print("\n--- shadow AI (egress log vs register) ---")
    shadow = discover_shadow_ai((FIX / "egress_log.txt").read_text(encoding="utf-8").splitlines(), raw)
    for s in shadow:
        print(f"UNREGISTERED {s['host']:30} {s['service']:26} users={s['users']} "
              f"depts={','.join(s['depts'])} requests={s['requests']} bytes_out={s['bytes_out']}")
    if not shadow:
        print("none")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--details", action="store_true", help="print every finding")
    args = p.parse_args()
    print(f"As of {AS_OF}. Spreadsheet = vulnerable_register.py; governed = secure_register.py + risk_register.py")
    register_section("vulnerable", "systems_vulnerable.yaml", "risks_vulnerable.csv", args.details)
    register_section("governed", "systems_governed.yaml", "risks_governed.csv", args.details)
    print("\nCodes: GOV-00 schema, 01 unowned, 02 no intended use, 03 weak oversight, 04 tier under-declared,")
    print("05 missing control, 06 review overdue, 07 prohibited, 08 no risk entry, 09 expired exception.")
    print("RISK-01 no owner, 02 overdue treatment, 03 above appetite with no plan, 04 invalid acceptance,")
    print("05 closed on a planned control, 06 bad scores. Run with --details to see every message.")


if __name__ == "__main__":
    main()
