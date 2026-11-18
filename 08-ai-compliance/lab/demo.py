"""Compliance scorecard: checkbox compliance vs evidence-based compliance.

From the repository root:
    python 08-ai-compliance/lab/demo.py
    python 08-ai-compliance/lab/demo.py --case cv-screening-deployer   # full obligation list

EDUCATIONAL, NOT LEGAL ADVICE. The date is fixed (AS_OF) so output is stable.
"""

from __future__ import annotations

import argparse
from datetime import date, datetime
from pathlib import Path

import yaml

import ai_act_classifier as act
import evidence_checker as ev
import incident_clock
import privacy_rights
from vulnerable_compliance import naive_classify, naive_erasure, naive_evidence_check

AS_OF = date(2026, 11, 15)
FIX = Path(__file__).with_name("fixtures")


def section_ai_act(case: str | None) -> None:
    cases = yaml.safe_load((FIX / "ai_act_cases.yaml").read_text(encoding="utf-8"))
    print("=== 1. EU AI Act classification (educational, not legal advice) ===")
    print(f"{'case':26} {'naive':14} {'engine categories':26} {'role':9} {'#obl':>4}  applies from (original dates)")
    print("-" * 112)
    for raw in cases:
        c = act.classify(raw)
        dates = sorted({o.applies_from.isoformat() for o in c.obligations})
        print(f"{c.case:26} {naive_classify(raw):14} {'+'.join(c.categories):26} {c.role:9} "
              f"{len(c.obligations):>4}  {', '.join(dates) or '-'}")
        if case == c.case:
            for r in c.reasons:
                print(f"{'':6}WHY: {r}")
            for o in c.obligations:
                print(f"{'':6}{o.ref:13} from {o.applies_from}  {o.text}")
            for q in c.open_questions:
                print(f"{'':6}ASK COUNSEL: {q}")
    print(act.DATES_NOTE)


def section_evidence() -> None:
    controls = yaml.safe_load((FIX / "controls.yaml").read_text(encoding="utf-8"))
    for name in ("vulnerable", "compliant"):
        folder = FIX / f"evidence_{name}"
        index = yaml.safe_load((folder / "index.yaml").read_text(encoding="utf-8"))
        naive = naive_evidence_check(controls, index)
        results = ev.check_evidence(controls, index, folder, AS_OF)
        status = ev.control_status(results)
        print(f"\n=== 2. Evidence gaps: {name} set (as of {AS_OF}) ===")
        print(f"{'control':11} {'checkbox':11} {'checker':8} problems")
        print("-" * 100)
        for c in controls:
            probs = [f"{r.evidence_type}={r.status}" for r in results if r.control == c["id"] and r.status != "OK"]
            print(f"{c['id']:11} {naive[c['id']]:11} {status[c['id']]:8} {', '.join(probs) or '-'}")
        print("framework coverage (requirements backed by a control with good evidence):")
        for fw, cov in ev.framework_coverage(controls, results).items():
            print(f"  {fw:12} {cov['covered']:>2}/{cov['requirements']:<2}"
                  + (f"  gaps: {'; '.join(cov['gaps'][:3])}{' ...' if len(cov['gaps']) > 3 else ''}"
                     if cov["gaps"] else ""))


def section_privacy() -> None:
    print("\n=== 3. Right to erasure in a RAG assistant ===")
    q = "What is the email for loyalty id L-5521?"
    ids = ["asha.verma@customer.example", "Asha Verma", "L-5521"]
    store = privacy_rights.demo_store(AS_OF)
    naive_erasure(store, "cust-5521")
    print(f"naive erasure (source only) -> assistant still answers: {store.ask(q)!r}")
    store = privacy_rights.demo_store(AS_OF)
    store.use_for_fine_tuning("FT-2026-07")
    receipt = store.erase_subject("cust-5521", ids, AS_OF)
    print(f"layered erasure            -> assistant answers:       {store.ask(q)!r}")
    print(f"receipt removed: {receipt.removed}")
    for p in receipt.pending:
        print(f"receipt PENDING: {p}")


def section_incident() -> None:
    print("\n=== 4. Reporting clocks for one AI incident ===")
    aware = datetime(2026, 11, 14, 9, 0)
    incident = {
        "aware_at": aware, "eu_high_risk_provider": True, "eu_serious_incident": True,
        "personal_data_breach": True, "eu_personal_data": True, "india_personal_data": True,
        "india_reportable_cyber_incident": True,
    }
    print("Scenario: prompt injection made the CV-screening product leak applicant data (EU + India).")
    print(f"Aware at {aware:%Y-%m-%d %H:%M}.")
    for c in incident_clock.reporting_clocks(incident):
        when = f"by {c.deadline:%Y-%m-%d %H:%M}" if c.deadline else "without delay"
        print(f"  {c.regime:10} notify {c.notify:48} {when:19} ({c.basis})")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--case", help="print every obligation for one AI Act case")
    args = p.parse_args()
    section_ai_act(args.case)
    section_evidence()
    section_privacy()
    section_incident()
    print("\n" + act.DISCLAIMER)


if __name__ == "__main__":
    main()
