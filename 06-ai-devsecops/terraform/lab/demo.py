"""Print a scorecard: every policy rule against the vulnerable and the secure plan.

From the repository root:
    python 06-ai-devsecops/terraform/lab/demo.py
"""

from __future__ import annotations

from collections import Counter
from datetime import date
from pathlib import Path

import policy_check as pc

LAB = Path(__file__).parent
TODAY = date(2026, 11, 18)  # fixed so the output is the same every run


def main() -> None:
    waivers = pc.load_waivers(LAB / "waivers.json")
    vuln = pc.check_plan(pc.load_plan(LAB / "plans" / "vulnerable.plan.json"), today=TODAY)
    sec = pc.check_plan(pc.load_plan(LAB / "plans" / "secure.plan.json"), waivers=waivers, today=TODAY)
    v_count = Counter(f.rule_id for f in vuln.findings)
    s_count = Counter(f.rule_id for f in sec.findings)
    s_waived = {f.rule_id for f, _ in sec.waived}

    print(f"{'rule':10} {'sev':8} {'title':56} {'vulnerable':11} secure")
    print("-" * 96)
    for rule_id, (severity, title, _) in sorted(pc.RULES.items()):
        v = f"FAIL x{v_count[rule_id]}" if v_count[rule_id] else "ok"
        s = "WAIVED" if rule_id in s_waived else (f"FAIL x{s_count[rule_id]}" if s_count[rule_id] else "ok")
        print(f"{rule_id:10} {severity:8} {title[:56]:56} {v:11} {s}")

    print()
    for name, report in (("vulnerable", vuln), ("secure", sec)):
        verdict = "FAIL" if report.failed("MEDIUM") else "PASS"
        print(f"{name:10} ->{verdict} (fail-on MEDIUM): {len(report.findings)} open, {len(report.waived)} waived")
    print("\nTip: run policy_check.py plans/secure.plan.json without --waivers and see TF-AI-060 come back.")


if __name__ == "__main__":
    main()
