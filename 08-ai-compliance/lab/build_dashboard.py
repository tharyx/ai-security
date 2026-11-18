"""Build the Portfolio Project 5 compliance dashboard from the Module 07 and 08 lab data.

    inventory   07-ai-governance/lab/fixtures/systems_governed.yaml   (AI system register)
    policies    07-ai-governance/policies/*.md                        (policy pack)
    risks       08-ai-compliance/lab/fixtures/ai_risks.yaml           (top AI risks)
    controls    08-ai-compliance/lab/fixtures/controls.yaml           (control set + mappings)
    evidence    08-ai-compliance/lab/fixtures/evidence_<set>/         (evidence repository)

From the repository root:
    python 08-ai-compliance/lab/build_dashboard.py                       # Markdown to the screen
    python 08-ai-compliance/lab/build_dashboard.py --set vulnerable
    python 08-ai-compliance/lab/build_dashboard.py --out journal/week-32/compliance-dashboard.html

This is a script (like demo.py), so it may import sibling lab files. Synthetic data only.
"""

from __future__ import annotations

import argparse
from datetime import date
from pathlib import Path

import yaml

import certin_audit
import compliance_matrix as cm
import evidence_checker as ev

LAB = Path(__file__).resolve().parent
REPO = LAB.parents[1]
GOV = REPO / "07-ai-governance"


def collect(evidence_set: str, as_of: date) -> dict:
    controls = ev.load(LAB / "fixtures" / "controls.yaml")
    folder = LAB / "fixtures" / f"evidence_{evidence_set}"
    results = ev.check_evidence(controls, ev.load(folder / "index.yaml"), folder, as_of)
    status = ev.control_status(results)
    systems = yaml.safe_load((GOV / "lab" / "fixtures" / "systems_governed.yaml").read_text(encoding="utf-8"))
    policies = []
    for p in sorted((GOV / "policies").glob("[0-9][0-9]-*.md")):
        h = cm.parse_policy_header(p.read_text(encoding="utf-8"))
        try:
            h["overdue"] = date.fromisoformat(h["Next review"]) < as_of
        except ValueError:
            h["overdue"] = True  # no valid review date counts as overdue
        policies.append(h)
    return {
        "label": evidence_set, "as_of": as_of,
        "inventory": [{"id": s["id"], "name": s["name"], "tier": s.get("declared_tier") or "unknown",
                       "status": s["status"]} for s in systems],
        "policies": policies,
        "control_status": status,
        "coverage": ev.framework_coverage(controls, results),
        "domains": {f"{d} {certin_audit.CORE_DOMAINS[d]}": st
                    for d, st in certin_audit.domain_evidence_status(controls, status).items()},
        "matrix": cm.build_matrix(ev.load(LAB / "fixtures" / "ai_risks.yaml"), controls, results),
    }


def main() -> None:
    p = argparse.ArgumentParser(description="Build the AI governance and compliance dashboard.")
    p.add_argument("--set", choices=["compliant", "vulnerable"], default="compliant", help="evidence set")
    p.add_argument("--as-of", default="2026-11-15")
    p.add_argument("--out", help="write to this .md or .html file instead of printing Markdown")
    args = p.parse_args()
    data = collect(args.set, date.fromisoformat(args.as_of))
    if not args.out:
        print(cm.render_dashboard_md(data))
        return
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    text = cm.render_dashboard_html(data) if out.suffix.lower() in {".html", ".htm"} else cm.render_dashboard_md(data)
    out.write_text(text, encoding="utf-8")
    print(f"wrote {out} ({len(text)} characters)")


if __name__ == "__main__":
    main()
