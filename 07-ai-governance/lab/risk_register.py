"""AI risk-register scorer: inherent risk, residual risk after controls, and hygiene checks.

Input: a CSV like fixtures/risks_governed.csv (based on 00-program/templates/risk-register.csv,
with numeric scores so a program can check it).

    inherent  = likelihood x impact                      (each 1..5, so 1..25)
    residual  = inherent x product of (1 - effect x credit) for each control

    effect    hard 0.60  (deterministic code: tool policy, ACL, schema)
              process 0.30 (human review, approval workflow)
              soft 0.25  (spotlighting, classifier, prompt wording)
    credit    tested 1.0 | implemented 0.5 | planned 0.0

These weights are teaching numbers, not an industry standard. The *shape* is the lesson:
a planned control reduces nothing, an untested control is half-trusted, and a soft control
never takes a critical risk to low on its own.

Switchable layers:
    require_evidence  if False, every listed control gets full credit (paper controls count)
    check_deadlines   if False, overdue treatments and expired acceptances are ignored
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

EFFECT = {"hard": 0.60, "process": 0.30, "soft": 0.25}
CREDIT = {"tested": 1.0, "implemented": 0.5, "planned": 0.0}
APPETITE = 9.0  # residual scores above this need a treatment plan or a valid acceptance
OPEN_STATES = {"open", "in_progress"}
# Who may accept a residual risk of each rating (delegation of authority).
ACCEPT_AUTHORITY = {
    "Low": None,  # any named risk owner
    "Medium": {"System Owner", "CISO", "AI Governance Board"},
    "High": {"CISO", "AI Governance Board"},
    "Critical": {"AI Governance Board"},
}


def rating(score: float) -> str:
    if score >= 15:
        return "Critical"
    if score >= 10:
        return "High"
    if score >= 5:
        return "Medium"
    return "Low"


@dataclass
class Control:
    kind: str
    name: str
    state: str


@dataclass
class RiskFinding:
    code: str
    severity: str
    message: str


@dataclass
class ScoredRisk:
    risk_id: str
    system_id: str
    threat: str
    inherent: float
    residual: float
    status: str
    findings: list[RiskFinding] = field(default_factory=list)

    @property
    def inherent_rating(self) -> str:
        return rating(self.inherent)

    @property
    def residual_rating(self) -> str:
        return rating(self.residual)

    @property
    def codes(self) -> set[str]:
        return {f.code for f in self.findings}


def load_csv(path: str | Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def parse_controls(text: str) -> list[Control]:
    """'hard:Tool broker authorization:tested; soft:Spotlighting:implemented'"""
    out = []
    for part in (text or "").split(";"):
        bits = [b.strip() for b in part.split(":")]
        if len(bits) == 3 and bits[0] in EFFECT and bits[2] in CREDIT:
            out.append(Control(bits[0], bits[1], bits[2]))
        elif part.strip():
            out.append(Control("unknown", part.strip(), "planned"))  # unparseable = no credit
    return out


def _date(text: str | None) -> date | None:
    return date.fromisoformat(text) if text and text.strip() else None


def score_risk(row: dict, as_of: date, *, require_evidence: bool = True,
               check_deadlines: bool = True) -> ScoredRisk:
    add_findings: list[RiskFinding] = []
    try:
        likelihood, impact = int(row["likelihood"]), int(row["impact"])
        if not (1 <= likelihood <= 5 and 1 <= impact <= 5):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        return ScoredRisk(row.get("risk_id", "?"), row.get("system_id", "?"), row.get("threat", ""),
                          25, 25, row.get("status", "?"),
                          [RiskFinding("RISK-06", "high", "likelihood/impact must be integers 1-5")])

    inherent = float(likelihood * impact)
    residual = inherent
    controls = parse_controls(row.get("controls", ""))
    for c in controls:
        credit = 1.0 if not require_evidence else CREDIT[c.state]
        residual *= 1 - EFFECT.get(c.kind, 0.0) * credit
    residual = round(residual, 1)
    status = (row.get("status") or "").strip().lower()
    r = ScoredRisk(row["risk_id"], row.get("system_id", ""), row.get("threat", ""), inherent, residual, status,
                   add_findings)
    add = add_findings.append

    if not (row.get("owner") or "").strip():
        add(RiskFinding("RISK-01", "high", "no risk owner"))
    due = _date(row.get("due_date"))
    if check_deadlines and status in OPEN_STATES and due and due < as_of:
        add(RiskFinding("RISK-02", "high", f"treatment overdue since {due} ({(as_of - due).days} days)"))
    if residual > APPETITE and status != "accepted" and not ((row.get("treatment") or "").strip() and due):
        add(RiskFinding("RISK-03", "high", f"residual {residual} above appetite {APPETITE} with no dated treatment plan"))
    if status == "accepted":
        approver = (row.get("accepted_by") or "").strip()
        allowed = ACCEPT_AUTHORITY[r.residual_rating]
        expiry = _date(row.get("acceptance_expiry"))
        if not approver:
            add(RiskFinding("RISK-04", "high", "accepted with no named approver"))
        elif allowed is not None and approver not in allowed:
            add(RiskFinding("RISK-04", "high",
                            f"'{approver}' may not accept a {r.residual_rating} residual risk"))
        if expiry is None:
            add(RiskFinding("RISK-04", "high", "acceptance has no expiry date"))
        elif check_deadlines and expiry < as_of:
            add(RiskFinding("RISK-04", "high", f"acceptance expired on {expiry}"))
    if status in {"closed", "mitigated"} and any(c.state == "planned" for c in controls):
        add(RiskFinding("RISK-05", "medium", "closed while a listed control is only planned"))
    return r


def score_register(rows: list[dict], as_of: date, **kw) -> list[ScoredRisk]:
    return [score_risk(row, as_of, **kw) for row in rows]


def register_kpis(scored: list[ScoredRisk]) -> dict:
    live = [r for r in scored if r.status != "closed"]
    return {
        "risks": len(scored),
        "above_appetite": sum(r.residual > APPETITE for r in live),
        "overdue_treatments": sum("RISK-02" in r.codes for r in scored),
        "invalid_acceptances": sum("RISK-04" in r.codes for r in scored),
        "unowned": sum("RISK-01" in r.codes for r in scored),
    }


def main() -> None:
    """Score a risk-register CSV from the command line.

    python 07-ai-governance/lab/risk_register.py 07-ai-governance/lab/fixtures/risks_vulnerable.csv
    """
    import argparse

    p = argparse.ArgumentParser(description="Score an AI risk register CSV.")
    p.add_argument("csv")
    p.add_argument("--as-of", default="2026-11-15", help="assessment date (YYYY-MM-DD)")
    p.add_argument("--no-evidence-rule", action="store_true", help="give planned/untested controls full credit")
    p.add_argument("--no-deadlines", action="store_true", help="ignore due dates and acceptance expiry")
    args = p.parse_args()
    scored = score_register(load_csv(args.csv), date.fromisoformat(args.as_of),
                            require_evidence=not args.no_evidence_rule, check_deadlines=not args.no_deadlines)
    print(f"{'risk':6} {'system':7} {'inherent':>8} {'residual':>9}  {'rating':9} findings")
    for r in scored:
        print(f"{r.risk_id:6} {r.system_id:7} {r.inherent:>8.0f} {r.residual:>9.1f}  {r.residual_rating:9} "
              f"{'; '.join(f'{f.code} {f.message}' for f in r.findings) or '-'}")
    print(register_kpis(scored))


if __name__ == "__main__":
    main()
