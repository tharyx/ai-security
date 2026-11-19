"""A small risk register with treatment rules: identify -> assess -> treat -> residual.

Pure standard library. The register is a JSON file of risks. Each risk records where it
was found (its identification source), an inherent likelihood and impact (1-5 each), a
treatment (avoid, accept, mitigate, transfer) and the evidence that the treatment needs.

The point of the lab is that every treatment has its own rules:

* mitigate  -> needs at least one control; controls lower likelihood or impact.
* avoid     -> needs a described change (the risky activity is removed); residual is 0.
* transfer  -> needs a named party (insurer, vendor contract); it can lower impact by
               at most 1 because you cannot transfer accountability, reputation or
               regulatory duty.
* accept    -> needs an owner with authority for that level, a reason and a review date.

A "spreadsheet register" with silent acceptances fails the gate; a governed one passes.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

TREATMENTS = ("avoid", "accept", "mitigate", "transfer")
SOURCES = ("compliance", "design", "vulnerability", "threat-landscape")
# Who may accept a risk, by residual band. Lower roles cannot sign off higher bands.
ACCEPT_AUTHORITY = {
    "LOW": {"team-lead", "product-owner", "ciso", "cro", "ceo"},
    "MEDIUM": {"product-owner", "ciso", "cro", "ceo"},
    "HIGH": {"ciso", "cro", "ceo"},
    "CRITICAL": {"ceo"},
}


def band(score: int) -> str:
    """5x5 matrix bands, the same as cybersecurity-track module 04."""
    if score <= 0:
        return "NONE"
    if score <= 4:
        return "LOW"
    if score <= 9:
        return "MEDIUM"
    if score <= 16:
        return "HIGH"
    return "CRITICAL"


@dataclass
class Control:
    name: str
    reduces: str  # "likelihood" or "impact"
    by: int


@dataclass
class Risk:
    id: str
    title: str
    source: str
    likelihood: int
    impact: int
    treatment: str
    owner: str = ""
    controls: list[Control] = field(default_factory=list)
    change: str = ""          # avoid: what was removed or redesigned
    transfer_to: str = ""     # transfer: insurer or contract party
    transfer_reduces: int = 0  # transfer: requested impact reduction
    accepted_by: str = ""     # accept: role that signed
    reason: str = ""          # accept: why
    review_date: str = ""     # accept: ISO date
    business_service: str = ""
    critical_service: bool = False
    bcp_ref: str = ""         # continuity plan reference for critical services

    @property
    def inherent(self) -> int:
        return self.likelihood * self.impact

    def residual_li(self) -> tuple[int, int]:
        """Residual (likelihood, impact) after the treatment."""
        lik, imp = self.likelihood, self.impact
        if self.treatment == "avoid" and self.change:
            return 0, 0
        if self.treatment == "mitigate":
            for c in self.controls:
                if c.reduces == "likelihood":
                    lik -= c.by
                elif c.reduces == "impact":
                    imp -= c.by
        if self.treatment == "transfer" and self.transfer_to:
            imp -= min(self.transfer_reduces, 1)  # cap: accountability stays with you
        return max(lik, 1), max(imp, 1)

    @property
    def residual(self) -> int:
        lik, imp = self.residual_li()
        return lik * imp


def load(path: str | Path) -> list[Risk]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    risks = []
    for r in data["risks"]:
        controls = [Control(**c) for c in r.pop("controls", [])]
        risks.append(Risk(controls=controls, **r))
    return risks


def validate(risk: Risk, appetite: int = 9, today: date | None = None) -> list[str]:
    """Return issue codes for one risk. Empty list = governed."""
    today = today or date.today()
    issues: list[str] = []
    if risk.source not in SOURCES:
        issues.append("UNKNOWN_SOURCE")
    if risk.treatment not in TREATMENTS:
        issues.append("UNKNOWN_TREATMENT")
        return issues
    if not (1 <= risk.likelihood <= 5 and 1 <= risk.impact <= 5):
        issues.append("SCORE_OUT_OF_RANGE")
    if not risk.owner:
        issues.append("NO_OWNER")
    if risk.treatment == "mitigate" and not risk.controls:
        issues.append("MITIGATE_WITHOUT_CONTROL")
    if risk.treatment == "mitigate" and any(c.by <= 0 for c in risk.controls):
        issues.append("CONTROL_WITH_NO_EFFECT")
    if risk.treatment == "avoid" and not risk.change:
        issues.append("AVOID_WITHOUT_CHANGE")
    if risk.treatment == "transfer":
        if not risk.transfer_to:
            issues.append("TRANSFER_WITHOUT_PARTY")
        if risk.transfer_reduces > 1:
            issues.append("TRANSFER_OVERCLAIMED")
    if risk.treatment == "accept":
        if not risk.reason:
            issues.append("ACCEPT_WITHOUT_REASON")
        if not risk.review_date:
            issues.append("ACCEPT_WITHOUT_REVIEW_DATE")
        elif date.fromisoformat(risk.review_date) < today:
            issues.append("ACCEPTANCE_EXPIRED")
        allowed = ACCEPT_AUTHORITY.get(band(risk.residual), set())
        if risk.accepted_by not in allowed:
            issues.append("ACCEPTED_WITHOUT_AUTHORITY")
    elif risk.residual > appetite:
        issues.append("RESIDUAL_ABOVE_APPETITE")
    if risk.critical_service and not risk.bcp_ref:
        issues.append("NO_CONTINUITY_PLAN")
    return issues


def coverage_gaps(risks: list[Risk]) -> list[str]:
    """Identification sources with no risk at all: a sign the team only looked one way."""
    seen = {r.source for r in risks}
    return [s for s in SOURCES if s not in seen]


def gate(risks: list[Risk], appetite: int = 9, today: date | None = None) -> int:
    bad = any(validate(r, appetite, today) for r in risks) or bool(coverage_gaps(risks))
    return 1 if bad else 0


def suggest_treatment(likelihood: int, impact: int, appetite: int = 9, optional_activity: bool = False) -> str:
    """A teaching heuristic, not a rule: what a reviewer would propose first."""
    score = likelihood * impact
    if score <= appetite:
        return "accept"
    if optional_activity:
        return "avoid"
    if likelihood <= 2 and impact >= 4:
        return "transfer"  # rare but severe: insurance or contract, plus some controls
    return "mitigate"


def report(risks: list[Risk], appetite: int = 9, today: date | None = None) -> str:
    lines = [
        f"| ID | Source | Treatment | Inherent | Residual | Issues |",
        "|---|---|---|---|---|---|",
    ]
    for r in sorted(risks, key=lambda x: -x.inherent):
        issues = validate(r, appetite, today)
        lines.append(
            f"| {r.id} | {r.source} | {r.treatment} | {r.inherent} {band(r.inherent)} | "
            f"{r.residual} {band(r.residual)} | {', '.join(issues) or 'ok'} |"
        )
    gaps = coverage_gaps(risks)
    lines.append("")
    lines.append(f"Identification sources missing: {', '.join(gaps) or 'none'}")
    lines.append(f"Gate: {'FAIL' if gate(risks, appetite, today) else 'PASS'} (appetite = residual {appetite})")
    return "\n".join(lines)
