"""Risk register scorer: likelihood x impact, residual risk after controls, owners, overdue reviews.

Scales are 1-5. Score = likelihood x impact (1-25).
Bands: 1-4 Low, 5-9 Medium, 10-16 High, 17-25 Critical.
Data can come from YAML or CSV. All sample data is synthetic.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from datetime import date, timedelta

import yaml

VALID_TREATMENTS = {"mitigate", "accept", "transfer", "avoid"}


def band(score: int) -> str:
    if score >= 17:
        return "Critical"
    if score >= 10:
        return "High"
    if score >= 5:
        return "Medium"
    return "Low"


@dataclass
class Risk:
    id: str
    asset: str
    threat: str
    vulnerability: str
    likelihood: int
    impact: int
    owner: str = ""
    treatment: str = "mitigate"
    likelihood_reduction: int = 0   # total effect of implemented controls
    impact_reduction: int = 0
    last_review: date | None = None
    review_days: int = 90
    controls: list[str] = field(default_factory=list)

    @property
    def inherent(self) -> int:
        return self.likelihood * self.impact

    @property
    def residual_likelihood(self) -> int:
        return max(1, self.likelihood - self.likelihood_reduction)

    @property
    def residual_impact(self) -> int:
        return max(1, self.impact - self.impact_reduction)

    @property
    def residual(self) -> int:
        return self.residual_likelihood * self.residual_impact

    def next_review(self) -> date | None:
        return self.last_review + timedelta(days=self.review_days) if self.last_review else None

    def is_overdue(self, as_of: date) -> bool:
        nxt = self.next_review()
        return nxt is None or nxt < as_of      # never reviewed counts as overdue


def _to_date(value) -> date | None:
    if value in (None, ""):
        return None
    return value if isinstance(value, date) else date.fromisoformat(str(value))


def _risk_from_dict(d: dict) -> Risk:
    controls = d.get("controls") or []
    if isinstance(controls, str):
        controls = [c for c in controls.split(";") if c]
    # YAML controls may be dicts with reductions; CSV uses explicit reduction columns.
    l_red = int(d.get("likelihood_reduction") or 0)
    i_red = int(d.get("impact_reduction") or 0)
    names = []
    for c in controls:
        if isinstance(c, dict):
            names.append(c["name"])
            l_red += int(c.get("likelihood_reduction", 0))
            i_red += int(c.get("impact_reduction", 0))
        else:
            names.append(str(c))
    return Risk(
        id=str(d["id"]), asset=d["asset"], threat=d["threat"], vulnerability=d["vulnerability"],
        likelihood=int(d["likelihood"]), impact=int(d["impact"]),
        owner=(d.get("owner") or "").strip(), treatment=(d.get("treatment") or "mitigate").strip(),
        likelihood_reduction=l_red, impact_reduction=i_red,
        last_review=_to_date(d.get("last_review")), review_days=int(d.get("review_days") or 90),
        controls=names,
    )


def load_yaml(text: str) -> list[Risk]:
    return [_risk_from_dict(r) for r in yaml.safe_load(text)["risks"]]


def load_csv(text: str) -> list[Risk]:
    return [_risk_from_dict(row) for row in csv.DictReader(io.StringIO(text))]


def validate(r: Risk) -> list[str]:
    problems = []
    if not (1 <= r.likelihood <= 5 and 1 <= r.impact <= 5):
        problems.append("likelihood and impact must be 1-5")
    if r.treatment not in VALID_TREATMENTS:
        problems.append(f"unknown treatment '{r.treatment}'")
    return problems


def assess(risks: list[Risk], as_of: date, appetite: int = 9) -> list[dict]:
    """Score every risk. `appetite` is the highest residual score leadership will accept.

    Issues reported:
      no_owner            - nobody is accountable
      overdue_review      - review date has passed (or never reviewed)
      above_appetite      - residual score is higher than appetite
      accepted_above_appetite - treatment is 'accept' but residual exceeds appetite
      controls_ineffective    - controls listed but residual equals inherent
      invalid             - bad scale values or treatment
    """
    rows = []
    for r in risks:
        issues = [f"invalid: {p}" for p in validate(r)]
        if not r.owner:
            issues.append("no_owner")
        if r.is_overdue(as_of):
            issues.append("overdue_review")
        if r.residual > appetite:
            issues.append("above_appetite")
            if r.treatment == "accept":
                issues.append("accepted_above_appetite")
        if r.controls and r.residual == r.inherent:
            issues.append("controls_ineffective")
        rows.append({
            "id": r.id, "asset": r.asset, "inherent": r.inherent, "inherent_band": band(r.inherent),
            "residual": r.residual, "residual_band": band(r.residual),
            "owner": r.owner or "-", "treatment": r.treatment,
            "next_review": str(r.next_review() or "never"), "issues": issues,
        })
    return sorted(rows, key=lambda x: (-x["residual"], x["id"]))


def format_table(rows: list[dict]) -> str:
    head = f"{'ID':6} {'Asset':20} {'Inh':>4} {'Res':>4} {'Residual band':14} {'Owner':8} Issues"
    lines = [head, "-" * len(head)]
    for r in rows:
        lines.append(f"{r['id']:6} {r['asset'][:20]:20} {r['inherent']:>4} {r['residual']:>4} "
                     f"{r['residual_band']:14} {r['owner'][:8]:8} {', '.join(r['issues']) or 'ok'}")
    return "\n".join(lines)
