"""Threat rating toolkit: OWASP Risk Rating, DREAD, a bug bar, and a Rapid Risk Assessment.

* OWASP Risk Rating Methodology: likelihood = mean of 8 factors (threat agent + vulnerability),
  impact = mean of 8 factors (technical + business), each 0-9; levels LOW <3, MEDIUM <6,
  HIGH >=6; severity from a 3x3 matrix.
* DREAD: five 1-10 scores averaged. Included to SHOW its weakness: two raters disagree.
* Bug bar: a fixed severity table (inspired by the Microsoft SDL bug bar, simplified for
  teaching: verify the official bars) that decides "must fix before release".
* RRA: a Mozilla-style Rapid Risk Assessment record: data dictionary, C/I/A impact per
  scenario, likelihood, recommendations; plus checks and a Markdown report.

Standard library only. All data is fictional.
"""
from __future__ import annotations

from statistics import mean

# ---------------------------------------------------------------- OWASP Risk Rating
LIKELIHOOD_FACTORS = ("skill_level", "motive", "opportunity", "size",
                      "ease_of_discovery", "ease_of_exploit", "awareness", "intrusion_detection")
IMPACT_FACTORS = ("loss_of_confidentiality", "loss_of_integrity", "loss_of_availability", "loss_of_accountability",
                  "financial_damage", "reputation_damage", "non_compliance", "privacy_violation")
MATRIX = {  # (impact, likelihood) -> severity
    ("LOW", "LOW"): "NOTE", ("LOW", "MEDIUM"): "LOW", ("LOW", "HIGH"): "MEDIUM",
    ("MEDIUM", "LOW"): "LOW", ("MEDIUM", "MEDIUM"): "MEDIUM", ("MEDIUM", "HIGH"): "HIGH",
    ("HIGH", "LOW"): "MEDIUM", ("HIGH", "MEDIUM"): "HIGH", ("HIGH", "HIGH"): "CRITICAL",
}


def level(score: float) -> str:
    if score < 3:
        return "LOW"
    if score < 6:
        return "MEDIUM"
    return "HIGH"


def owasp_risk(factors: dict[str, int], business_known: bool = True) -> dict:
    """Return likelihood, impact, their levels and the overall severity.

    If the business impact is not known (business_known=False), OWASP says to use the
    technical impact only; we do that by averaging the first four impact factors.
    """
    missing = [f for f in LIKELIHOOD_FACTORS + IMPACT_FACTORS if f not in factors]
    if missing:
        raise ValueError(f"missing factors: {missing}")
    if any(not 0 <= v <= 9 for v in factors.values()):
        raise ValueError("factors must be 0-9")
    lik = mean(factors[f] for f in LIKELIHOOD_FACTORS)
    imp_fields = IMPACT_FACTORS if business_known else IMPACT_FACTORS[:4]
    imp = mean(factors[f] for f in imp_fields)
    li, il = level(lik), level(imp)
    return {"likelihood": round(lik, 3), "impact": round(imp, 3), "likelihood_level": li,
            "impact_level": il, "severity": MATRIX[(il, li)]}


# ---------------------------------------------------------------- DREAD
def dread(scores: dict[str, int]) -> tuple[float, str]:
    keys = ("damage", "reproducibility", "exploitability", "affected_users", "discoverability")
    avg = mean(scores[k] for k in keys)
    rating = "HIGH" if avg >= 7 else "MEDIUM" if avg >= 4 else "LOW"
    return round(avg, 2), rating


def rater_spread(ratings: list[dict[str, int]]) -> float:
    """Difference between the highest and lowest DREAD average for the SAME threat."""
    avgs = [dread(r)[0] for r in ratings]
    return round(max(avgs) - min(avgs), 2)


# ---------------------------------------------------------------- Bug bar
SEVERITIES = ("Low", "Moderate", "Important", "Critical")


def bug_bar(effect: str, scope: str, sensitive_data: bool = False,
            persistent: bool = False, user_interaction: bool = False) -> str:
    """Simplified server-side bug bar. effect is a STRIDE category name; scope is
    'remote_anonymous', 'remote_authenticated' or 'local'."""
    remote = scope.startswith("remote")
    if effect == "Elevation of privilege":
        sev = "Critical" if scope == "remote_anonymous" else "Important"
    elif effect == "Information disclosure":
        sev = "Important" if (sensitive_data and remote) else "Moderate" if sensitive_data else "Low"
    elif effect in ("Spoofing", "Tampering"):
        sev = "Important" if remote else "Moderate"
    elif effect == "Denial of service":
        sev = "Important" if (persistent and scope == "remote_anonymous") else "Moderate" if remote else "Low"
    elif effect == "Repudiation":
        sev = "Moderate" if sensitive_data else "Low"
    else:
        raise ValueError(f"unknown effect {effect}")
    if user_interaction and sev != "Low":
        sev = SEVERITIES[SEVERITIES.index(sev) - 1]  # needing a victim click lowers severity one step
    return sev


def release_blocker(severity: str) -> bool:
    return severity in ("Critical", "Important")


# ---------------------------------------------------------------- Rapid Risk Assessment
IMPACT_LEVELS = ("LOW", "MEDIUM", "HIGH", "MAXIMUM")
CLASSIFICATION_FLOOR = {"PUBLIC": "LOW", "INTERNAL": "MEDIUM", "CONFIDENTIAL": "HIGH", "RESTRICTED": "MAXIMUM"}


def _max(levels) -> str:
    return max(levels, key=IMPACT_LEVELS.index)


def rra_check(rra: dict) -> list[str]:
    issues = []
    for f in ("service", "owner", "data_dictionary", "scenarios", "recommendations"):
        if not rra.get(f):
            issues.append(f"MISSING_{f.upper()}")
    classes = {d["data"]: d["classification"] for d in rra.get("data_dictionary", [])}
    for s in rra.get("scenarios", []):
        exposed = s.get("data_exposed", [])
        unknown = [d for d in exposed if d not in classes]
        if unknown:
            issues.append(f"DATA_NOT_IN_DICTIONARY in '{s['name']}': {unknown}")
        known = [CLASSIFICATION_FLOOR[classes[d]] for d in exposed if d in classes]
        if known:
            floor = _max(known)
            if IMPACT_LEVELS.index(s["confidentiality"]) < IMPACT_LEVELS.index(floor):
                issues.append(f"UNDERRATED_CONFIDENTIALITY in '{s['name']}' (exposed data needs at least {floor})")
    return issues


def rra_overall(rra: dict) -> dict[str, str]:
    out = {}
    for prop in ("confidentiality", "integrity", "availability"):
        out[prop] = _max(s[prop] for s in rra["scenarios"])
    return out


def rra_report(rra: dict) -> str:
    lines = [f"# RRA: {rra['service']}", f"Owner: {rra.get('owner', '?')}", "",
             "## Data dictionary", "| Data | Classification |", "|---|---|"]
    lines += [f"| {d['data']} | {d['classification']} |" for d in rra["data_dictionary"]]
    lines += ["", "## Threat scenarios", "| Scenario | C | I | A | Likelihood |", "|---|---|---|---|---|"]
    lines += [f"| {s['name']} | {s['confidentiality']} | {s['integrity']} | {s['availability']} | {s['likelihood']} |"
              for s in rra["scenarios"]]
    ov = rra_overall(rra)
    lines += ["", f"Overall impact: C={ov['confidentiality']} I={ov['integrity']} A={ov['availability']}",
              "", "## Recommendations"]
    lines += [f"- {r}" for r in rra["recommendations"]]
    issues = rra_check(rra)
    lines += ["", "## Review issues", *([f"- {i}" for i in issues] or ["- none"])]
    return "\n".join(lines)
