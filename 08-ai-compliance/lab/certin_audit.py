"""CERT-In AI Security Auditing Guidelines v1.0 (India, Nov 2026): tiering, scoping and findings.

    EDUCATIONAL. This module models the *structure* of the guideline in our own words:
    eight inherent-risk factors -> composite score -> tier -> minimum audit depth and domains;
    the six-phase audit; finding severity -> remediation timeline; re-audit triggers.
    Read the official document for the exact requirements and the latest version.

What it encodes from the guideline
    * Eight factors (F1-F8), each scored 1 (low) to 4 (critical), scored *before* taking credit
      for controls. Missing evidence must not justify a low score -> a missing factor fails closed.
    * Composite 8-12 Tier 1 (Low), 13-19 Tier 2 (Moderate), 20-26 Tier 3 (High), 27-32 Tier 4 (Critical).
    * Escalation triggers (autonomous consequential actions, privileged access, cannot be
      safely stopped...) must be considered and documented. LAB RULE (ours, not CERT-In's):
      any trigger lifts the tier to at least Tier 3.
    * For scoping, if the auditor's tier and the organization's self-assessed tier differ,
      the higher one applies.
    * Minimum audit domains: Tier 1 -> 8.1 governance and 8.6 security; Tier 2 and above -> all nine
      core domains, plus the advanced-AI sections (9-11) where they apply.
    * Finding severity: Critical / High -> immediate escalation and an expedited corrective
      action plan; Moderate -> plan within 30 business days, fix within 60 days;
      Low / Observation -> within 3 months or continuous improvement.
    * Re-audit within 3 months after an "Unsatisfactory" opinion or two or more Critical findings.
    * A corrective action plan (CAP) names one person as owner, not a team.

    python 08-ai-compliance/lab/certin_audit.py 08-ai-compliance/lab/fixtures/certin_audit.yaml
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path

import yaml

FACTORS = {
    "F1": "impact severity",
    "F2": "autonomy and actionability",
    "F3": "data sensitivity",
    "F4": "scale and exposure",
    "F5": "reversibility and recoverability",
    "F6": "operational / sector criticality",
    "F7": "adversarial exposure",
    "F8": "complexity and auditability",
}
ESCALATION_TRIGGERS = {
    "autonomous_consequential_actions": "autonomously performs safety-critical or consequential actions",
    "controls_critical_infrastructure": "controls or materially affects critical infrastructure",
    "irreversible_harm": "can cause irreversible physical, operational or systemic harm",
    "privileged_access": "has privileged access to production, sensitive data or critical processes",
    "executes_code_transactions_or_messages": "can autonomously execute code, transactions or external messages",
    "high_threat_environment": "operates in a high-threat or contested environment",
    "cannot_be_safely_stopped": "cannot be reliably interrupted, rolled back or put in a safe state",
}
TIER_NAMES = {1: "Tier 1 (Low)", 2: "Tier 2 (Moderate)", 3: "Tier 3 (High)", 4: "Tier 4 (Critical)"}
MIN_AUDIT = {
    1: "self-assessment or basic internal review with documented evidence",
    2: "documented internal audit; independent audit by a CERT-In empanelled auditor at least yearly",
    3: "periodic independent third-party audit by a CERT-In empanelled auditor; more often after changes",
    4: "independent audit by a CERT-In empanelled auditor with continuous monitoring",
}
CORE_DOMAINS = {
    "8.1": "governance and accountability",
    "8.2": "data lifecycle, quality and privacy",
    "8.3": "model risk management",
    "8.4": "ethics, bias and fairness",
    "8.5": "explainability and transparency",
    "8.6": "security, adversarial resilience and incident reporting",
    "8.7": "monitoring, drift and validation",
    "8.8": "human oversight and decision accountability",
    "8.9": "third-party and AI supply-chain assurance",
}
AUDIT_PHASES = ["1 engagement initiation", "2 risk assessment and scoping", "3 audit planning",
                "4 fieldwork and evidence collection", "5 analysis and finding development",
                "6 reporting and follow-up"]
SEVERITIES = ["Critical", "High", "Moderate", "Low"]
TEAM_WORDS = {"team", "department", "dept", "group", "function", "office"}


@dataclass
class TierResult:
    system: str
    composite: int
    score_tier: int
    tier: int
    reasons: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return TIER_NAMES[self.tier]

    @property
    def minimum_audit(self) -> str:
        return MIN_AUDIT[self.tier]

    @property
    def mandatory_domains(self) -> list[str]:
        return ["8.1", "8.6"] if self.tier == 1 else list(CORE_DOMAINS)


def tier_from_composite(composite: int) -> int:
    if not 8 <= composite <= 32:
        raise ValueError(f"composite {composite} outside 8..32")
    return 1 if composite <= 12 else 2 if composite <= 19 else 3 if composite <= 26 else 4


def assess_tier(system: str, scores: dict, triggers: list[str] | None = None,
                self_assessed_tier: int | None = None) -> TierResult:
    missing = [f for f in FACTORS if f not in scores]
    if missing:
        raise ValueError(f"{system}: factors not scored {missing}; missing evidence cannot mean 'low'")
    bad = {f: v for f, v in scores.items() if f in FACTORS and v not in (1, 2, 3, 4)}
    if bad:
        raise ValueError(f"{system}: scores must be 1..4, got {bad}")
    composite = sum(scores[f] for f in FACTORS)
    t = TierResult(system, composite, tier_from_composite(composite), tier_from_composite(composite))
    t.reasons.append(f"composite {composite} -> {TIER_NAMES[t.score_tier]}")
    for trig in triggers or []:
        if trig not in ESCALATION_TRIGGERS:
            raise ValueError(f"unknown escalation trigger '{trig}'")
        t.reasons.append(f"escalation trigger: {ESCALATION_TRIGGERS[trig]}")
    if triggers and t.tier < 3:
        t.tier = 3
        t.reasons.append("lab rule: an escalation trigger lifts the tier to at least Tier 3 (document why)")
    if self_assessed_tier and self_assessed_tier != t.tier:
        t.reasons.append(f"organization said {TIER_NAMES[self_assessed_tier]}; the higher tier applies for scoping")
        t.tier = max(t.tier, self_assessed_tier)
    return t


def domain_evidence_status(controls: list[dict], control_status: dict[str, str]) -> dict[str, str]:
    """Join the CERT-In domain mapping in controls.yaml with the evidence checker's control status.

    OK         at least one mapped control has good evidence
    GAP        mapped controls exist, but none has good evidence
    NO_CONTROL no control in our set maps to this domain (a design gap, not an evidence gap)
    """
    out = {}
    for dom in CORE_DOMAINS:
        ctls = [c["id"] for c in controls
                if any(ref.startswith(dom + " ") for ref in c.get("maps_to", {}).get("cert_in_ai", []))]
        if not ctls:
            out[dom] = "NO_CONTROL"
        else:
            out[dom] = "OK" if any(control_status.get(c) == "OK" for c in ctls) else "GAP"
    return out


def audit_readiness(t: TierResult, domain_status: dict[str, str]) -> list[str]:
    """Mandatory domains for this tier that would not survive fieldwork today."""
    return [f"{d} {CORE_DOMAINS[d]}: {domain_status.get(d, 'NO_CONTROL')}"
            for d in t.mandatory_domains if domain_status.get(d) != "OK"]


def add_business_days(start: date, n: int) -> date:
    d = start
    while n > 0:
        d += timedelta(days=1)
        if d.weekday() < 5:
            n -= 1
    return d


def add_months(start: date, months: int) -> date:
    y, m = divmod(start.month - 1 + months, 12)
    year, month = start.year + y, m + 1
    for day in (start.day, 30, 29, 28):
        try:
            return date(year, month, day)
        except ValueError:
            continue
    raise ValueError("bad date")


def remediation_plan(severity: str, reported: date) -> dict:
    """Deadlines that follow from the finding severity (simplified from the guideline's table)."""
    if severity in {"Critical", "High"}:
        return {"escalate": "immediately to senior management" if severity == "Critical"
                else "through the governance and risk-escalation process",
                "cap_due": None, "fix_due": None,
                "note": "contain or restrict by risk; expedited CAP; report externally only if a separate "
                        "rule (for example CERT-In 6-hour incident reporting) is triggered"}
    if severity == "Moderate":
        return {"escalate": "aggregate reporting to the AI governance committee",
                "cap_due": add_business_days(reported, 30), "fix_due": reported + timedelta(days=60), "note": ""}
    if severity == "Low":
        return {"escalate": "none (trend analysis)", "cap_due": None, "fix_due": add_months(reported, 3), "note": ""}
    raise ValueError(f"unknown severity '{severity}'")


def check_finding(f: dict) -> list[str]:
    """A finding is usable only if it has condition, criteria, cause, effect, and a named person as owner."""
    problems = [f"missing '{k}'" for k in ("condition", "criteria", "cause", "effect", "recommendation")
                if not str(f.get(k, "")).strip()]
    if f.get("severity") not in SEVERITIES:
        problems.append(f"severity '{f.get('severity')}' is not one of {SEVERITIES}")
    owner = str(f.get("owner", "")).strip()
    if not owner or any(w in owner.lower().split() for w in TEAM_WORDS):
        problems.append(f"owner '{owner}' must be a named person, not a team")
    return problems


def re_audit_required(opinion: str, findings: list[dict]) -> bool:
    critical = sum(1 for f in findings if f.get("severity") == "Critical")
    return opinion == "Unsatisfactory" or critical >= 2


def main() -> None:
    p = argparse.ArgumentParser(description="CERT-In style AI risk tiering and audit findings (educational).")
    p.add_argument("data", help="YAML with 'systems' and 'findings'")
    args = p.parse_args()
    data = yaml.safe_load(Path(args.data).read_text(encoding="utf-8"))
    for s in data.get("systems", []):
        t = assess_tier(s["system"], s["scores"], s.get("triggers"), s.get("self_assessed_tier"))
        print(f"{t.system:28} composite {t.composite:>2}  {t.name:18} audit: {t.minimum_audit}")
        for r in t.reasons[1:]:
            print(f"{'':30}{r}")
    for f in data.get("findings", []):
        probs = check_finding(f)
        print(f"{f.get('id', '?'):16} {f.get('severity', '?'):9} {'OK' if not probs else '; '.join(probs)}")


if __name__ == "__main__":
    main()
