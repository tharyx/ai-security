"""Regulatory reporting clocks for an AI incident.

    EDUCATIONAL, NOT LEGAL ADVICE. Simplified rules; each clock has conditions and
    exceptions that this code does not model. Verify against the current official texts.

One incident can start several clocks at once, with different regulators, different
triggers and different deadlines. Missing the shortest one is the classic failure.

Clocks modelled (start = when the organization became aware):
    EU AI Act Art 73   provider of a high-risk AI system, serious incident:
                       15 days; 10 days if a person died; 2 days if widespread
                       infringement or serious disruption of critical infrastructure
    GDPR Art 33        personal data breach likely to risk people's rights: supervisory
                       authority within 72 hours (Art 34: tell people without undue delay
                       if the risk is high)
    CERT-In (India)    reportable cyber incidents: within 6 hours of noticing
                       (CERT-In Directions of 28 April 2022)
    DPDP Act (India)   personal data breach: inform the Data Protection Board and each
                       affected person. The DPDP Rules 2025 set the format and timing;
                       check whether these duties have commenced for you and the current text.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass
class Clock:
    regime: str
    notify: str
    deadline: datetime | None  # None = "without delay"; no fixed number modelled
    basis: str

    def remaining(self, now: datetime) -> timedelta | None:
        return None if self.deadline is None else self.deadline - now


def reporting_clocks(incident: dict) -> list[Clock]:
    aware: datetime = incident["aware_at"]
    clocks: list[Clock] = []
    if incident.get("eu_high_risk_provider") and incident.get("eu_serious_incident"):
        if incident.get("widespread_or_critical_infrastructure"):
            days, why = 2, "widespread infringement or critical infrastructure disruption"
        elif incident.get("death"):
            days, why = 10, "death of a person"
        else:
            days, why = 15, "serious incident"
        clocks.append(Clock("EU AI Act", "market surveillance authority", aware + timedelta(days=days),
                            f"Art 73: {why} -> {days} days"))
    if incident.get("personal_data_breach") and incident.get("eu_personal_data"):
        if incident.get("risk_to_individuals", True):
            clocks.append(Clock("GDPR", "lead supervisory authority", aware + timedelta(hours=72),
                                "Art 33: 72 hours"))
        if incident.get("high_risk_to_individuals"):
            clocks.append(Clock("GDPR", "affected data subjects", None, "Art 34: without undue delay"))
    if incident.get("india_reportable_cyber_incident"):
        clocks.append(Clock("CERT-In", "CERT-In", aware + timedelta(hours=6), "Directions 28 Apr 2022: 6 hours"))
    if incident.get("personal_data_breach") and incident.get("india_personal_data"):
        clocks.append(Clock("DPDP Act", "Data Protection Board + affected Data Principals", None,
                            "s.8(6) + DPDP Rules 2025: check commencement and current timelines"))
    return sorted(clocks, key=lambda c: c.deadline or datetime.max)
