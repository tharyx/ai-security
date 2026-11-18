"""Regulatory reporting clocks for an AI incident.

    EDUCATIONAL, NOT LEGAL ADVICE. Simplified rules; each clock has conditions and
    exceptions that this code does not model. Verify against the current official texts.

One incident can start several clocks at once, with different regulators, different
triggers and different deadlines. Missing the shortest one is the classic failure.

Clocks modelled (start = when the organization became aware):
    EU AI Act Art 73   provider of a high-risk AI system, serious incident:
                       15 days; 10 days if a person died; 2 days if widespread
                       infringement or serious disruption of critical infrastructure.
                       After the Digital Omnibus (Reg. (EU) 2026/1744) the high-risk regime, and
                       so Art 73 for Annex III systems, applies from 2 Dec 2027 (Annex I products:
                       2 Aug 2028). Before that the clock is shown "for practice" only.
    GDPR Art 33        personal data breach likely to risk people's rights: supervisory
                       authority within 72 hours (Art 34: tell people without undue delay
                       if the risk is high)
    CERT-In (India)    reportable cyber incidents: within 6 hours of noticing
                       (CERT-In Directions of 28 April 2022)
    DPDP Act (India)   personal data breach: inform the Data Protection Board and each
                       affected person without delay (s.8(6)). The DPDP Rules 2025 (notified
                       Nov 2025, phased) add a detailed report to the Board within 72 hours.
                       The breach-reporting rules are expected to commence about 18 months
                       after notification (around 13 May 2027). Before that date this module
                       marks the Rules clock as "not yet commenced". Verify at the source.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta

# Approximate commencement of the DPDP Rules' breach-reporting duties (18 months after the
# Nov 2025 notification). Teaching value; check the official notification for the exact date.
DPDP_RULES_BREACH_FROM = date(2027, 5, 13)
# EU AI Act high-risk obligations (incl. Art 73) after the Digital Omnibus. Verify at the source.
AI_ACT_ANNEX_III_FROM = date(2027, 12, 2)
AI_ACT_ANNEX_I_FROM = date(2028, 8, 2)


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
        starts = AI_ACT_ANNEX_I_FROM if incident.get("annex_i_product") else AI_ACT_ANNEX_III_FROM
        note = "" if aware.date() >= starts else f"; practice only: Art 73 applies from {starts}"
        clocks.append(Clock("EU AI Act", "market surveillance authority", aware + timedelta(days=days),
                            f"Art 73: {why} -> {days} days{note}"))
    if incident.get("personal_data_breach") and incident.get("eu_personal_data"):
        if incident.get("risk_to_individuals", True):
            clocks.append(Clock("GDPR", "lead supervisory authority", aware + timedelta(hours=72),
                                "Art 33: 72 hours"))
        if incident.get("high_risk_to_individuals"):
            clocks.append(Clock("GDPR", "affected data subjects", None, "Art 34: without undue delay"))
    if incident.get("india_reportable_cyber_incident"):
        clocks.append(Clock("CERT-In", "CERT-In", aware + timedelta(hours=6), "Directions 28 Apr 2022: 6 hours"))
    if incident.get("personal_data_breach") and incident.get("india_personal_data"):
        if aware.date() >= DPDP_RULES_BREACH_FROM:
            clocks.append(Clock("DPDP Act", "Data Protection Board + affected Data Principals", None,
                                "s.8(6) + DPDP Rules 2025: intimation without delay"))
            clocks.append(Clock("DPDP Rules", "Data Protection Board (detailed report)",
                                aware + timedelta(hours=72), "DPDP Rules 2025: 72 hours (verify)"))
        else:
            clocks.append(Clock("DPDP Act", "Data Protection Board + affected Data Principals", None,
                                f"s.8(6); Rules breach duties not yet commenced (expected ~{DPDP_RULES_BREACH_FROM})"))
    return sorted(clocks, key=lambda c: c.deadline or datetime.max)
