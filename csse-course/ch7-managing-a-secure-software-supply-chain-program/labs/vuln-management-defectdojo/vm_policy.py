"""Vulnerability-management rules on top of findings: SLA, risk acceptance, false positives, metrics.

Mirrors the ideas of DefectDojo's SLA configuration, risk acceptances and metrics views.
SLA days below (7/30/90/120) are example defaults, not a standard; set your own and verify
what your DefectDojo version ships. For CVSS/EPSS/KEV prioritisation see
cybersecurity-track/08-vulnerability-management. Time is injected, so tests are exact.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, timedelta

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
DEFAULT_SLA = {"Critical": 7, "High": 30, "Medium": 90, "Low": 120}
KEV_SLA_DAYS = 3  # example policy: known-exploited vulnerabilities get a much tighter limit


@dataclass
class Finding:
    id: int
    title: str
    severity: str
    found: date
    component: str = ""
    kev: bool = False
    epss: float = 0.0
    status: str = "active"          # active | mitigated | false_positive | risk_accepted
    mitigated: date | None = None
    note: str = ""


@dataclass
class RiskAcceptance:
    finding_id: int
    owner: str
    approver: str
    justification: str
    accepted_on: date
    expires: date


class PolicyError(Exception):
    pass


@dataclass
class Policy:
    sla_days: dict = field(default_factory=lambda: dict(DEFAULT_SLA))
    max_acceptance_days: int = 180
    kev_days: int = KEV_SLA_DAYS

    def sla_for(self, f: Finding) -> int | None:
        days = self.sla_days.get(f.severity)
        if days is None:
            return None
        return min(days, self.kev_days) if f.kev else days

    def due_date(self, f: Finding) -> date | None:
        days = self.sla_for(f)
        return f.found + timedelta(days=days) if days is not None else None


class Tracker:
    def __init__(self, findings: list[Finding], policy: Policy | None = None):
        self.findings = {f.id: f for f in findings}
        self.policy = policy or Policy()
        self.acceptances: dict[int, RiskAcceptance] = {}
        self.audit: list[str] = []

    # -- SLA
    def sla_status(self, f: Finding, today: date) -> str:
        if f.status != "active":
            return "n/a"
        due = self.policy.due_date(f)
        if due is None:
            return "no-sla"
        return "breached" if today > due else "within-sla"

    def overdue(self, today: date) -> list[Finding]:
        return sorted((f for f in self.findings.values() if self.sla_status(f, today) == "breached"),
                      key=lambda f: self.policy.due_date(f))

    # -- risk acceptance
    def accept_risk(self, finding_id: int, *, owner: str, approver: str, justification: str,
                    today: date, days: int) -> RiskAcceptance:
        f = self.findings[finding_id]
        if not justification.strip():
            raise PolicyError("justification is required")
        if approver == owner:
            raise PolicyError("approver must be different from the owner")
        if days <= 0 or days > self.policy.max_acceptance_days:
            raise PolicyError(f"acceptance must be 1-{self.policy.max_acceptance_days} days (it must expire)")
        if f.kev:
            raise PolicyError("known-exploited findings cannot be risk-accepted without an exception board")
        ra = RiskAcceptance(finding_id, owner, approver, justification, today, today + timedelta(days=days))
        f.status = "risk_accepted"
        self.acceptances[finding_id] = ra
        self.audit.append(f"{today} accept {finding_id} by {owner}/{approver} until {ra.expires}")
        return ra

    def sweep_expired(self, today: date) -> list[int]:
        """Reactivate findings whose acceptance has expired. Their SLA clock is NOT reset."""
        reopened = []
        for fid, ra in list(self.acceptances.items()):
            if today > ra.expires:
                self.findings[fid].status = "active"
                del self.acceptances[fid]
                reopened.append(fid)
                self.audit.append(f"{today} acceptance for {fid} expired: reactivated")
        return reopened

    # -- false positive
    def mark_false_positive(self, finding_id: int, *, reporter: str, reviewer: str, reason: str,
                            today: date) -> None:
        if not reason.strip():
            raise PolicyError("a reason is required")
        if reviewer == reporter:
            raise PolicyError("reviewer must be a different person")
        f = self.findings[finding_id]
        f.status, f.note = "false_positive", reason
        self.audit.append(f"{today} false-positive {finding_id} by {reporter}/{reviewer}")

    def mitigate(self, finding_id: int, today: date) -> None:
        f = self.findings[finding_id]
        f.status, f.mitigated = "mitigated", today
        self.audit.append(f"{today} mitigated {finding_id}")

    # -- metrics
    def open_by_severity(self) -> dict[str, int]:
        out = {s: 0 for s in SEVERITIES}
        for f in self.findings.values():
            if f.status == "active":
                out[f.severity] += 1
        return out

    def mttr_days(self) -> dict[str, float | None]:
        out: dict[str, float | None] = {}
        for s in SEVERITIES:
            done = [(f.mitigated - f.found).days for f in self.findings.values()
                    if f.severity == s and f.status == "mitigated" and f.mitigated]
            out[s] = round(sum(done) / len(done), 1) if done else None
        return out

    def sla_compliance(self) -> float | None:
        """Share of mitigated findings closed within their SLA."""
        closed = [f for f in self.findings.values() if f.status == "mitigated" and f.mitigated]
        scored = [f for f in closed if self.policy.due_date(f)]
        if not scored:
            return None
        ok = sum(1 for f in scored if f.mitigated <= self.policy.due_date(f))
        return round(100 * ok / len(scored), 1)

    def summary(self, today: date) -> dict:
        return {"open_by_severity": self.open_by_severity(), "mttr_days": self.mttr_days(),
                "sla_compliance_pct": self.sla_compliance(),
                "overdue": [f.id for f in self.overdue(today)],
                "risk_accepted": sorted(self.acceptances)}
