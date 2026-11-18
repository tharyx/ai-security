"""A governed AI system register: schema, automatic risk tiering, checks and a release gate.

Teams describe their AI systems in YAML (see fixtures/). This module turns those facts
into a risk tier, a list of required controls, governance findings and a release decision.

Each layer can be switched off so you can prove which layer caught which problem:

    L1  validate    Strict schema (pydantic, extra="forbid"). A typo such as
                    "human_oversite" fails loudly instead of being silently dropped.
    L2  auto_tier   The tier is computed from facts by written rules. The team's
                    declared tier is only compared, never trusted.
    L3  checks      Governance checks: unowned system, no intended use, high risk with
                    no human oversight, missing controls, overdue review, expired
                    exception, no linked risk entry, prohibited use.
    L4  gate        Release gate: a system may run in production only when it has no
                    blocking findings. Deployment pipelines call can_deploy().

The important idea: the tier comes from facts the team cannot easily game, and the gate
is code in the deployment path, not a meeting that people can skip.

Also here: shadow AI discovery (compare egress logs with the register).

Educational lab. The tiering rules are an example *organizational* policy, inspired by
(but not the same as) the EU AI Act categories that Module 08 covers.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

TIER_ORDER = ["low", "medium", "high", "critical", "prohibited"]
Tier = Literal["low", "medium", "high", "critical", "prohibited"]
Oversight = Literal["none", "sample_review", "approve_each", "human_decides"]
DecisionImpact = Literal["none", "informs_human", "automated_decision"]
DataClass = Literal["public", "internal", "confidential", "personal", "sensitive_personal"]
Status = Literal["proposed", "pilot", "production", "retired"]

# Organizational policy: uses the company will not build or buy at all.
PROHIBITED_USES = {
    "social_scoring",
    "workplace_emotion_recognition",
    "manipulation_of_vulnerable_groups",
    "untargeted_face_scraping",
}
# Domains where AI output can change someone's life, money, job or rights.
HIGH_IMPACT_DOMAINS = {
    "employment", "credit", "insurance", "education", "healthcare", "essential_services",
    "law_enforcement", "biometric_identification", "critical_infrastructure", "migration",
    "justice",
}
PERSONAL = {"personal", "sensitive_personal"}
PLACEHOLDER_TEXT = {"", "tbd", "todo", "n/a", "na", "various", "general use", "see wiki"}

CONTROL_CATALOG = {
    "CTL-REG": "Registered with owners and an intended-use statement",
    "CTL-AUP": "Users trained on the AI acceptable-use policy",
    "CTL-TM": "Threat model reviewed",
    "CTL-EVAL": "Pre-release evaluation (quality and security tests)",
    "CTL-LOG": "Prompt and tool-call logging with redaction",
    "CTL-PRIV": "Privacy review / DPIA screening",
    "CTL-VEND": "Vendor and model-provider assessment",
    "CTL-HO": "Human oversight design (who reviews, when, can they override)",
    "CTL-RT": "Red-team exercise before release",
    "CTL-MON": "Production monitoring and alerting",
    "CTL-IR": "AI incident runbook, tested",
    "CTL-IA": "AI impact assessment (affected people, fairness)",
    "CTL-BOARD": "AI governance board approval",
    "CTL-APPEAL": "A route for affected people to contest outcomes",
}
TIER_CONTROLS: dict[str, list[str]] = {
    "low": ["CTL-REG", "CTL-AUP"],
    "medium": ["CTL-TM", "CTL-EVAL", "CTL-LOG"],
    "high": ["CTL-HO", "CTL-RT", "CTL-MON", "CTL-IR"],
    "critical": ["CTL-IA", "CTL-BOARD", "CTL-APPEAL"],
}
REVIEW_INTERVAL_DAYS = {"low": 365, "medium": 365, "high": 180, "critical": 90}

# Shadow AI discovery: domains of AI services the proxy can see (all *.example, synthetic).
KNOWN_AI_DOMAINS = {
    "api.llm-vendor-a.example": "LLM Vendor A API",
    "api.genai-vendor-b.example": "GenAI Vendor B API",
    "chat.free-ai-tool.example": "Free consumer chatbot",
    "transcribe.ai-notes.example": "AI meeting-notes service",
}


# --------------------------------------------------------------------------- L1 schema
class AITool(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    side_effects: bool = False


class PolicyException(BaseModel):
    """A time-limited, approved deviation from policy. Key is e.g. 'GOV-05:CTL-RT'."""

    model_config = ConfigDict(extra="forbid")
    finding: str
    reason: str
    approved_by: str
    expires: date


class AISystem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^AI-\d{3}$")
    name: str
    business_owner: str | None = None
    technical_owner: str | None = None
    intended_use: str | None = None
    prohibited_uses: list[str] = []
    status: Status
    declared_tier: Tier | None = None
    provider: str  # "internal" or the vendor's name
    model: str
    data_classes: list[DataClass] = []
    affected_people: list[str] = []
    use_domains: list[str] = []
    decision_impact: DecisionImpact = "none"
    external_facing: bool = False
    tools: list[AITool] = []
    human_oversight: Oversight = "none"
    controls: list[str] = []
    last_review: date | None = None
    egress_domains: list[str] = []
    exceptions: list[PolicyException] = []


class LenientAISystem(AISystem):
    """What you get with validate=False: unknown fields are silently dropped."""

    model_config = ConfigDict(extra="ignore")


# --------------------------------------------------------------------------- results
@dataclass
class Finding:
    code: str
    severity: Literal["critical", "high", "medium", "low"]
    message: str
    blocking: bool
    waivable: bool = True
    key: str = ""  # what an exception must name to waive it, e.g. "GOV-05:CTL-RT"

    def __post_init__(self) -> None:
        self.key = self.key or self.code


@dataclass
class Assessment:
    system_id: str
    name: str
    status: str
    declared_tier: str | None
    tier: str
    reasons: list[str] = field(default_factory=list)
    required_controls: list[str] = field(default_factory=list)
    missing_controls: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    waived: list[Finding] = field(default_factory=list)
    decision: str = "APPROVED"

    @property
    def codes(self) -> set[str]:
        return {f.code for f in self.findings}

    @property
    def blocking(self) -> list[Finding]:
        return [f for f in self.findings if f.blocking]


# --------------------------------------------------------------------------- L2 tiering
def _at_least(a: str, b: str) -> bool:
    return TIER_ORDER.index(a) >= TIER_ORDER.index(b)


def compute_tier(s: AISystem) -> tuple[str, list[str]]:
    """Apply the tiering rules. The highest matching rule wins; every match is explained."""
    hits: list[tuple[str, str]] = []
    domains, data = set(s.use_domains), set(s.data_classes)
    if domains & PROHIBITED_USES:
        hits.append(("prohibited", f"prohibited use: {', '.join(sorted(domains & PROHIBITED_USES))}"))
    high_impact = sorted(domains & HIGH_IMPACT_DOMAINS)
    if high_impact and s.decision_impact == "automated_decision":
        hits.append(("critical", f"automated decision in high-impact domain ({', '.join(high_impact)})"))
    elif high_impact:
        hits.append(("high", f"high-impact domain ({', '.join(high_impact)})"))
    if any(t.side_effects for t in s.tools) and data & (PERSONAL | {"confidential"}):
        hits.append(("high", "tools with side effects can act on sensitive data"))
    if "sensitive_personal" in data:
        hits.append(("high", "processes sensitive personal data"))
    if s.external_facing:
        hits.append(("medium", "external-facing"))
    if data & PERSONAL:
        hits.append(("medium", "processes personal data"))
    if "confidential" in data and s.provider != "internal":
        hits.append(("medium", "confidential data sent to an external provider"))
    if not hits:
        return "low", ["low: internal use, no personal data, no actions"]
    tier = max((t for t, _ in hits), key=TIER_ORDER.index)
    return tier, [f"{t}: {why}" for t, why in hits]


def required_controls(s: AISystem, tier: str) -> list[str]:
    if tier == "prohibited":
        return []
    req: list[str] = []
    for t in ["low", "medium", "high", "critical"]:
        if _at_least(tier, t):
            req += TIER_CONTROLS[t]
    if set(s.data_classes) & PERSONAL:
        req.append("CTL-PRIV")
    if s.provider != "internal" and _at_least(tier, "medium"):
        req.append("CTL-VEND")
    return req


# --------------------------------------------------------------------------- the register
class GovernedRegister:
    def __init__(
        self,
        *,
        as_of: date,
        validate: bool = True,
        auto_tier: bool = True,
        checks: bool = True,
        gate: bool = True,
    ) -> None:
        self.as_of = as_of
        self.validate = validate
        self.auto_tier = auto_tier
        self.checks = checks
        self.gate = gate
        self.assessments: dict[str, Assessment] = {}

    # -- public API ----------------------------------------------------------
    def load(self, raw_systems: list[dict], risks: list[dict] | None = None) -> list[Assessment]:
        risk_systems = {r.get("system_id") for r in (risks or []) if (r.get("owner") or "").strip()}
        results = [self.assess(raw, risk_systems if risks is not None else None) for raw in raw_systems]
        self.assessments = {a.system_id: a for a in results}
        return results

    def can_deploy(self, system_id: str) -> bool:
        """What a CI/CD pipeline asks before deploying. Unknown systems are denied."""
        a = self.assessments.get(system_id)
        if a is None:
            return False
        return a.decision.startswith("APPROVED")

    # -- one system ----------------------------------------------------------
    def assess(self, raw: dict, risk_systems: set | None = None) -> Assessment:
        model = AISystem if self.validate else LenientAISystem
        try:
            s = model.model_validate(raw)
        except ValidationError as exc:  # fail closed: an unreadable record is not approved
            err = exc.errors()[0]
            where = ".".join(str(p) for p in err["loc"])
            a = Assessment(str(raw.get("id", "?")), str(raw.get("name", "?")), str(raw.get("status", "?")),
                           raw.get("declared_tier"), "unknown")
            a.findings.append(Finding("GOV-00", "critical", f"record rejected by schema: {where}: {err['msg']}",
                                      blocking=True, waivable=False))
            a.decision = "BLOCKED" if self.gate else "APPROVED (gate off)"
            return a

        if self.auto_tier:
            tier, reasons = compute_tier(s)
        else:  # trust the team's own answer
            tier, reasons = (s.declared_tier or "low"), ["declared by the team (not verified)"]
        req = required_controls(s, tier)
        a = Assessment(s.id, s.name, s.status, s.declared_tier, tier, reasons, req,
                       [c for c in req if c not in s.controls])

        if s.status == "retired":
            a.decision = "RETIRED"
            return a
        if self.checks:
            self._run_checks(s, a, risk_systems)
            self._apply_exceptions(s, a)
        if not self.gate:
            a.decision = "APPROVED (gate off)"
        elif a.blocking:
            a.decision = "BLOCKED"
        return a

    # -- L3 checks -----------------------------------------------------------
    def _run_checks(self, s: AISystem, a: Assessment, risk_systems: set | None) -> None:
        add = a.findings.append
        if a.tier == "prohibited":
            add(Finding("GOV-07", "critical", "prohibited use under AI policy", blocking=True, waivable=False))
        missing_owner = [r for r in ("business_owner", "technical_owner") if not (getattr(s, r) or "").strip()]
        if missing_owner:
            add(Finding("GOV-01", "high", f"unowned: no {' or '.join(missing_owner)}", blocking=True, waivable=False))
        if (s.intended_use or "").strip().lower() in PLACEHOLDER_TEXT or len((s.intended_use or "").strip()) < 20:
            add(Finding("GOV-02", "high", "no real intended-use statement", blocking=True, waivable=False))
        if _at_least(a.tier, "high") and a.tier != "prohibited":
            weak = {"none"} if a.tier == "high" else {"none", "sample_review"}
            if s.human_oversight in weak:
                add(Finding("GOV-03", "critical",
                            f"{a.tier} risk with human oversight '{s.human_oversight}'",
                            blocking=True, waivable=False))
        if self.auto_tier and (s.declared_tier is None or TIER_ORDER.index(s.declared_tier) < TIER_ORDER.index(a.tier)):
            add(Finding("GOV-04", "medium",
                        f"declared tier '{s.declared_tier}' is below computed tier '{a.tier}'", blocking=False))
        for c in a.missing_controls:
            add(Finding("GOV-05", "high", f"missing required control {c}: {CONTROL_CATALOG.get(c, c)}",
                        blocking=True, key=f"GOV-05:{c}"))
        interval = REVIEW_INTERVAL_DAYS.get(a.tier)
        if interval and (s.last_review is None or (self.as_of - s.last_review).days > interval):
            last = s.last_review.isoformat() if s.last_review else "never"
            add(Finding("GOV-06", "medium", f"review overdue (last: {last}, interval: {interval} days)",
                        blocking=False))
        if risk_systems is not None and _at_least(a.tier, "high") and a.tier != "prohibited" \
                and s.id not in risk_systems:
            add(Finding("GOV-08", "high", "high/critical system has no owned entry in the risk register",
                        blocking=True))

    def _apply_exceptions(self, s: AISystem, a: Assessment) -> None:
        """Approved, unexpired exceptions waive *waivable* findings. Waivers stay visible."""
        valid = {}
        for ex in s.exceptions:
            if ex.expires < self.as_of:
                a.findings.append(Finding("GOV-09", "high", f"exception for {ex.finding} expired on {ex.expires}",
                                          blocking=True))
            elif ex.approved_by.strip():
                valid[ex.finding] = ex
        kept = []
        for f in a.findings:
            if f.waivable and f.key in valid:
                a.waived.append(f)
            else:
                kept.append(f)
        a.findings = kept


# --------------------------------------------------------------------------- shadow AI
def discover_shadow_ai(log_lines: list[str], raw_systems: list[dict]) -> list[dict]:
    """Find AI services used on the network that no registered system declares.

    Log format (synthetic proxy log): ``<time> user=<id> dept=<dept> host=<host> bytes_out=<n>``
    """
    registered = {d for s in raw_systems if s.get("status") != "retired" for d in s.get("egress_domains", [])}
    usage: dict[str, dict] = defaultdict(lambda: {"users": set(), "depts": set(), "bytes_out": 0, "requests": 0})
    for line in log_lines:
        parts = dict(p.split("=", 1) for p in line.split() if "=" in p)
        host = parts.get("host", "")
        if host in KNOWN_AI_DOMAINS and host not in registered:
            u = usage[host]
            u["users"].add(parts.get("user", "?"))
            u["depts"].add(parts.get("dept", "?"))
            u["bytes_out"] += int(parts.get("bytes_out", 0))
            u["requests"] += 1
    return [
        {"host": h, "service": KNOWN_AI_DOMAINS[h], "users": len(u["users"]), "depts": sorted(u["depts"]),
         "requests": u["requests"], "bytes_out": u["bytes_out"]}
        for h, u in sorted(usage.items())
    ]


# --------------------------------------------------------------------------- KPIs
def governance_kpis(assessments: list[Assessment]) -> dict:
    """Management-system metrics (ISO/IEC 42001 clause 9 style: measure, then improve)."""
    live = [a for a in assessments if a.decision != "RETIRED"]
    n = len(live) or 1
    return {
        "systems_in_scope": len(live),
        # A record that failed the schema (GOV-00) cannot prove anything, so it counts as failing.
        "pct_owned": round(100 * sum(not a.codes & {"GOV-00", "GOV-01"} for a in live) / n),
        "pct_intended_use": round(100 * sum(not a.codes & {"GOV-00", "GOV-02"} for a in live) / n),
        "blocked": sum(a.decision == "BLOCKED" for a in live),
        "overdue_reviews": sum("GOV-06" in a.codes for a in live),
        "missing_controls": sum(len(a.missing_controls) for a in live),
        "active_waivers": sum(len(a.waived) for a in live),
    }


# --------------------------------------------------------------------------- CLI
def main() -> None:
    """Assess one system from a YAML file, with layers switchable from the command line.

    python 07-ai-governance/lab/secure_register.py 07-ai-governance/lab/fixtures/systems_vulnerable.yaml --id AI-002
    """
    import argparse
    from pathlib import Path

    import yaml

    p = argparse.ArgumentParser(description="Assess one AI system against the governance rules.")
    p.add_argument("systems_yaml")
    p.add_argument("--id", required=True, help="system id, e.g. AI-002")
    p.add_argument("--as-of", default="2026-11-15", help="assessment date (YYYY-MM-DD)")
    p.add_argument("--no-validate", action="store_true", help="L1 off: drop unknown fields silently")
    p.add_argument("--no-auto-tier", action="store_true", help="L2 off: trust the declared tier")
    p.add_argument("--no-checks", action="store_true", help="L3 off: no governance findings")
    args = p.parse_args()

    raw = next(s for s in yaml.safe_load(Path(args.systems_yaml).read_text(encoding="utf-8")) if s["id"] == args.id)
    reg = GovernedRegister(as_of=date.fromisoformat(args.as_of), validate=not args.no_validate,
                           auto_tier=not args.no_auto_tier, checks=not args.no_checks)
    a = reg.assess(raw)
    print(f"{a.system_id} {a.name}: declared={a.declared_tier} computed={a.tier} decision={a.decision}")
    for r in a.reasons:
        print(f"  reason   {r}")
    print(f"  required {', '.join(a.required_controls) or '-'}")
    print(f"  missing  {', '.join(a.missing_controls) or '-'}")
    for f in a.findings:
        print(f"  {f.severity:8} {f.code} {f.message}{'' if f.waivable else '  [not waivable]'}")
    for f in a.waived:
        print(f"  waived   {f.key}")


if __name__ == "__main__":
    main()
