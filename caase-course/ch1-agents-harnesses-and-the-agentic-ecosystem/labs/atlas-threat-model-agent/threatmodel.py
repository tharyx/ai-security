"""Map a YAML description of an agentic system to ATLAS tactics, OWASP ASI items and a risk rating.

    system.yaml -> rules per component type -> findings (tactics, ASI, LLM 2026) -> likelihood x impact

This is a teaching tool: the rules are simple and the mapping is a starting point for a human review,
not an authoritative classification. Check atlas.mitre.org and genai.owasp.org ("verify at source").
Tactic names follow the course list; ATLAS 2026 renamed "ML Model Access" to "AI Model Access" and
"ML Attack Staging" to "AI Attack Staging" (and maybe again; unconfirmed).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path

import yaml

COURSE_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "ML Model Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery",
    "Collection", "ML Attack Staging", "Exfiltration", "Impact",
]
RENAMED = {"AI Model Access": "ML Model Access", "AI Attack Staging": "ML Attack Staging"}
ASI_IDS = [f"ASI{n:02d}" for n in range(1, 11)]
KNOWN_CONTROLS = {"approval", "allowlist", "sandbox", "schema_validation", "signing", "provenance", "budget",
                  "logging", "egress_filter", "scoped_credentials", "dlp"}
KNOWN_TYPES = {"user_interface", "model_endpoint", "retriever", "tool", "mcp_server", "skill_marketplace",
               "memory", "code_executor", "peer_agent"}


@dataclass
class Rule:
    threat: str
    tactics: list[str]
    asi: list[str]
    llm2026: list[str]
    mitigated_by: set[str]
    injection_reachable: bool = False  # can untrusted text anywhere in the system steer this component?


RULES: dict[str, Rule] = {
    "injection": Rule("Prompt injection through untrusted content", ["Initial Access", "Execution"], ["ASI01"],
                      ["LLM01"], {"provenance", "schema_validation", "approval"}),
    "tool_misuse": Rule("Tool misuse or exfiltration through a side-effect tool", ["Exfiltration", "Impact"],
                        ["ASI02"], ["LLM03"], {"allowlist", "approval", "egress_filter", "schema_validation"}, True),
    "identity": Rule("Identity and privilege abuse (shared or broad credentials)",
                     ["Privilege Escalation", "Credential Access"], ["ASI03"], ["LLM03"],
                     {"scoped_credentials", "approval"}, True),
    "supply_chain": Rule("Malicious or compromised third-party tool, server or skill",
                         ["Resource Development", "Initial Access"], ["ASI04"], ["LLM04"],
                         {"signing", "allowlist", "sandbox"}),
    "code_exec": Rule("Unexpected code execution", ["Execution", "Privilege Escalation"], ["ASI05"], ["LLM10"],
                      {"sandbox", "egress_filter", "approval"}, True),
    "memory": Rule("Memory and context poisoning", ["Persistence", "Defense Evasion"], ["ASI06"], ["LLM05"],
                   {"provenance", "approval"}),
    "inter_agent": Rule("Insecure inter-agent communication and cascades", ["Initial Access", "Defense Evasion"],
                        ["ASI07", "ASI08"], ["LLM06"], {"signing", "budget"}, True),
    "model_access": Rule("Model access abuse and data leaving the boundary",
                         ["ML Model Access", "Reconnaissance", "Collection"], [], ["LLM02", "LLM06"],
                         {"dlp", "budget", "logging"}),
    "autonomy": Rule("Unchecked autonomy: runaway or rogue behaviour, misplaced human trust", ["Impact", "Defense Evasion"],
                     ["ASI09", "ASI10"], ["LLM03"], {"approval", "logging", "budget"}),
}


@dataclass
class Finding:
    component: str
    threat: str
    tactics: list[str]
    asi: list[str]
    llm2026: list[str]
    likelihood: int
    impact: int
    missing: list[str]
    score: int = 0
    level: str = ""

    def __post_init__(self):
        self.score = self.likelihood * self.impact
        self.level = level(self.score)


def level(score: int) -> str:
    return "critical" if score >= 15 else "high" if score >= 10 else "medium" if score >= 5 else "low"


def impact_of(comp: dict, autonomy: int) -> int:
    """Impact 1-5 from factors: privileges, data sensitivity, blast radius, reversibility, then autonomy."""
    blast = {"external": 4, None: 1, "none": 1, "internal": 2}.get(comp.get("side_effect"), 1)
    irreversible = 5 if (comp.get("side_effect") == "external" and comp.get("reversible", True) is False) else 1
    factors = sorted([comp.get("privileges", 1), comp.get("data_sensitivity", 1), blast, irreversible], reverse=True)
    base = math.ceil((factors[0] + factors[1]) / 2)
    return max(1, min(5, base + (1 if autonomy >= 3 else 0)))


def likelihood_of(comp: dict, rule: Rule, untrusted_in_system: bool = False) -> int:
    base = 2
    if comp.get("untrusted_input") or comp.get("exposed_to_internet"):
        base = 4
    elif rule.injection_reachable and untrusted_in_system:
        base = 4  # a side-effect component is reachable through an injected instruction
    elif comp.get("third_party"):
        base = 3
    controls = set(comp.get("controls", []))
    return max(1, base - len(controls & rule.mitigated_by))


def load(path: str | Path) -> dict:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "components" not in data:
        raise ValueError("system file needs a 'components' list")
    for c in data["components"]:
        if c.get("type") not in KNOWN_TYPES:
            raise ValueError(f"component {c.get('id')!r} has unknown type {c.get('type')!r}")
        unknown = set(c.get("controls", [])) - KNOWN_CONTROLS
        if unknown:
            raise ValueError(f"component {c['id']!r} lists unknown controls {sorted(unknown)}")
    return data


def rules_for(comp: dict) -> list[str]:
    t, keys = comp["type"], []
    if comp.get("untrusted_input") and t in ("user_interface", "retriever", "memory"):
        keys.append("injection")
    if t == "tool" and comp.get("side_effect") == "external":
        keys.append("tool_misuse")
    if comp.get("shared_credential") or (t == "tool" and comp.get("privileges", 1) >= 4):
        keys.append("identity")
    if t in ("mcp_server", "skill_marketplace") and comp.get("third_party"):
        keys.append("supply_chain")
    if t == "code_executor":
        keys.append("code_exec")
    if t == "memory":
        keys.append("memory")
    if t == "peer_agent":
        keys.append("inter_agent")
    if t == "model_endpoint" and (comp.get("exposed_to_internet") or comp.get("cloud_routed")):
        keys.append("model_access")
    return keys


def analyze(system: dict) -> list[Finding]:
    autonomy = int(system.get("autonomy", 1))
    findings: list[Finding] = []
    untrusted = any(c.get("untrusted_input") for c in system["components"])
    for comp in system["components"]:
        for key in rules_for(comp):
            r = RULES[key]
            missing = sorted(r.mitigated_by - set(comp.get("controls", [])))
            findings.append(Finding(comp["id"], r.threat, r.tactics, r.asi, r.llm2026,
                                    likelihood_of(comp, r, untrusted), impact_of(comp, autonomy), missing))
    # system-level: autonomy without a human in the loop anywhere
    has_approval = any("approval" in c.get("controls", []) for c in system["components"])
    has_logging = any("logging" in c.get("controls", []) for c in system["components"])
    if autonomy >= 3 and not has_approval or autonomy >= 2 and not has_logging:
        r = RULES["autonomy"]
        like = 4 if (autonomy >= 3 and not has_approval) else 3
        findings.append(Finding("system", r.threat, r.tactics, r.asi, r.llm2026, like,
                                min(5, 3 + autonomy // 2), sorted(r.mitigated_by)))
    return sorted(findings, key=lambda f: -f.score)


def summary(findings: list[Finding]) -> dict:
    tactics = {t for f in findings for t in f.tactics}
    asi = {a for f in findings for a in f.asi}
    return {"findings": len(findings), "total_score": sum(f.score for f in findings),
            "max_score": max((f.score for f in findings), default=0),
            "critical_or_high": sum(f.level in ("critical", "high") for f in findings),
            "tactics_hit": sorted(tactics, key=COURSE_TACTICS.index), "asi_hit": sorted(asi)}


def report(system: dict) -> str:
    fs = analyze(system)
    s = summary(fs)
    lines = [f"# Threat model: {system.get('name', 'unnamed')}", "",
             f"autonomy={system.get('autonomy')}  findings={s['findings']}  total_score={s['total_score']}  "
             f"critical/high={s['critical_or_high']}", "",
             "| Level | Score | Component | Threat | ATLAS tactics | ASI | LLM 2026 |", "|---|---|---|---|---|---|---|"]
    for f in fs:
        lines.append(f"| {f.level} | {f.score} (L{f.likelihood} x I{f.impact}) | {f.component} | {f.threat} | "
                     f"{', '.join(f.tactics)} | {', '.join(f.asi) or '-'} | {', '.join(f.llm2026)} |")
    return "\n".join(lines)
