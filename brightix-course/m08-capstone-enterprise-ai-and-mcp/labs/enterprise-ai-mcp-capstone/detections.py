"""SOC detection rules over the capstone telemetry, correlation per trace, and incident
playbook outputs (proposals for a human; this module changes nothing).

The gateway logs FACTS even when nothing is enforced (baseline). So the same rules work
in both modes: on the baseline they find incidents that HAPPENED (impact), on the
hardened build they find attempts that were STOPPED (no impact, still worth a look).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from aisec_lab import load_lab_module

app = load_lab_module(__file__, "enterprise_app")
SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class Alert:
    rule: str
    severity: str
    trace: str
    user: str
    evidence: list[int]
    detail: str
    atlas: str
    owasp: str
    impact: bool = False             # True when the harmful step actually happened


@dataclass
class Incident:
    trace: str
    user: str
    alerts: list[Alert] = field(default_factory=list)
    impact: bool = False

    @property
    def severity(self) -> str:
        return max((a.severity for a in self.alerts), key=SEV_RANK.__getitem__)

    @property
    def rules(self) -> list[str]:
        return sorted({a.rule for a in self.alerts})


def _a(rule, sev, e, detail, atlas, owasp, impact=None) -> Alert:
    if impact is None:
        impact = e.get("decision") in ("allowed", "shown")
    return Alert(rule, sev, e["trace"], e.get("user", ""), [e["seq"]], detail, atlas, owasp, impact)


def rule_untrusted_tool_call(log):
    """A tool call whose idea came from a document, tool result or tool description."""
    return [_a("untrusted_tool_call", "critical" if e["decision"] == "allowed" else "high", e,
               f"{e['agent']} -> {e['tool']} ({e['provenance']}, {e['decision']})",
               "LLM Prompt Injection (indirect)", "Prompt Injection")
            for e in log if e["kind"] == "tool_call" and e["provenance"].startswith("untrusted")]


def rule_egress_violation(log):
    return [_a("egress_violation", "critical" if e["decision"] == "allowed" else "high", e,
               f"send_email to {e['dest']} ({e['decision']})", "Exfiltration via AI Agent Tool Invocation",
               "Sensitive Information Disclosure")
            for e in log if e["kind"] == "tool_call" and e["tool"] == "send_email"
            and e["dest"] not in app.EGRESS_ALLOWLIST[e["tenant"]]]


def rule_cross_tenant(log):
    out = []
    for e in log:
        if e["kind"] == "retrieval" and (any(t != e["tenant"] for t in e["doc_tenants"])
                                         or (e["tenant_arg"] and e["tenant_arg"] != e["tenant"])):
            crossed = any(t != e["tenant"] for t in e["doc_tenants"])
            out.append(_a("cross_tenant_access", "critical" if crossed else "high", e,
                          f"asked for {e['tenant_arg'] or '-'}, got docs from {e['doc_tenants']}",
                          "Data from Information Repositories (verify)", "Vector and Embedding Weaknesses", impact=crossed))
        if e["kind"] == "tool_call" and e["tool"] == "read_crm" and e["tenant_arg"] and e["tenant_arg"] != e["tenant"]:
            out.append(_a("cross_tenant_access", "critical" if e["decision"] == "allowed" else "high", e,
                          f"read_crm for {e['tenant_arg']} by a {e['tenant']} user ({e['decision']})",
                          "Data from Information Repositories (verify)", "Sensitive Information Disclosure"))
    return out


def rule_tool_integrity(log):
    """Tool description not pinned (shadow server) or changed since approval (rug pull)."""
    seen, out = set(), []
    for e in log:
        if e["kind"] == "tool_list" and e["reason"] and (e["trace"], e["tool"]) not in seen:
            seen.add((e["trace"], e["tool"]))
            out.append(_a("tool_integrity", "critical" if e["decision"] == "shown" else "high", e, f"{e['tool']}: {e['reason']} ({e['decision']})",
                          "AI Supply Chain Compromise", "Supply Chain"))
    return out


def rule_entitlement_gap(log):
    return [_a("entitlement_gap", "critical" if e["decision"] == "allowed" else "medium", e,
               f"{e['tool']} for a user without the entitlement ({e['decision']})",
               "Exfiltration via AI Agent Tool Invocation", "Excessive Agency")
            for e in log if e["kind"] == "tool_call" and not e["user_entitled"]]


def rule_canary_exposure(log):
    out = []
    for e in log:
        if e["kind"] == "response" and e["canary_hit"]:
            out.append(_a("canary_exposure", "critical", e, "a canary reached the user", "LLM Meta Prompt Extraction",
                          "Hidden Context Exposure", impact=True))
        if e["kind"] == "dlp" and e["forbidden"]:
            out.append(_a("canary_exposure", "medium", e, f"DLP stopped {e['forbidden']} forbidden canary in {e['where']}",
                          "LLM Meta Prompt Extraction", "Hidden Context Exposure", impact=False))
    return out


def rule_guard_block(log):
    return [_a("guard_block", "low", e, f"{e['stage']} guard blocked", "LLM Jailbreak", "Prompt Injection", impact=False)
            for e in log if e["kind"] == "guard"]


RULES = [rule_untrusted_tool_call, rule_egress_violation, rule_cross_tenant, rule_tool_integrity,
         rule_entitlement_gap, rule_canary_exposure, rule_guard_block]


def detect(log: list[dict]) -> list[Alert]:
    return [a for r in RULES for a in r(log)]


def correlate(log: list[dict], alerts: list[Alert]) -> list[Incident]:
    """One incident per trace (a trace is one user request across all agents and tools)."""
    by: dict[str, Incident] = {}
    for a in alerts:
        by.setdefault(a.trace, Incident(a.trace, a.user)).alerts.append(a)
    for inc in by.values():
        if not inc.user:
            inc.user = next((e["user"] for e in log if e.get("trace") == inc.trace and e.get("user")), "")
        inc.impact = any(a.impact for a in inc.alerts)
    return sorted(by.values(), key=lambda i: (-SEV_RANK[i.severity], i.trace))


# step: (action, destructive?)
PLAYBOOK = {
    "untrusted_tool_call": [("preserve prompt/response/tool-call evidence with hashes", False),
                            ("quarantine the source document or record and re-index", True),
                            ("revoke the action agent's token if a call executed", True)],
    "egress_violation": [("block the destination at the egress proxy", True),
                         ("notify the data owner; start breach assessment if data left", False)],
    "cross_tenant_access": [("preserve retrieval logs", False), ("suspend the user's session", True),
                            ("check the retrieval ACL filter is deployed", False)],
    "tool_integrity": [("disable the MCP tool or server at the gateway", True),
                       ("diff the old and new descriptions; contact the vendor", False)],
    "entitlement_gap": [("review the agent's scopes and on-behalf-of checks", False),
                        ("revoke the agent's broad service credential", True)],
    "canary_exposure": [("roll back the system prompt / rotate the canary", True),
                        ("raise guardrail strictness for this app", False)],
    "guard_block": [("monitor the user; no action alone", False)],
}


EVIDENCE_STEP = "preserve prompt/response/tool-call evidence with hashes"


def playbook_output(inc: Incident) -> dict:
    """Proposed response for a human: evidence first, then safe steps, then gated containment."""
    steps, seen = [{"action": EVIDENCE_STEP, "needs_approval": False}], {EVIDENCE_STEP}
    rules = [r for r in inc.rules if r != "guard_block"] or inc.rules  # a guard block alone is only a signal
    for rule in rules:
        for action, destructive in PLAYBOOK[rule]:
            if action not in seen:
                seen.add(action)
                steps.append({"action": action, "needs_approval": destructive})
    steps[1:] = sorted(steps[1:], key=lambda s: s["needs_approval"])  # stable: safe steps before gated ones
    return {"incident": inc.trace, "user": inc.user, "severity": inc.severity, "impact": inc.impact,
            "rules": inc.rules, "atlas": sorted({a.atlas for a in inc.alerts}),
            "owasp": sorted({a.owasp for a in inc.alerts}), "steps": steps}
