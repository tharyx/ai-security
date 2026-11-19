"""Threat model as code for the capstone target, with a generated markdown report.

Why "as code": the model lives next to the system, is reviewed in pull requests, and
tests check it stays honest (every threat has a test or a verification, every control
it names really exists as a config toggle, every red-team attack maps to a threat).

Tags (verify at source before using in a real report):
  STRIDE letter · MITRE ATLAS technique NAME (IDs change between releases)
  OWASP Top 10 for LLM Applications 2026 name (see the repo's 2023<->2026 mapping page)
  OWASP Top 10 for Agentic Applications 2026 (ASI ids as used in this repo; verify)
"""

from __future__ import annotations

from aisec_lab import load_lab_module

app = load_lab_module(__file__, "enterprise_app")

ASSETS = [
    {"id": "AS-1", "name": "Tenant documents (RAG store)", "class": "confidential, per tenant", "owner": "Knowledge mgmt"},
    {"id": "AS-2", "name": "CRM customer records", "class": "confidential, regulated", "owner": "Sales ops"},
    {"id": "AS-3", "name": "System prompts and agent configuration", "class": "internal", "owner": "AI platform"},
    {"id": "AS-4", "name": "Agent service credentials and tool tokens", "class": "secret", "owner": "IAM"},
    {"id": "AS-5", "name": "Outbound email channel (brand, data egress)", "class": "business critical", "owner": "Messaging"},
    {"id": "AS-6", "name": "Security telemetry and evidence", "class": "integrity critical", "owner": "SOC"},
]

BOUNDARIES = [
    {"id": "TB-1", "name": "Internet user -> assistant API", "note": "identity verified here (OIDC/JWT)"},
    {"id": "TB-2", "name": "Agents -> LLM provider", "note": "model output is untrusted"},
    {"id": "TB-3", "name": "Agents -> MCP gateway", "note": "policy enforcement point for every tool call"},
    {"id": "TB-4", "name": "Gateway -> third-party MCP servers", "note": "supply chain: descriptions and results are untrusted"},
    {"id": "TB-5", "name": "Tenant A data <-> tenant B data", "note": "logical isolation in a shared store"},
    {"id": "TB-6", "name": "Enterprise -> internet egress (email)", "note": "where data leaves"},
]

ELEMENTS = [
    {"id": "user", "type": "external_entity", "zone": "internet"},
    {"id": "planner", "type": "process", "zone": "app"},
    {"id": "research", "type": "process", "zone": "app"},
    {"id": "action", "type": "process", "zone": "app"},
    {"id": "llm", "type": "process", "zone": "provider"},
    {"id": "gateway", "type": "process", "zone": "app"},
    {"id": "docs-mcp", "type": "process", "zone": "internal-tools"},
    {"id": "crm-mcp", "type": "process", "zone": "internal-tools"},
    {"id": "mail-mcp", "type": "process", "zone": "internal-tools"},
    {"id": "analytics-mcp", "type": "process", "zone": "third-party"},
    {"id": "doc-store", "type": "data_store", "zone": "data"},
    {"id": "crm-db", "type": "data_store", "zone": "data"},
    {"id": "telemetry", "type": "data_store", "zone": "soc"},
]

FLOWS = [
    {"id": "F1", "src": "user", "dst": "planner", "data": "request + identity token", "boundary": "TB-1"},
    {"id": "F2", "src": "planner", "dst": "llm", "data": "system prompt + tool catalog + request", "boundary": "TB-2"},
    {"id": "F3", "src": "research", "dst": "gateway", "data": "search_docs(query, tenant)", "boundary": "TB-3"},
    {"id": "F4", "src": "gateway", "dst": "docs-mcp", "data": "query + tenant filter", "boundary": ""},
    {"id": "F5", "src": "docs-mcp", "dst": "doc-store", "data": "retrieval (both tenants in one store)", "boundary": "TB-5"},
    {"id": "F6", "src": "action", "dst": "gateway", "data": "send_email / read_crm / run_report", "boundary": "TB-3"},
    {"id": "F7", "src": "gateway", "dst": "analytics-mcp", "data": "tools/list descriptions, tool results", "boundary": "TB-4"},
    {"id": "F8", "src": "mail-mcp", "dst": "user", "data": "email to any address", "boundary": "TB-6"},
    {"id": "F9", "src": "gateway", "dst": "telemetry", "data": "decisions, hashes, provenance", "boundary": ""},
]

# controls: config toggles (enterprise_app.Config). Anything else must be listed in EXTERNAL_CONTROLS.
THREATS = [
    {"id": "TH-01", "title": "Poisoned document steers an agent into an action (indirect injection)", "stride": "T",
     "target": "F3/F5", "boundary": "TB-5", "assets": ["AS-5", "AS-1"],
     "atlas": "LLM Prompt Injection (indirect); RAG Poisoning", "owasp_llm": "Prompt Injection",
     "owasp_agentic": "ASI01 Agent Goal Hijack", "likelihood": 5, "impact": 5, "attack": "AT-01",
     "controls": ["egress_allowlist", "hitl_send_email", "output_dlp", "output_guard"]},
    {"id": "TH-02", "title": "Tenant A user retrieves tenant B documents", "stride": "I",
     "target": "F5", "boundary": "TB-5", "assets": ["AS-1"], "atlas": "Data from Information Repositories (verify)",
     "owasp_llm": "Vector and Embedding Weaknesses", "owasp_agentic": "ASI03 Identity and Privilege Abuse",
     "likelihood": 4, "impact": 5, "attack": "AT-02", "controls": ["retrieval_acl"]},
    {"id": "TH-03", "title": "Malicious MCP server description (tool poisoning, shadow install)", "stride": "T",
     "target": "F7", "boundary": "TB-4", "assets": ["AS-2", "AS-4"], "atlas": "AI Supply Chain Compromise",
     "owasp_llm": "Supply Chain", "owasp_agentic": "ASI04 Agentic Supply Chain", "likelihood": 3, "impact": 5,
     "attack": "AT-03", "controls": ["tool_pinning", "least_privilege"]},
    {"id": "TH-04", "title": "Approved MCP tool changes after approval (rug pull)", "stride": "T",
     "target": "F7", "boundary": "TB-4", "assets": ["AS-5", "AS-1"], "atlas": "AI Supply Chain Compromise",
     "owasp_llm": "Supply Chain", "owasp_agentic": "ASI04 Agentic Supply Chain", "likelihood": 3, "impact": 5,
     "attack": "AT-04", "controls": ["tool_pinning", "egress_allowlist", "hitl_send_email"]},
    {"id": "TH-05", "title": "Instruction hidden in a tool result (tool-response injection)", "stride": "T",
     "target": "F6", "boundary": "TB-3", "assets": ["AS-5"], "atlas": "LLM Prompt Injection (indirect)",
     "owasp_llm": "Prompt Injection", "owasp_agentic": "ASI02 Tool Misuse", "likelihood": 4, "impact": 4,
     "attack": "AT-05", "controls": ["egress_allowlist", "hitl_send_email"]},
    {"id": "TH-06", "title": "Low-privilege user acts through the action agent's credentials (confused deputy)",
     "stride": "E", "target": "action", "boundary": "TB-3", "assets": ["AS-2", "AS-4"],
     "atlas": "Exfiltration via AI Agent Tool Invocation", "owasp_llm": "Excessive Agency",
     "owasp_agentic": "ASI03 Identity and Privilege Abuse", "likelihood": 4, "impact": 4, "attack": "AT-06",
     "controls": ["least_privilege"]},
    {"id": "TH-07", "title": "Data leaves by email to an outside address", "stride": "I", "target": "F8",
     "boundary": "TB-6", "assets": ["AS-1", "AS-5"], "atlas": "Exfiltration via AI Agent Tool Invocation",
     "owasp_llm": "Sensitive Information Disclosure", "owasp_agentic": "ASI02 Tool Misuse", "likelihood": 4,
     "impact": 4, "attack": "AT-07", "controls": ["egress_allowlist", "hitl_send_email", "output_dlp"]},
    {"id": "TH-08", "title": "System prompt and its markers leak to a user", "stride": "I", "target": "F2",
     "boundary": "TB-2", "assets": ["AS-3"], "atlas": "LLM Meta Prompt Extraction",
     "owasp_llm": "Hidden Context Exposure", "owasp_agentic": "ASI01 Agent Goal Hijack", "likelihood": 5,
     "impact": 3, "attack": "AT-08", "controls": ["output_dlp", "input_guard", "output_guard"]},
    {"id": "TH-09", "title": "Agent action cannot be attributed to a user and an agent (repudiation)", "stride": "R",
     "target": "F9", "boundary": "TB-3", "assets": ["AS-6"], "atlas": "Defense Evasion (tactic)",
     "owasp_llm": "Excessive Agency", "owasp_agentic": "ASI10 Rogue Agents", "likelihood": 3, "impact": 3,
     "attack": None, "verified_by": "AR-09 telemetry check", "controls": ["gateway_telemetry"]},
    {"id": "TH-10", "title": "Cost-DoS: token floods or agent loops burn budget", "stride": "D",
     "target": "llm", "boundary": "TB-2", "assets": ["AS-3"], "atlas": "Cost Harvesting; Denial of AI Service",
     "owasp_llm": "Unbounded Consumption", "owasp_agentic": "ASI08 Cascading Failures", "likelihood": 3,
     "impact": 3, "attack": None, "verified_by": None, "controls": ["action_budget", "token_quota (not built)"]},
]
EXTERNAL_CONTROLS = {"gateway_telemetry": "always on (Gateway.log)", "action_budget": "EnterpriseAssistant.MAX_ACTIONS",
                     "token_quota (not built)": "GAP: no per-user token quota in this lab (see the m06 SOAR lab)"}


def hard_controls(t: dict) -> list[str]:
    return [c for c in t["controls"] if c in app.HARD or c in ("gateway_telemetry", "action_budget")]


def validate() -> list[str]:
    """Consistency checks a reviewer would otherwise do by hand."""
    problems = []
    ids = {e["id"] for e in ELEMENTS}
    toggles = set(app.SOFT + app.HARD)
    for f in FLOWS:
        if f["src"] not in ids or f["dst"] not in ids:
            problems.append(f"{f['id']}: unknown element")
    for t in THREATS:
        for c in t["controls"]:
            if c not in toggles and c not in EXTERNAL_CONTROLS:
                problems.append(f"{t['id']}: control {c} does not exist")
        if not t.get("attack") and not t.get("verified_by"):
            problems.append(f"{t['id']}: no test and no verification (coverage gap)")
        if not hard_controls(t):
            problems.append(f"{t['id']}: only soft controls")
    return problems


def residual(t: dict, scorecard=None) -> str:
    if t.get("attack") and scorecard is not None:
        row = next(r for r in scorecard.rows if r["id"] == t["attack"])
        if not row["hardened"] and not row["hard_only"]:
            return "Low (tested: blocked even with soft layers off)"
        return "HIGH (attack still works)"
    if t.get("verified_by"):
        return "Low (verified by check)"
    return "Medium (UNTESTED: accept or fund)"


def report(scorecard=None) -> str:
    out = ["# Threat model: multi-agent enterprise assistant (RAG + MCP)", "",
           "> Generated by `threat_model.py`. Tags are names; verify ATLAS IDs and OWASP numbering at source.", "",
           "## Assets", "", "| ID | Asset | Classification | Owner |", "|---|---|---|---|"]
    out += [f"| {a['id']} | {a['name']} | {a['class']} | {a['owner']} |" for a in ASSETS]
    out += ["", "## Trust boundaries", "", "| ID | Boundary | Note |", "|---|---|---|"]
    out += [f"| {b['id']} | {b['name']} | {b['note']} |" for b in BOUNDARIES]
    out += ["", "## Data flows crossing a boundary", "", "| Flow | From -> To | Data | Boundary |", "|---|---|---|---|"]
    out += [f"| {f['id']} | {f['src']} -> {f['dst']} | {f['data']} | {f['boundary']} |" for f in FLOWS if f["boundary"]]
    out += ["", "## Threats", "",
            "| ID | Threat | STRIDE | ATLAS | OWASP LLM 2026 | OWASP Agentic | LxI | Test | Hard controls | Residual |",
            "|---|---|---|---|---|---|---|---|---|---|"]
    for t in sorted(THREATS, key=lambda t: -t["likelihood"] * t["impact"]):
        out.append(f"| {t['id']} | {t['title']} | {t['stride']} | {t['atlas']} | {t['owasp_llm']} | "
                   f"{t['owasp_agentic']} | {t['likelihood'] * t['impact']} | {t.get('attack') or t.get('verified_by') or 'none'} | "
                   f"{', '.join(hard_controls(t)) or '-'} | {residual(t, scorecard)} |")
    gaps = validate()
    out += ["", "## Open issues", ""] + ([f"- {g}" for g in gaps] or ["- none"])
    return "\n".join(out) + "\n"
