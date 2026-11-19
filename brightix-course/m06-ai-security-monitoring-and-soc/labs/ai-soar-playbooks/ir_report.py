"""Incident timeline report mapped to NIST SP 800-61 (Rev. 2 phases and Rev. 3 / CSF 2.0).

Rev. 2 (2012) uses a four-phase lifecycle:
    Preparation -> Detection & Analysis -> Containment, Eradication & Recovery -> Post-Incident Activity
Rev. 3 (April 2025) drops its own lifecycle and maps incident response onto the NIST
Cybersecurity Framework 2.0 functions: Govern, Identify, Protect (mostly "preparation"),
Detect, Respond, Recover, with lessons learned feeding Identify > Improvement.

The CSF category codes used here (DE.AE, RS.MA, RS.AN, RS.CO, RS.MI, RC.RP, ID.IM) are
the CSF 2.0 short codes as we understand them. Verify against the published SP 800-61r3
and CSF 2.0 before you put them in a real report.
"""

from __future__ import annotations

from datetime import datetime

# action -> (Rev. 2 phase, Rev. 3 CSF 2.0 function > category)
STEP_MAP = {
    "enrich": ("Detection & Analysis", "Respond > RS.AN incident analysis"),
    "preserve_evidence": ("Containment, Eradication & Recovery (evidence gathering)", "Respond > RS.AN integrity and provenance"),
    "notify": ("Detection & Analysis (notification)", "Respond > RS.CO reporting and communication"),
    "set_quota": ("Containment, Eradication & Recovery (containment)", "Respond > RS.MI incident mitigation"),
    "raise_guardrail": ("Containment, Eradication & Recovery (containment)", "Respond > RS.MI incident mitigation"),
    "revoke_agent_token": ("Containment, Eradication & Recovery (containment)", "Respond > RS.MI incident mitigation"),
    "revoke_api_key": ("Containment, Eradication & Recovery (containment)", "Respond > RS.MI incident mitigation"),
    "block_egress": ("Containment, Eradication & Recovery (containment)", "Respond > RS.MI incident mitigation"),
    "disable_mcp_tool": ("Containment, Eradication & Recovery (containment)", "Respond > RS.MI incident mitigation"),
    "quarantine_doc": ("Containment, Eradication & Recovery (eradication)", "Respond > RS.MI incident mitigation"),
    "rotate_canary": ("Containment, Eradication & Recovery (eradication)", "Respond > RS.MI incident mitigation"),
    "rollback_system_prompt": ("Containment, Eradication & Recovery (recovery)", "Recover > RC.RP recovery plan execution"),
    "verify_not_retrievable": ("Containment, Eradication & Recovery (recovery)", "Recover > RC.RP recovery plan execution"),
}
CONTAIN = {"revoke_agent_token", "revoke_api_key", "block_egress", "disable_mcp_tool", "quarantine_doc",
           "set_quota", "raise_guardrail"}


def _t(ts: datetime) -> str:
    return ts.strftime("%H:%M:%S")


def timeline(incident, steps, pb: dict, lint_ok: bool) -> list[dict]:
    rows = [{"ts": None, "rev2": "Preparation", "rev3": "Govern / Identify / Protect",
             "what": f"playbook {pb['id']} linted ({'pass' if lint_ok else 'FAIL'}); watchlists and pins in place"}]
    rows.append({"ts": incident.first_seen, "rev2": "Detection & Analysis (indicator)", "rev3": "Detect > DE.AE adverse event analysis",
                 "what": "first malicious telemetry event"})
    for a in sorted(incident.alerts, key=lambda a: a.ts):
        rows.append({"ts": a.ts, "rev2": "Detection & Analysis", "rev3": "Detect > DE.AE adverse event analysis",
                     "what": f"alert {a.rule} ({a.severity}): {a.summary}"})
    rows.append({"ts": incident.detected_at, "rev2": "Detection & Analysis (declared)", "rev3": "Respond > RS.MA incident management",
                 "what": f"{incident.id} opened, severity {incident.severity}, playbook {pb['id']}"})
    for s in steps:
        rev2, rev3 = STEP_MAP[s.action]
        who = f" (approved by {s.approved_by})" if s.approved_by else ""
        rows.append({"ts": s.ts, "rev2": rev2, "rev3": rev3, "what": f"{s.action} [{s.status}]{who}: {s.detail}"})
    rows = rows[:1] + sorted(rows[1:], key=lambda r: r["ts"])  # stable: ties keep insertion order
    rows.append({"ts": None, "rev2": "Post-Incident Activity", "rev3": "Identify > ID.IM improvement",
                 "what": "lessons learned: new detection or tuning, control gap, playbook change, risk register entry"})
    return rows


def exposure(incident, steps, events) -> dict:
    """Malicious-looking activity on the incident's doc / MCP tool / destination AFTER detection.
    Split by whether it happened before or after the first containment step: the second
    group is what fast containment would have prevented (it is what MTTC buys you)."""
    keys = {k for k in incident.entities if k.split(":")[0] in ("doc", "mcp", "dest")}
    contained = [s.ts for s in steps if s.status == "done" and s.action in CONTAIN]
    cut = min(contained) if contained else None
    later = [e for e in events if e.ts > incident.detected_at and e.id not in incident.evidence
             and ({f"doc:{d}" for d in e.docs} | {f"mcp:{e.tool}", f"dest:{e.dest}"}) & keys]
    return {"after_detection": len(later),
            "before_containment": sum(1 for e in later if cut is None or e.ts < cut),
            "prevented_by_containment": sum(1 for e in later if cut is not None and e.ts >= cut)}


def metrics(incident, steps, events=None) -> dict:
    contained = [s.ts for s in steps if s.status == "done" and s.action in CONTAIN]
    pending = [s.action for s in steps if s.status in ("pending_approval", "denied", "refused")]
    out = {
        "time_to_detect_min": round((incident.detected_at - incident.first_seen).total_seconds() / 60, 1),
        "time_to_contain_min": round((min(contained) - incident.detected_at).total_seconds() / 60, 1) if contained else None,
        "open_items": pending,
    }
    if events is not None:
        out["exposure"] = exposure(incident, steps, events)
    return out


def render(incident, steps, pb: dict, lint_ok: bool, evidence_head: str, events=None) -> str:
    m = metrics(incident, steps, events)
    lines = [f"### {incident.id}: {pb['title']}", "",
             f"- Severity: **{incident.severity}** · rules: {', '.join(incident.rules)}",
             f"- ATLAS (names; verify IDs): {', '.join(incident.tags['atlas'])}",
             f"- OWASP (2026 LLM names): {', '.join(incident.tags['owasp'])}",
             f"- Entities: {', '.join(incident.entities)}",
             f"- Time to detect: {m['time_to_detect_min']} min · time to first containment: "
             f"{m['time_to_contain_min'] if m['time_to_contain_min'] is not None else 'not contained'} min",
             f"- Open items: {', '.join(m['open_items']) or 'none'} · evidence store chain head: `{evidence_head[:16]}`",
             *([f"- Exposure after detection: {m['exposure']['after_detection']} events "
                f"({m['exposure']['before_containment']} before containment, "
                f"{m['exposure']['prevented_by_containment']} would be stopped by it)"] if "exposure" in m else []),
             "", "| Time (UTC) | SP 800-61 Rev. 2 phase | Rev. 3 / CSF 2.0 (verify) | What happened |",
             "|---|---|---|---|"]
    for r in timeline(incident, steps, pb, lint_ok):
        lines.append(f"| {_t(r['ts']) if r['ts'] else '-'} | {r['rev2']} | {r['rev3']} | {r['what'].replace('|', '/')} |")
    return "\n".join(lines) + "\n"
