"""The compliance matrix: AI risks -> controls -> audit evidence -> framework requirements.

This is the hands-on deliverable of Module 08 and the core of Portfolio Project 5
("AI Governance & Compliance Framework"). It answers one question per risk:
*is the control we rely on for this risk proven by fresh, intact evidence today?*

Inputs (no imports from sibling lab files; tests and build_dashboard.py pass the data in):
    risks     fixtures/ai_risks.yaml   risk, rating, OWASP LLM 2026 / Agentic / MCP IDs, control IDs
    controls  fixtures/controls.yaml   control set with framework mappings
    results   evidence_checker.check_evidence(...) output (objects with .control, .evidence_type,
              .status, .evidence_id)

Risk verdicts
    PROVEN       every control linked to the risk has all its evidence OK
    PARTIAL      some linked controls are proven, some are not
    UNPROVEN     no linked control is proven (controls may exist on paper)
    NO_CONTROL   the risk has no control at all (a design gap: no evidence can fix it)
    BROKEN_LINK  the risk points to a control ID that is not in the control set

Also renders a small compliance dashboard (Markdown or HTML) from data the caller collects:
inventory, policy pack status, the matrix and framework coverage.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field

FRAMEWORK_LABELS = {"eu_ai_act": "EU AI Act", "iso_42001": "ISO/IEC 42001", "nist_ai_rmf": "NIST AI RMF",
                    "iso_27001": "ISO/IEC 27001", "soc2": "SOC 2", "cert_in_ai": "CERT-In AI audit"}
RATING_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


@dataclass
class ControlLink:
    control: str
    title: str
    status: str  # OK | GAP | UNKNOWN
    evidence: list[tuple[str, str, str]] = field(default_factory=list)  # (type, status, evidence id)
    requirements: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class MatrixRow:
    risk_id: str
    system: str
    rating: str
    risk: str
    refs: list[str]
    links: list[ControlLink]
    verdict: str


def build_matrix(risks: list[dict], controls: list[dict], results: list) -> list[MatrixRow]:
    by_id = {c["id"]: c for c in controls}
    rows: list[MatrixRow] = []
    for r in risks:
        refs = [*r.get("owasp_llm_2026", []), *r.get("owasp_agentic", []), *r.get("owasp_mcp", [])]
        links: list[ControlLink] = []
        for cid in r.get("controls", []):
            c = by_id.get(cid)
            if c is None:
                links.append(ControlLink(cid, "(not in control set)", "UNKNOWN"))
                continue
            ev = [(x.evidence_type, x.status, x.evidence_id) for x in results if x.control == cid]
            status = "OK" if ev and all(s == "OK" for _, s, _ in ev) else "GAP"
            reqs = {fw: refs_ for fw, refs_ in c.get("maps_to", {}).items() if refs_}
            links.append(ControlLink(cid, c.get("title", ""), status, ev, reqs))
        rows.append(MatrixRow(r["id"], r.get("system", "?"), r.get("rating", "?"), r.get("risk", ""), refs,
                              links, _verdict(links)))
    return sorted(rows, key=lambda x: (RATING_ORDER.get(x.rating, 9), x.risk_id))


def _verdict(links: list[ControlLink]) -> str:
    if not links:
        return "NO_CONTROL"
    if any(link.status == "UNKNOWN" for link in links):
        return "BROKEN_LINK"
    ok = sum(link.status == "OK" for link in links)
    return "PROVEN" if ok == len(links) else "PARTIAL" if ok else "UNPROVEN"


def summary(rows: list[MatrixRow]) -> dict:
    counts: dict[str, int] = {}
    for r in rows:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    exposed = [r.risk_id for r in rows if r.rating in {"Critical", "High"} and r.verdict != "PROVEN"]
    return {"risks": len(rows), "verdicts": dict(sorted(counts.items())),
            "proven_pct": round(100 * counts.get("PROVEN", 0) / len(rows)) if rows else 0,
            "high_or_critical_not_proven": exposed}


def render_matrix_md(rows: list[MatrixRow], frameworks: tuple[str, ...] = ("eu_ai_act", "iso_42001",
                                                                          "nist_ai_rmf", "cert_in_ai")) -> str:
    head = ["Risk", "Rating", "OWASP", "Control", "Evidence", *(FRAMEWORK_LABELS[f] for f in frameworks), "Verdict"]
    lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for r in rows:
        links = r.links or [ControlLink("-", "", "-")]
        for i, link in enumerate(links):
            ev = "<br>".join(f"{t}: {s}" for t, s, _ in link.evidence) or "-"
            fws = ["; ".join(link.requirements.get(f, [])) or "-" for f in frameworks]
            first = i == 0
            lines.append("| " + " | ".join([
                f"{r.risk_id} {r.risk}" if first else "", r.rating if first else "",
                ", ".join(r.refs) if first else "", f"{link.control} ({link.status})", ev, *fws,
                f"**{r.verdict}**" if first else ""]).replace("\n", " ") + " |")
    return "\n".join(lines)


# --------------------------------------------------------------------------- dashboard
def parse_policy_header(text: str) -> dict[str, str]:
    """Read the header table of a 07-ai-governance/policies/*.md file."""
    out = {"title": text.splitlines()[0].lstrip("# ").strip() if text else ""}
    for key in ("Policy ID", "Owner", "Next review"):
        m = re.search(rf"^\|\s*{key}\s*\|\s*([^|]*?)\s*\|\s*$", text, re.MULTILINE)
        out[key] = m.group(1) if m else ""
    return out


def render_dashboard_md(data: dict) -> str:
    inv, pols, rows, cov = data["inventory"], data["policies"], data["matrix"], data["coverage"]
    s = summary(rows)
    ok_controls = sum(v == "OK" for v in data["control_status"].values())
    tiers: dict[str, int] = {}
    for sysd in inv:
        tiers[sysd["tier"]] = tiers.get(sysd["tier"], 0) + 1
    overdue = [p for p in pols if p["overdue"]]
    out = [f"# AI Governance and Compliance Dashboard ({data['label']}, as of {data['as_of']})", "",
           "> Generated from lab data by `build_dashboard.py`. Synthetic data; educational, not legal advice.", "",
           "## Headline numbers", "",
           "| Measure | Value |", "|---|---|",
           f"| AI systems in the register | {len(inv)} ({', '.join(f'{k}: {v}' for k, v in sorted(tiers.items()))}) |",
           f"| Policies in the pack | {len(pols)} ({len(overdue)} overdue for review) |",
           f"| Controls with good evidence | {ok_controls}/{len(data['control_status'])} |",
           f"| Top risks proven by evidence | {s['verdicts'].get('PROVEN', 0)}/{s['risks']} ({s['proven_pct']}%) |",
           f"| High/critical risks not proven | {', '.join(s['high_or_critical_not_proven']) or 'none'} |", "",
           "## Framework coverage (requirements backed by a control with good evidence)", "",
           "| Framework | Covered | Gaps (first 3) |", "|---|---|---|"]
    for fw, c in cov.items():
        out.append(f"| {FRAMEWORK_LABELS.get(fw, fw)} | {c['covered']}/{c['requirements']} | "
                   f"{'; '.join(c['gaps'][:3]) or '-'} |")
    if data.get("domains"):
        out += ["", "## CERT-In AI audit domains (evidence status)", "", "| Domain | Status |", "|---|---|"]
        out += [f"| {d} | {st} |" for d, st in data["domains"].items()]
    out += ["", "## Risk -> control -> evidence matrix", "", render_matrix_md(rows), "",
            "## Policy pack", "", "| Policy | Owner | Next review |", "|---|---|---|"]
    out += [f"| {p['Policy ID']} {p['title']} | {p['Owner']} | {p['Next review']}"
            f"{' (OVERDUE)' if p['overdue'] else ''} |" for p in pols]
    out += ["", "## AI system inventory", "", "| System | Name | Tier | Status |", "|---|---|---|---|"]
    out += [f"| {x['id']} | {x['name']} | {x['tier']} | {x['status']} |" for x in inv]
    return "\n".join(out) + "\n"


def render_dashboard_html(data: dict) -> str:
    """A self-contained HTML page with the same numbers (no external files, all text escaped)."""
    e = html.escape
    s = summary(data["matrix"])
    color = {"PROVEN": "#16a34a", "PARTIAL": "#d97706", "UNPROVEN": "#dc2626", "NO_CONTROL": "#dc2626",
             "BROKEN_LINK": "#dc2626"}
    rows = "".join(
        f"<tr><td>{e(r.risk_id)}</td><td>{e(r.risk)}</td><td>{e(r.rating)}</td><td>{e(', '.join(r.refs))}</td>"
        f"<td>{e(', '.join(f'{lk.control} ({lk.status})' for lk in r.links) or '-')}</td>"
        f"<td style='color:{color[r.verdict]};font-weight:600'>{e(r.verdict)}</td></tr>"
        for r in data["matrix"])
    cov = "".join(f"<tr><td>{e(FRAMEWORK_LABELS.get(fw, fw))}</td><td>{c['covered']}/{c['requirements']}</td></tr>"
                  for fw, c in data["coverage"].items())
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        f"<title>AI Compliance Dashboard</title>"
        "<style>body{font-family:Segoe UI,Helvetica,Arial,sans-serif;margin:24px;color:#0f172a}"
        "table{border-collapse:collapse;margin:12px 0}td,th{border:1px solid #cbd5e1;padding:4px 8px;"
        "text-align:left}th{background:#f8fafc}</style></head><body>"
        f"<h1>AI Governance and Compliance Dashboard</h1><p>{e(data['label'])} set, as of {e(str(data['as_of']))}. "
        f"Synthetic lab data.</p>"
        f"<p><b>{s['verdicts'].get('PROVEN', 0)}/{s['risks']}</b> top risks proven by evidence; "
        f"high/critical not proven: {e(', '.join(s['high_or_critical_not_proven']) or 'none')}.</p>"
        f"<h2>Framework coverage</h2><table><tr><th>Framework</th><th>Covered</th></tr>{cov}</table>"
        "<h2>Risk to control to evidence</h2><table><tr><th>Risk</th><th>Description</th><th>Rating</th>"
        f"<th>OWASP</th><th>Controls</th><th>Verdict</th></tr>{rows}</table></body></html>\n")
