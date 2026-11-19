"""Rate the STRIDE findings of the MCP architecture lab, rank them, and write a register and exec summary.

Method: OWASP Risk Rating style.
    likelihood = mean(threat agent, vulnerability)         both 0-9
    impact     = mean(technical impact, business impact)   both 0-9
    level      = LOW (<3), MEDIUM (3 to <6), HIGH (6+)       for each of likelihood and impact
    severity   = matrix(likelihood level, impact level)      Note / Low / Medium / High / Critical

MCP adjustments (documented on purpose, change them in the lesson exercise):
    * a data flow that crosses a trust boundary: threat agent +1 (more people can reach it)
    * every control already present: vulnerability -3 (never below 1)       -> RESIDUAL rating
    * business impact is raised to the highest value of the assets the element touches (asset value, 0-9)
The inherent rating ignores existing controls; the residual rating includes them.

Usage (repository root):
    python cmcpse-course/ch3-threat-modeling-mcp-architectures/labs/risk-rating/rate_risks.py [--format md|csv|json] [--exec]
"""

from __future__ import annotations

import argparse
import csv
import io
import json
from dataclasses import asdict, dataclass
from pathlib import Path

from aisec_lab import load_lab_module

HERE = Path(__file__).resolve().parent
STRIDE_DIR = HERE.parent / "stride-mcp-architecture"
sm = load_lab_module(str(STRIDE_DIR / "_"), "stride_mcp")

CONTROL_VULN_REDUCTION = 3.0
CROSSING_AGENT_BONUS = 1.0
SEVERITY_ORDER = ["Note", "Low", "Medium", "High", "Critical"]

# OWASP matrix: rows = likelihood level, columns = impact level.
MATRIX = {
    ("LOW", "LOW"): "Note", ("LOW", "MEDIUM"): "Low", ("LOW", "HIGH"): "Medium",
    ("MEDIUM", "LOW"): "Low", ("MEDIUM", "MEDIUM"): "Medium", ("MEDIUM", "HIGH"): "High",
    ("HIGH", "LOW"): "Medium", ("HIGH", "MEDIUM"): "High", ("HIGH", "HIGH"): "Critical",
}


def level(x: float) -> str:
    return "LOW" if x < 3 else "MEDIUM" if x < 6 else "HIGH"


def clamp(x: float) -> float:
    return max(0.0, min(9.0, x))


@dataclass
class Rating:
    likelihood: float
    impact: float
    likelihood_level: str
    impact_level: str
    severity: str
    score: float  # likelihood * impact, used only to order findings inside the same severity


def rate(agent: float, vuln: float, tech: float, business: float) -> Rating:
    lk = (clamp(agent) + clamp(vuln)) / 2
    im = (clamp(tech) + clamp(business)) / 2
    ll, il = level(lk), level(im)
    return Rating(round(lk, 2), round(im, 2), ll, il, MATRIX[(ll, il)], round(lk * im, 2))


def treatment(severity: str, status: str) -> str:
    """One of the four classic treatments (mitigate, transfer, avoid, accept) plus a timeframe."""
    if status == "mitigated" and severity in ("Note", "Low", "Medium"):
        return "accept (monitor)"
    return {"Critical": "avoid or mitigate now (before release)", "High": "mitigate (this sprint)",
            "Medium": "mitigate (plan it) or transfer", "Low": "accept with owner sign-off",
            "Note": "accept"}[severity]


def asset_values(arch: dict) -> dict[str, float]:
    return {a["id"]: float(a["value"]) for a in arch.get("assets", [])}


def build_register(arch: dict, findings: list) -> list[dict]:
    values = asset_values(arch)
    rows = []
    for f in findings:
        fa = f.factors
        asset_max = max([values.get(a, 0) for a in f.assets] or [0])
        agent = fa["agent"] + (CROSSING_AGENT_BONUS if f.crossing else 0)
        business = max(fa["business"], asset_max)
        inherent = rate(agent, fa["vuln"], fa["tech"], business)
        vuln_res = max(1.0, fa["vuln"] - CONTROL_VULN_REDUCTION * len(f.present_controls))
        residual = rate(agent, vuln_res, fa["tech"], business)
        rows.append({
            "finding": f.id, "element": f.element_name, "stride": f.stride, "threat": f.title,
            "owasp_mcp": ", ".join(f.owasp_mcp), "status": f.status,
            "inherent": inherent.severity, "inherent_score": inherent.score,
            "residual": residual.severity, "residual_score": residual.score,
            "likelihood": residual.likelihood_level, "impact": residual.impact_level,
            "treatment": treatment(residual.severity, f.status),
            "recommended_controls": ", ".join(f.missing_controls) or "(none missing)",
            "mitigation": f.mitigation,
        })
    return rank(rows)


def rank(rows: list[dict]) -> list[dict]:
    """Sort by residual severity, then by score, then by finding id (stable and explainable)."""
    return sorted(rows, key=lambda r: (-SEVERITY_ORDER.index(r["residual"]), -r["residual_score"], r["finding"]))


def severity_counts(rows: list[dict], key: str = "residual") -> dict[str, int]:
    return {s: sum(1 for r in rows if r[key] == s) for s in reversed(SEVERITY_ORDER)}


def group_by_mitigation(rows: list[dict], top: int = 5) -> list[tuple[str, int]]:
    """Which missing control would close the most High/Critical findings? (helps prioritise work)"""
    tally: dict[str, int] = {}
    for r in rows:
        if r["residual"] in ("High", "Critical") and r["status"] == "open":
            for c in r["recommended_controls"].split(", "):
                if c and not c.startswith("("):
                    tally[c] = tally.get(c, 0) + 1
    return sorted(tally.items(), key=lambda kv: (-kv[1], kv[0]))[:top]


def exec_summary(arch: dict, rows: list[dict], top: int = 5) -> str:
    inh, res = severity_counts(rows, "inherent"), severity_counts(rows)
    lines = [
        f"# Threat model executive summary: {arch['system']}", "",
        "## Bottom line", "",
        f"We reviewed {len(rows)} potential threats. Without controls, {inh['Critical']} would be Critical and "
        f"{inh['High']} High. After the controls that exist today, {res['Critical']} are Critical and {res['High']} are High.", "",
        "## Top risks (residual)", "",
        "| Rank | Threat | Where | Severity | Decision needed |", "|---|---|---|---|---|"]
    for i, r in enumerate(rows[:top], 1):
        lines.append(f"| {i} | {r['threat']} | {r['element']} | {r['residual']} | {r['treatment']} |")
    lines += ["", "## Where to invest first", ""]
    for control, n in group_by_mitigation(rows):
        lines.append(f"* {control}: closes {n} High or Critical finding(s)")
    lines += ["", "## Severity counts", "", "| Severity | Inherent | Residual |", "|---|---|---|"]
    for s in reversed(SEVERITY_ORDER):
        lines.append(f"| {s} | {inh[s]} | {res[s]} |")
    lines += ["", "## Assumptions and limits", "",
              "* Ratings are estimates from a library of generic MCP threats, not measurements.",
              "* Findings marked mitigated need a test that proves the control works.",
              "* Loopback-only flows (127.0.0.1) may be accepted by the owner; record who accepted and when.", ""]
    return "\n".join(lines)


def to_markdown(rows: list[dict]) -> str:
    lines = ["| Rank | Finding | Element | STRIDE | Threat | Inherent | Residual | Treatment |", "|---|---|---|---|---|---|---|---|"]
    for i, r in enumerate(rows, 1):
        lines.append(f"| {i} | {r['finding']} | {r['element']} | {r['stride']} | {r['threat']} | {r['inherent']} | {r['residual']} | {r['treatment']} |")
    return "\n".join(lines) + "\n"


def to_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=list(rows[0]))
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("arch", nargs="?", default=str(sm.DEFAULT_ARCH))
    ap.add_argument("--format", choices=["md", "csv", "json"], default="md")
    ap.add_argument("--exec", action="store_true", help="print the executive summary instead of the register")
    args = ap.parse_args(argv)
    arch = sm.load_arch(args.arch)
    rows = build_register(arch, sm.find_threats(arch))
    if args.exec:
        print(exec_summary(arch, rows))
    elif args.format == "json":
        print(json.dumps(rows, indent=2))
    elif args.format == "csv":
        print(to_csv(rows), end="")
    else:
        print(to_markdown(rows), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
