"""Map Ansible hardening tasks to PCI DSS v4.0.1 requirement numbers (hedged) and report coverage.

Honest limits, printed in every report:
  * A hardening task is EVIDENCE of a technical control, not proof of compliance.
  * Many requirements are policy/process (2.2.1, 7.2.1) or need other tools (5.2.1 anti-malware,
    11.5.2 file integrity monitoring). The report lists those as GAPS instead of hiding them.
  * Requirement numbers and wording must be confirmed in the PCI SSC document library with your QSA.
"""

from __future__ import annotations

from pathlib import Path

import yaml

DISCLAIMER = (
    "Coverage here means 'a task implements or supports the technical part'. It is not a compliance "
    "statement. Verify requirement numbers and wording at the PCI SSC library; ask your QSA."
)


def load_tasks(playbook: str | Path) -> list[dict]:
    plays = yaml.safe_load(Path(playbook).read_text(encoding="utf-8"))
    tasks = []
    for play in plays:
        for t in play.get("tasks", []):
            tasks.append({"name": t["name"], "tags": list(t.get("tags", []))})
    return tasks


def load_mapping(path: str | Path) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def validate_mapping(mapping: dict) -> list[str]:
    """Return problems: mapped requirement ids that are not in the catalogue, bad strengths."""
    problems = []
    cat = mapping["catalogue"]
    for tag, entries in mapping["mappings"].items():
        for e in entries:
            if e["req"] not in cat:
                problems.append(f"tag {tag}: unknown requirement {e['req']}")
            if e["strength"] not in {"direct", "supporting"}:
                problems.append(f"tag {tag}: bad strength {e['strength']}")
    return problems


def coverage(tasks: list[dict], mapping: dict) -> dict:
    problems = validate_mapping(mapping)
    if problems:
        raise ValueError("; ".join(problems))
    per_req: dict[str, dict] = {r: {"direct": [], "supporting": []} for r in mapping["catalogue"]}
    unmapped = []
    for t in tasks:
        hit = False
        for tag in t["tags"]:
            for e in mapping["mappings"].get(tag, []):
                per_req[e["req"]][e["strength"]].append(t["name"])
                hit = True
        if not hit:
            unmapped.append(t["name"])
    rows = []
    for req, title in mapping["catalogue"].items():
        d, s = per_req[req]["direct"], per_req[req]["supporting"]
        status = "covered" if d else "partial" if s else "gap"
        rows.append({"req": req, "title": title, "status": status, "direct": d, "supporting": s})
    counts = {k: sum(r["status"] == k for r in rows) for k in ("covered", "partial", "gap")}
    pct = round(100.0 * counts["covered"] / len(rows), 1)
    return {"version": mapping["version"], "rows": rows, "counts": counts, "covered_pct": pct,
            "unmapped_tasks": unmapped, "disclaimer": DISCLAIMER}


def sort_key(req: str) -> list[int]:
    return [int(x) for x in req.split(".")]


def render_text(report: dict) -> str:
    lines = [f"PCI mapping coverage ({report['version']})",
             f"covered {report['counts']['covered']}, partial {report['counts']['partial']}, gap {report['counts']['gap']}  -> {report['covered_pct']}% directly covered", ""]
    for r in sorted(report["rows"], key=lambda r: sort_key(r["req"])):
        marker = {"covered": "OK     ", "partial": "PARTIAL", "gap": "GAP    "}[r["status"]]
        detail = f"{len(r['direct'])} direct, {len(r['supporting'])} supporting" if r["status"] != "gap" else "needs another control or a process"
        lines.append(f"  {marker} {r['req']:<9} {r['title'][:62]:<62} ({detail})")
    if report["unmapped_tasks"]:
        lines.append("")
        lines.append("Tasks with no requirement mapping: " + ", ".join(report["unmapped_tasks"]))
    lines += ["", report["disclaimer"]]
    return "\n".join(lines)
