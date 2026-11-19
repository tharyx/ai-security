"""Generate an application-specific security checklist from (a sample of) OWASP ASVS 5.0.

Workflow taught here:
1. pick a target level (L1, L2 or L3) and describe the app's features (web, api, cookies, ...);
2. select only the requirements that apply (level <= target AND feature overlap);
3. give each one a STABLE internal id (APS-<ref>) that you keep across ASVS versions, mapped to the
   ASVS reference in its own column;
4. record results with evidence, measure coverage, and gate the build.

The bundled fixture is a small ASVS-5-LIKE sample with paraphrased texts and sample references.
``load_csv`` reads a CSV export (column names are configurable) so you can swap in the official
file. Verify the official file's location and columns at the OWASP ASVS project.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

STATUSES = ("pass", "fail", "na", "untested")


def load_sample(path) -> list:
    return json.loads(Path(path).read_text(encoding="utf-8"))["requirements"]


DEFAULT_COLS = {"ref": "req_id", "chapter": "chapter_id", "chapter_name": "chapter_name",
                "text": "req_description", "level": "level"}


def load_csv(path, cols: dict = DEFAULT_COLS) -> list:
    reqs = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            reqs.append({
                "ref": row[cols["ref"]], "chapter": row[cols["chapter"]],
                "chapter_name": row[cols["chapter_name"]], "text": row[cols["text"]],
                "level": int(str(row[cols["level"]]).lstrip("Ll")), "applies_to": ["all"],
            })
    return reqs


def internal_id(ref: str, prefix: str = "APS") -> str:
    return f"{prefix}-" + ref.replace(".", "-")


def _chapter_key(ch: str) -> int:
    return int(ch.lstrip("V"))


def select(reqs: list, level: int, features: list) -> list:
    if level not in (1, 2, 3):
        raise ValueError("ASVS level must be 1, 2 or 3")
    feats = set(features)
    chosen = [r for r in reqs
              if r["level"] <= level and ("all" in r["applies_to"] or feats & set(r["applies_to"]))]
    items = [dict(r, id=internal_id(r["ref"]), status="untested", evidence="") for r in chosen]
    return sorted(items, key=lambda i: (_chapter_key(i["chapter"]), i["ref"]))


def apply_results(items: list, results: dict) -> list:
    out = []
    for i in items:
        res = results.get(i["id"], {})
        status = res.get("status", "untested")
        if status not in STATUSES:
            raise ValueError(f"{i['id']}: unknown status {status!r}")
        out.append(dict(i, status=status, evidence=res.get("evidence", "")))
    return out


def summary(items: list) -> dict:
    counts = {s: sum(1 for i in items if i["status"] == s) for s in STATUSES}
    applicable = len(items) - counts["na"]
    counts["total"] = len(items)
    counts["tested_pct"] = round(100 * (len(items) - counts["untested"]) / len(items), 1) if items else 0.0
    counts["pass_pct"] = round(100 * counts["pass"] / applicable, 1) if applicable else 0.0
    return counts


def gate(items: list) -> int:
    """Fail on any failed requirement, or on any level-1 requirement still untested."""
    bad = [i for i in items if i["status"] == "fail" or (i["status"] == "untested" and i["level"] == 1)]
    return 1 if bad else 0


def to_markdown(items: list, title: str) -> str:
    box = {"pass": "[x]", "fail": "[ ] FAIL", "na": "[-] n/a", "untested": "[ ]"}
    lines = [f"# ASVS checklist: {title}", ""]
    current = None
    for i in items:
        if i["chapter"] != current:
            current = i["chapter"]
            lines += ["", f"## {i['chapter']} {i['chapter_name']}", ""]
        ev = f" (evidence: {i['evidence']})" if i["evidence"] else ""
        lines.append(f"- {box[i['status']]} **{i['id']}** L{i['level']} [{i['ref']}] {i['text']}{ev}")
    s = summary(items)
    lines += ["", f"Total {s['total']}: pass {s['pass']}, fail {s['fail']}, n/a {s['na']}, "
                  f"untested {s['untested']}. Tested {s['tested_pct']}%, passing {s['pass_pct']}%."]
    return "\n".join(lines).replace("\n\n\n", "\n\n")


def to_csv(items: list) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["id", "asvs_ref", "chapter", "level", "status", "evidence", "text"])
    for i in items:
        w.writerow([i["id"], i["ref"], i["chapter"], i["level"], i["status"], i["evidence"], i["text"]])
    return buf.getvalue()
