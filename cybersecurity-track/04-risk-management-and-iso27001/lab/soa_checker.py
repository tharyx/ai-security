"""Statement of Applicability (SoA) gap checker for ISO/IEC 27001:2022 Annex A.

Annex A has 93 controls in 4 themes: Organizational (5.1-5.37 = 37), People (6.1-6.8 = 8),
Physical (7.1-7.14 = 14), Technological (8.1-8.34 = 34).
This lab only needs the IDs, so titles are not stored here. Sample SoA titles are short
paraphrases written for this lesson.

Gap rules:
  missing_from_soa        - expected control has no SoA row at all
  excluded_no_reason      - marked not applicable but no justification
  not_implemented         - applicable, but status is 'no' or 'planned'
  partial                 - applicable, status 'partial'
  no_evidence             - status 'implemented' but no evidence listed (auditors will ask)
  unknown_control         - SoA row uses an ID that is not in Annex A
"""

from __future__ import annotations

from dataclasses import dataclass, field

import yaml

THEMES = {"5": ("Organizational", 37), "6": ("People", 8), "7": ("Physical", 14),
          "8": ("Technological", 34)}


def annex_a_ids() -> list[str]:
    return [f"{prefix}.{n}" for prefix, (_, count) in THEMES.items() for n in range(1, count + 1)]


def theme_of(control_id: str) -> str:
    return THEMES.get(control_id.split(".")[0], ("Unknown", 0))[0]


@dataclass
class Entry:
    control_id: str
    title: str = ""
    applicable: bool = True
    justification: str = ""
    status: str = "no"                 # implemented | partial | planned | no
    evidence: list[str] = field(default_factory=list)


@dataclass
class Gap:
    control_id: str
    kind: str
    detail: str

    @property
    def theme(self) -> str:
        return theme_of(self.control_id)


def load_soa(text: str) -> list[Entry]:
    data = yaml.safe_load(text)
    return [Entry(control_id=str(row["id"]), title=row.get("title", ""),
                  applicable=bool(row.get("applicable", True)),
                  justification=(row.get("justification") or "").strip(),
                  status=str(row.get("status", "no")).lower(),
                  evidence=list(row.get("evidence") or []))
            for row in data["controls"]]


def check(entries: list[Entry], expected: list[str] | None = None) -> list[Gap]:
    expected = expected if expected is not None else annex_a_ids()
    valid = set(annex_a_ids())
    by_id = {e.control_id: e for e in entries}
    gaps: list[Gap] = []
    for cid in expected:
        e = by_id.get(cid)
        if e is None:
            gaps.append(Gap(cid, "missing_from_soa", "no SoA row"))
        elif not e.applicable:
            if not e.justification:
                gaps.append(Gap(cid, "excluded_no_reason", "excluded without justification"))
        elif e.status in ("no", "planned"):
            gaps.append(Gap(cid, "not_implemented", f"status is '{e.status}'"))
        elif e.status == "partial":
            gaps.append(Gap(cid, "partial", "only partly implemented"))
        elif e.status == "implemented" and not e.evidence:
            gaps.append(Gap(cid, "no_evidence", "implemented but no evidence recorded"))
    for e in entries:
        if e.control_id not in valid:
            gaps.append(Gap(e.control_id, "unknown_control", "not an Annex A control ID"))
    return sorted(gaps, key=lambda g: (g.kind, tuple(
        int(p) if p.isdigit() else 0 for p in g.control_id.split("."))))


def summary(entries: list[Entry], gaps: list[Gap], expected: list[str]) -> dict:
    gap_ids = {g.control_id for g in gaps}
    by_kind: dict[str, int] = {}
    for g in gaps:
        by_kind[g.kind] = by_kind.get(g.kind, 0) + 1
    return {"expected": len(expected), "clean": len([c for c in expected if c not in gap_ids]),
            "gaps": len(gaps), "by_kind": by_kind}


def format_gaps(gaps: list[Gap]) -> str:
    lines = [f"{'Control':8} {'Theme':15} {'Gap type':20} Detail", "-" * 70]
    lines += [f"{g.control_id:8} {g.theme:15} {g.kind:20} {g.detail}" for g in gaps]
    return "\n".join(lines)
