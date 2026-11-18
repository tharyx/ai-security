"""The AI "register" many companies start with: a spreadsheet and good intentions.

Teams fill in a row. Whatever they type is accepted. The tier they choose decides how
much review they get. If a system is in the sheet, the pipeline deploys it.

DO NOT copy this pattern. Every line marked VULN is a governance failure this lab
teaches you to find. Compare with secure_register.py and risk_register.py.

    python 07-ai-governance/lab/demo.py
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SheetRow:
    system_id: str
    name: str
    tier: str
    decision: str
    notes: list[str] = field(default_factory=list)


class SpreadsheetRegister:
    def __init__(self) -> None:
        self.rows: dict[str, SheetRow] = {}

    def assess(self, raw: dict) -> SheetRow:
        # VULN 1: no schema. A typo like "human_oversite" is just another column nobody reads.
        # VULN 2: the team's own declared tier decides the level of review ("low" if left blank).
        tier = raw.get("declared_tier") or "low"
        notes = []
        # VULN 3: no check for owners or an intended-use statement. Orphaned systems look fine.
        # VULN 4: no check that high-risk systems have human oversight.
        # VULN 5: review dates and exception expiry dates are recorded but never compared to today.
        # VULN 6: controls are listed as free text; nobody checks them against the tier.
        if tier == "prohibited":
            decision = "BLOCKED"
        else:
            decision = "APPROVED"
            notes.append("self-attested")
        row = SheetRow(str(raw.get("id")), str(raw.get("name")), tier, decision, notes)
        self.rows[row.system_id] = row
        return row

    def load(self, raw_systems: list[dict]) -> list[SheetRow]:
        return [self.assess(r) for r in raw_systems]

    def can_deploy(self, system_id: str) -> bool:
        # VULN 7: "it's in the sheet" is treated as "it's approved".
        return system_id in self.rows


def naive_residual(row: dict) -> str:
    """How the spreadsheet scores residual risk.

    VULN 8: any listed control, even a planned one, makes the risk "Low".
    VULN 9: due dates, owners and acceptance expiry are never checked.
    """
    return "Low" if (row.get("controls") or "").strip() else "High"
