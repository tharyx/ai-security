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


# ---------------------------------------------------------------- model governance and incidents
def naive_model_approval(request: dict) -> str:
    """'Someone said yes in the ticket.'

    VULN 10: any approval counts, even the requester approving their own request.
    VULN 11: the version is not pinned, so "latest" is approved and can change under you.
    VULN 12: evaluations, model card, risk entry and vendor assessment are never looked at.
    """
    return "APPROVED" if request.get("approvals") else "REJECTED"


def naive_can_deploy_model(approved_models: set[str], model: str) -> bool:
    # VULN 13: matches on the model *name*, so a silently swapped artifact deploys.
    return model in approved_models


def naive_incident_severity(incident: dict) -> str:
    """'The model said something odd: send it to the ML team as a quality bug.'

    VULN 14: severity comes from the kind of technology, not from impact (data, privilege, actions,
             people). Only "classic" security events such as stolen keys are treated as security.
    VULN 15: no regulatory flags are produced, so the 6-hour and 72-hour clocks start late.
    """
    return "SEV2" if incident.get("vector") == "key_theft" else "SEV4"
