# Lab: Risk register with treatment rules (identify, assess, treat, residual)

**Course topics:** [CSC 3] Risk Management workflow, Risk Identification, Risk Treatment (mitigate, avoid, transfer, accept), Ensuring Business Continuity While Reducing Risk; [CTMP 1] Risk Management Strategies with Examples. Lesson: [01 Risk management primer](../../01-risk-management-primer.md).

**Time:** 45 minutes. **Tests:** 10, all offline. **Safety:** fictional company data only. Only test systems you own or have written permission to test.

> **Related lab, not a duplicate.** [cybersecurity-track module 04](../../../../cybersecurity-track/04-risk-management-and-iso27001/01-risk-concepts.md#lab-risk-register-scorer) has a general risk register scorer (bands, overdue reviews). This lab focuses on what a **security champion** checks: the identification source of each risk, and the **evidence rule of each treatment**.

## Goal

Turn a "spreadsheet" register, where decisions have no evidence, into a governed register that passes a gate.

## Concept

[risk_register.py](risk_register.py) loads a JSON register. Each risk has a source (`compliance`, `design`, `vulnerability`, `threat-landscape`), likelihood and impact (1 to 5) and one treatment. Residual risk depends on the treatment:

| Treatment | Residual | Evidence rule (issue code if missing) |
|---|---|---|
| mitigate | controls lower likelihood or impact | at least one control (`MITIGATE_WITHOUT_CONTROL`); each control changes something (`CONTROL_WITH_NO_EFFECT`) |
| avoid | 0 | a described change (`AVOID_WITHOUT_CHANGE`) |
| transfer | impact lowered by at most 1 | a named party (`TRANSFER_WITHOUT_PARTY`); no bigger claim (`TRANSFER_OVERCLAIMED`) |
| accept | unchanged | reason, review date, and an accepter with authority for the band (`ACCEPTED_WITHOUT_AUTHORITY`, `ACCEPTANCE_EXPIRED`) |

Other checks: an owner on every risk (`NO_OWNER`), residual above appetite (`RESIDUAL_ABOVE_APPETITE`, default 9), a continuity plan for critical services (`NO_CONTINUITY_PLAN`), and a register-level **coverage gap** when one identification source has no risks at all.

## Steps

1. Run the demo and read both registers.
2. In `register_spreadsheet.json`, fix R-01: change the treatment to `mitigate` and add two controls. Run again.
3. Fix R-04: name an insurer, set `transfer_reduces` to 1, add a `bcp_ref`. Notice residual stays MEDIUM: transfer does not make ransomware go away.
4. Add a `threat-landscape` risk (for example a credential-stuffing wave) to close the coverage gap.
5. Change `TODAY` in `demo.py` to 2027-04-01 and watch R-06 in the governed register expire.

## Run

```text
.venv/Scripts/python appsec-course/03-risk-management-and-threat-modeling-overview/labs/risk-register/demo.py
.venv/Scripts/python -m pytest appsec-course/03-risk-management-and-threat-modeling-overview/labs/risk-register -q -p no:cacheprovider
```

## Real output (from demo.py)

```text
=== register_spreadsheet.json (as of 2026-11-19) ===
| ID | Source | Treatment | Inherent | Residual | Issues |
|---|---|---|---|---|---|
| R-01 | compliance | accept | 20 CRITICAL | 20 CRITICAL | ACCEPT_WITHOUT_REASON, ACCEPT_WITHOUT_REVIEW_DATE, ACCEPTED_WITHOUT_AUTHORITY |
| R-02 | design | mitigate | 16 HIGH | 16 HIGH | MITIGATE_WITHOUT_CONTROL, RESIDUAL_ABOVE_APPETITE |
| R-03 | vulnerability | mitigate | 12 HIGH | 12 HIGH | NO_OWNER, CONTROL_WITH_NO_EFFECT, RESIDUAL_ABOVE_APPETITE |
| R-05 | design | avoid | 12 HIGH | 12 HIGH | AVOID_WITHOUT_CHANGE, RESIDUAL_ABOVE_APPETITE |
| R-04 | vulnerability | transfer | 10 HIGH | 10 HIGH | TRANSFER_WITHOUT_PARTY, TRANSFER_OVERCLAIMED, RESIDUAL_ABOVE_APPETITE, NO_CONTINUITY_PLAN |

Identification sources missing: threat-landscape
Gate: FAIL (appetite = residual 9)

=== register_governed.json (as of 2026-11-19) ===
| ID | Source | Treatment | Inherent | Residual | Issues |
|---|---|---|---|---|---|
| R-01 | compliance | mitigate | 20 CRITICAL | 3 LOW | ok |
| R-02 | design | mitigate | 16 HIGH | 4 LOW | ok |
| R-03 | vulnerability | mitigate | 12 HIGH | 4 LOW | ok |
| R-05 | design | avoid | 12 HIGH | 0 NONE | ok |
| R-04 | vulnerability | transfer | 10 HIGH | 8 MEDIUM | ok |
| R-06 | threat-landscape | accept | 9 MEDIUM | 9 MEDIUM | ok |

Identification sources missing: none
Gate: PASS (appetite = residual 9)

Treatment suggestions (heuristic, a reviewer still decides):
  likelihood 2, impact 2, optional activity=False: accept
  likelihood 4, impact 4, optional activity=True: avoid
  likelihood 2, impact 5, optional activity=False: transfer
  likelihood 4, impact 4, optional activity=False: mitigate
```

## Run the real tool (hedged)

There is no single "real tool": registers live in GRC platforms (ServiceNow IRM, Archer, OneTrust, Drata, Vanta), Jira projects or a spreadsheet. Whatever you use, configure the same rules: mandatory owner, treatment-specific evidence fields, approval workflow by risk level, review-date reminders. Check your platform's documentation for field and workflow names (verify at source).

## What you learned

- Each treatment needs different evidence; "accepted" with no owner, reason or date is ignoring.
- Transfer moves money, not accountability.
- Avoidance is the only treatment that removes a risk completely.
- Critical services need a continuity plan next to the risk decision.
