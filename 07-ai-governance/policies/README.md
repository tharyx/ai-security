# AI Policy Pack (templates)

Seven short, practical templates you can adapt for your capstone organization or a real job. Each one has the same parts, so an auditor (or the linter) can check it:

**Header** (ID, version, owner, approver, effective date, next review) · **1. Purpose** · **2. Scope** · **3. Roles** · **4. Requirements** (numbered and testable, each with "how we check") · **5. Exceptions** · **6. Review cycle** · **7. Framework mapping** (NIST AI RMF and ISO/IEC 42001, plus laws and OWASP where useful).

| # | Template | What it decides | Main lab link |
|---|---|---|---|
| 01 | [AI Acceptable Use Policy](01-ai-acceptable-use-policy.md) | What staff may do with AI tools and which data may go where | Shadow-AI discovery, disclosure checks (TR-01/02) |
| 02 | [AI Risk Management Policy](02-ai-risk-management-policy.md) | How risks are tiered, scored, treated and accepted, and by whom | `secure_register.py`, `risk_register.py` |
| 03 | [AI Model Approval Policy](03-ai-model-approval-policy.md) | Gates for approving a model *version*; pinning; expiry; deploy check | `model_approval.py` |
| 04 | [AI Data Governance Policy](04-ai-data-governance-policy.md) | Datasheets, lawful basis, label propagation, lineage, retention, erasure | `doc_validator.py`; Module 08 `privacy_rights.py` |
| 05 | [AI Third-Party Risk Assessment](05-ai-third-party-risk-assessment.md) | Vendor tiers, the 14-question questionnaire, contract clauses | Module 08 evidence checker (CTL-VEND) |
| 06 | [AI Incident Response Policy](06-ai-incident-response-policy.md) | Severity, kill switch, evidence, legal clocks, lessons learned | `incident_triage.py`; Module 08 `incident_clock.py` |
| 07 | [AI Security Standard](07-ai-security-standard.md) | 15 technical controls by tier, mapped to OWASP LLM / Agentic / MCP Top 10 | Modules 02-06 labs |

## How the pack fits together

```text
AI policy (principles, board-approved)            <- one page, not included: write your own
 ├─ 01 Acceptable Use          (every employee)
 ├─ 02 Risk Management         (how we decide)
 │    ├─ 03 Model Approval     (gate for models and versions)
 │    ├─ 04 Data Governance    (gate for data)
 │    └─ 05 Third-Party Risk   (gate for vendors)
 ├─ 06 Incident Response       (when things go wrong)
 └─ 07 AI Security Standard    (the technical controls everything above relies on)
```

## Check the pack like code

```powershell
python 07-ai-governance/lab/policy_lint.py 07-ai-governance/policies
```

Expected output (as of 2026-11-15):

```text
01-ai-acceptable-use-policy.md                 9 requirements  OK
02-ai-risk-management-policy.md               10 requirements  OK
03-ai-model-approval-policy.md                12 requirements  OK
04-ai-data-governance-policy.md               10 requirements  OK
05-ai-third-party-risk-assessment.md           9 requirements  OK
06-ai-incident-response-policy.md             11 requirements  OK
07-ai-security-standard.md                    15 requirements  OK
```

Break it yourself: delete the "How we check" text of one requirement, or set a "Next review" date in the past, and run the linter again (POL-04, POL-05).

## Rules for adapting them

1. Keep each policy short. If a requirement cannot be checked, rewrite it until it can.
2. Put the technical "how" in the standard (07), not in every policy.
3. Every requirement needs an owner who can say "here is the evidence".
4. Templates, not legal advice. Laws and standards cited here change; verify them at the source and record the date you checked.
