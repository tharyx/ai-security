# AI Incident Response Policy

| Field | Value |
|---|---|
| Policy ID | POL-AI-06 |
| Version | 1.0 |
| Owner | Head of Security Operations |
| Approved by | AI Governance Board |
| Effective | 2026-11-01 |
| Next review | 2027-11-01 |
| Status | Template: adapt to your organization before use |

## 1. Purpose

Detect, contain, investigate, report and learn from AI incidents quickly, and never miss a legal reporting deadline. This policy extends the general security incident response plan; it does not replace it.

## 2. Scope

Any event where an AI system causes or could cause harm: security attacks (prompt injection, poisoning, model or key theft, agent misuse), data leaks through AI, harmful or false output, biased or wrong decisions about people, model failure or drift, and data uploaded to unapproved AI tools. Near misses are in scope and are recorded.

## 3. Roles

| Role | Responsibility |
|---|---|
| Anyone | Reports a suspected AI incident (AUP-08) |
| SOC analyst | Triages, sets the first severity, starts containment |
| Incident commander | Leads SEV1 and SEV2 incidents; owns communication |
| System owner | Makes business decisions (pause, fall back to the manual process) |
| DPO and legal | Decide on regulatory and personal notifications; own the clocks |
| AI engineering | Rolls back models, rebuilds indexes, fixes guardrails |

## 4. Requirements

| ID | Requirement | How we check (evidence) |
|---|---|---|
| AIR-01 | AI incidents are classified by category and severity (SEV1 to SEV4) using the triage rules. Severity follows real impact (data, privilege, actions, people harmed, scale), not whether AI was involved. | Triage record (lab `incident_triage.py`) |
| AIR-02 | Severity is lowered only after containment is verified, not when it was requested. | Incident timeline shows verification before downgrade |
| AIR-03 | Every high-tier AI system has a kill switch or degrade mode (tools off, read-only, human-only) that the on-call team can use in under 15 minutes, tested every 6 months. | Kill-switch test record |
| AIR-04 | Evidence is preserved before changes: prompts and outputs, retrieved document IDs, tool-call log, model version and hash, index version, agent memory snapshot. | Evidence checklist in the ticket |
| AIR-05 | Legal clocks start at awareness and are tracked from the first hour: CERT-In (6 hours for reportable incidents in India), GDPR Art 33 (72 hours), EU AI Act Art 73 (serious incidents, by provider), DPDP Act and Rules. | Clock table in the ticket (Module 08 `incident_clock.py`) |
| AIR-06 | SEV1 and SEV2 incidents are reported to the system owner, CISO, DPO and legal within 1 hour of classification. | Notification timestamps |
| AIR-07 | Affected people are told when the law requires it, or when they need to act to protect themselves. | Communication records |
| AIR-08 | Recovery returns to a known-good state: last approved model hash, clean index snapshot, rotated keys. | Recovery record; `can_deploy` log |
| AIR-09 | Every SEV1 and SEV2 incident has a blameless review within 10 working days, with root cause, new regression tests and updates to the risk register. | Post-incident report; new test IDs; risk entries |
| AIR-10 | An AI incident tabletop exercise runs at least once a year. | Tabletop report (CTL-IR evidence) |
| AIR-11 | System logs needed for investigation are kept at least 180 days (CERT-In expects this for systems in India) and protected from change. | Log retention config and test |

## 5. Exceptions

None for AIR-05 (legal deadlines). Other requirements may be adjusted for a specific system by the CISO, recorded and time-limited.

## 6. Review cycle

Every year, after every SEV1 incident, and after each tabletop exercise.

## 7. Framework mapping

| Requirement | NIST AI RMF | ISO/IEC 42001 | Other |
|---|---|---|---|
| AIR-01, AIR-02 | MANAGE 2.3, MANAGE 4.3 | Clause 10.2 (nonconformity and corrective action) | OWASP LLM Top 10 2026 and OWASP Agentic Top 10 as categories |
| AIR-03, AIR-08 | MANAGE 2.4 | Annex A.6 (operation and monitoring) | |
| AIR-04, AIR-11 | MEASURE 2.8 | Annex A.6 (event logs) | EU AI Act Art 12 and 26(6); CERT-In Directions (28 April 2022) |
| AIR-05, AIR-06, AIR-07 | MANAGE 4.3, GOVERN 4.3 | Annex A.8 (communication of incidents) | EU AI Act Art 73; GDPR Art 33-34; DPDP Act s.8(6); CERT-In AI audit guideline 8.6 |
| AIR-09 | MANAGE 4.1, MEASURE 3.1 | Clause 10.2 | |
| AIR-10 | GOVERN 4.3 | Clause 9.1 | |
