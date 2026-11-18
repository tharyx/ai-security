# AI Risk Management Policy

| Field | Value |
|---|---|
| Policy ID | POL-AI-02 |
| Version | 1.0 |
| Owner | Chief Risk Officer |
| Approved by | AI Governance Board |
| Effective | 2026-11-01 |
| Next review | 2027-11-01 |
| Status | Template: adapt to your organization before use |

## 1. Purpose

Make sure every AI system's risks are found, scored, treated and owned in the same way, and that nobody accepts a risk they are not allowed to accept.

## 2. Scope

Every AI system in the AI system register (built, bought, or embedded in SaaS), for its whole life: intake, design, release, operation, change and retirement. It covers security, privacy, safety, fairness, reliability, legal, third-party and misuse risks.

## 3. Roles

| Role | Responsibility |
|---|---|
| Business owner | Accountable for the system's risks; accepts Low and Medium residual risk |
| Technical owner | Runs the assessment; implements controls; collects evidence |
| AI Governance Office | Owns the method and the risk register; challenges scores (2nd line) |
| CISO | Accepts High residual security risk; can block a release |
| AI Governance Board | Sets the AI risk appetite; accepts Critical residual risk |
| Internal audit | Tests that the process works (3rd line) |

## 4. Requirements

| ID | Requirement | How we check (evidence) |
|---|---|---|
| RMP-01 | Every registered AI system has a risk tier computed from written rules, not a self-declared tier. | Register export; tier-gaming finding GOV-04 is zero |
| RMP-02 | High and critical systems have at least one owned entry in the AI risk register before release. | Release gate finding GOV-08; risk register export |
| RMP-03 | Risks are identified from catalogs: OWASP Top 10 for LLM Applications 2026, OWASP Top 10 for Agentic Applications, OWASP MCP Top 10 (when MCP is used), MITRE ATLAS and NIST AI 600-1. | Assessment worksheet shows the catalog IDs |
| RMP-04 | Each risk records likelihood (1-5), impact (1-5), inherent score, controls with their state (planned, implemented, tested) and residual score. | Risk register schema check (lab `risk_register.py`, RISK-06) |
| RMP-05 | Only tested controls get full credit; planned controls get none. | Scorer output; RISK-05 finding is zero |
| RMP-06 | Residual risk above appetite (score above 9) needs a treatment plan with owner and date, or a valid acceptance. | RISK-03 finding is zero |
| RMP-07 | Acceptance follows the authority table (Low: owner; Medium: system owner, CISO or board; High: CISO or board; Critical: board) and expires within 12 months. | RISK-04 finding is zero; acceptance records |
| RMP-08 | Risks are re-assessed on any material change (model or version, data source, tool, user group, purpose, region) and at least every 6 months for high and critical systems. | Change tickets linked to risk reviews; GOV-06 overdue finding |
| RMP-09 | Third-party AI risks are assessed with the AI Third-Party Risk Assessment before contract and every year. | Vendor assessment evidence (CTL-VEND) |
| RMP-10 | The board receives a quarterly AI risk report: systems by tier, top residual risks, risks above appetite, expiring acceptances, incidents. | Board pack and minutes |

## 5. Exceptions

A risk is never "excepted"; it is treated or accepted. Process deviations (for example a late re-assessment) need approval by the CRO, are time-limited and are reported to the board.

## 6. Review cycle

Every year, after any Critical incident, and when NIST, ISO or a regulator publishes a relevant update (for example the announced revision of the NIST AI RMF).

## 7. Framework mapping

| Requirement | NIST AI RMF | ISO/IEC 42001 | Other |
|---|---|---|---|
| RMP-01, RMP-02 | MAP 1.1, MAP 1.5, GOVERN 1.6 | Clause 6.1.2, 8.2 | CERT-In AI Security Auditing Guidelines, section 5 (risk tiering) |
| RMP-03 | MAP 4.1, MAP 5.1 | Clause 6.1.2 | ISO/IEC 23894 (risk identification) |
| RMP-04, RMP-05 | MEASURE 1.1, MEASURE 3.1 | Clause 6.1.2, 8.2 | |
| RMP-06, RMP-07 | MANAGE 1.3, GOVERN 1.4 | Clause 6.1.3, 8.3 | EU AI Act Art 9 |
| RMP-08 | GOVERN 1.5, MANAGE 4.1 | Clause 8.2, 9.1 | |
| RMP-09 | GOVERN 6.1, MANAGE 3.1 | Annex A.10 (third-party relationships) | |
| RMP-10 | GOVERN 2.3 | Clause 9.3 (management review) | |
