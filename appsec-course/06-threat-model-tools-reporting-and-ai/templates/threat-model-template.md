# Threat model: <system name>

> Copy this file next to the code (for example `threatmodel/README.md`). Generate the tables from your tool where you can; keep the decisions and assumptions here under review. Use fictional data when practising.

| Field | Value |
|---|---|
| System and version | <name> <version or commit> |
| Owner (tech lead) | <name> |
| Security reviewer / champion | <name> |
| Method | STRIDE per element (+ LINDDUN if personal data) |
| Rating method | OWASP Risk Rating / CVSS v4.0 / bug bar (pick one) |
| Last reviewed | <YYYY-MM-DD> for version <x.y> |
| Next review | <YYYY-MM-DD> or on change trigger |

## 1. Scope

- In scope: <components, flows>
- Out of scope (with reason): <component: reason>

## 2. Diagram

<Generated DFD (pytm `--dfd`, Threat Dragon export, Mermaid). Mark trust boundaries.>

## 3. Assets and data

| Asset / data | Classification | Where stored | Notes |
|---|---|---|---|
| | | | |

## 4. Assumptions

| Id | Assumption | Verified by | If false |
|---|---|---|---|
| A1 | <the IdP enforces MFA for admins> | <config check / test id> | <threat T? becomes High> |

## 5. Threats and decisions

| Id | Element / flow | STRIDE | Threat | Rating | Decision | Mitigation | Ticket | Test |
|---|---|---|---|---|---|---|---|---|
| T1 | | | | | mitigate / accept / transfer / avoid | | | |

## 6. Accepted and transferred risks

| Threat | Owner | Approved by | Reason | Compensating controls | Expires |
|---|---|---|---|---|---|
| | | | | | |

## 7. Validation (are we done for this version?)

- [ ] Model matches the deployed inventory and observed flows
- [ ] Every threat has a valid decision
- [ ] Every mitigation has a passing test
- [ ] Reviewed for this version; next review date set

## 8. Change log

| Date | Change | By |
|---|---|---|
| | | |

## 9. AI assistance (if used)

| Tool and model | What it drafted | Reviewed by | Data sent (redacted?) |
|---|---|---|---|
| | | | |
