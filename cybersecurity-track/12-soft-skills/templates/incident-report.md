# Incident report template

> Copy this file for each incident. Use UTC for all times. Write facts first. Mark guesses as guesses. Never paste real passwords, tokens or personal data into a report; refer to where the evidence is stored.

**Incident ID:** INC-YYYY-NNNN  **Severity:** (Sev 1 / 2 / 3 / 4)  **Status:** (Open / Contained / Resolved / Closed)
**Reporter / author:** _name_  **Incident lead:** _name_  **Report version / date:** _v1, YYYY-MM-DD HH:MM UTC_

## 1. Summary (3 to 5 lines, for a non-technical reader)

- **What happened:** _one sentence_
- **Impact:** _who or what was affected, how many users/records/systems, business impact_
- **Current status:** _contained? still happening? next update at HH:MM_
- **Decision needed from leadership (if any):** _none / what, by when_

## 2. Detection

| Item | Detail |
|---|---|
| How it was detected | _SIEM alert / EDR / user report / third party_ |
| Detection time (UTC) | |
| Alert or ticket reference | |
| Time to detect (from first malicious activity, if known) | |

## 3. Timeline (facts only)

| Time (UTC) | Event | Source / evidence | Who |
|---|---|---|---|
| | | _log name, query, screenshot ID_ | |

## 4. Scope and impact

- **Systems / accounts / data affected:**
- **Data types involved (not the data itself):** _e.g. employee emails, no payment data_
- **Confirmed vs suspected:** _list separately_
- **Legal or regulatory angle (for legal/privacy team to decide):**

## 5. Analysis

- **Attack path / root cause (what we know):**
- **What we do not know yet:**
- **MITRE ATT&CK techniques observed (optional):**
- **Indicators (IPs, domains, hashes; use defanged form like hxxp://bad[.]example):**

## 6. Response actions

| Time (UTC) | Action (contain / eradicate / recover) | Done by | Result |
|---|---|---|---|

## 7. Follow-up actions

| Action | Owner | Due date | Status |
|---|---|---|---|

## 8. Lessons learned (blameless; fill in at the review)

- What worked well:
- What slowed us down:
- What we change (process, tooling, detection, training):

## 9. Evidence list

| ID | Description | Location | Collected by / time | Hash (if file) |
|---|---|---|---|---|

---

### Case-note one-liner format (for tickets)

`[UTC time] [analyst] OBSERVED: ... | CHECKED: ... | CONCLUSION: ... | NEXT: ...`

Example: `[2026-11-16 03:40Z] [asha] OBSERVED: 4,000 failed sign-ins for 900 accounts from 198.51.100.7 | CHECKED: no success except user ben | CONCLUSION: likely password spraying, ben at risk | NEXT: revoke ben's sessions, block IP, check ben's mailbox rules`
