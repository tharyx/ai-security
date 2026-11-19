# Lesson 06: Worked Example: Threat Modeling a Password Reset Workflow

**Syllabus items covered:** [CTMP 2] "Threat Modeling a Password Reset Workflow"; [CSC 4] "Threat modeling for a Password Reset workflow" (and it uses "Creating Data Flow Diagrams", "Writing Security Requirements for Threat Modeling" and OWASP risk rating from the earlier lessons).

**Time:** 90 minutes. **Labs:** [password-reset-threat-model](labs/password-reset-threat-model/README.md), [dfd-stride](labs/dfd-stride/README.md), [threat-rating](labs/threat-rating/README.md).

Password reset is the favourite course example because it is small, every application has one, and it is a **second login door** that is often weaker than the first.

## 1. What are we working on?

Flow: the user enters an email at `/forgot`; the service creates a token and emails a link; the user opens the link and sets a new password at `/reset`. The level-1 DFD (from [lesson 01, section 4](01-security-requirements-and-diagramming.md#4-creating-a-data-flow-diagram-step-by-step)) has: user and email provider (external), reset service (process), users DB, token cache and audit log (stores), and flows F1 to F8. Trust boundaries: internet, third party, app, data.

Run `demo.py` in the [dfd-stride lab](labs/dfd-stride/README.md) to see the Mermaid diagram and the 44 STRIDE-per-element candidates.

## 2. What can go wrong? (STRIDE)

| # | STRIDE | Threat | Where |
|---|---|---|---|
| 1 | S | Token is predictable (time, user id, weak random) | Token generation |
| 2 | I | Response reveals whether an email has an account | F1 / response F8 |
| 3 | T | Host header (or `X-Forwarded-Host`) controls the link domain, so the link goes to the attacker | Link building |
| 4 | S | Token can be used twice | `/reset` |
| 5 | S | Token never expires; an old email in a breached mailbox works | Token store |
| 6 | I | Tokens stored in clear: a DB dump or backup gives working links | Token store |
| 7 | I | Tokens or links written to logs or analytics, or leaked via `Referer` | Logs, page |
| 8 | E | Existing sessions (including the attacker's) survive the reset | Session store |
| 9 | S | New password can be trivial | `/reset` |
| 10 | D | Unlimited reset emails (mail bombing, cost, provider blocklisting) | F1, F3 |
| 11 | R | No audit trail of resets | Audit log |

Extra threats to discuss (not in the lab): security questions as a reset method (weak, avoid), resetting via SMS (SIM swap), the email account itself being compromised (consider MFA re-check after reset), and the reset page being framed (clickjacking).

## 3. What are we going to do about it? (requirements)

Each threat becomes a testable requirement. The lab implements all eleven as code: SR-01 CSPRNG tokens, SR-02 uniform response, SR-03 fixed base URL, SR-04 single use, SR-05 15-minute expiry, SR-06 hash at rest, SR-07 no tokens in logs, SR-08 revoke sessions, SR-09 length + blocklist (NIST SP 800-63B-4: at least 15 characters for single-factor passwords; verify at source), SR-10 three emails per account per hour, SR-11 audit event. Also follow the OWASP Forgot Password Cheat Sheet.

**DBA analogy:** storing only `SHA-256(token)` is like storing password hashes instead of passwords in `USER$`: a dump of the table does not give you working credentials.

## 4. Rate them

Using the OWASP Risk Rating worked example from [lesson 05, section 3.1](05-threat-rating.md#31-worked-example-risk-rating-with-the-owasp-risk-rating-methodology): the predictable token is **HIGH** before the fix and **MEDIUM** after it. User enumeration is usually MEDIUM; host header poisoning HIGH (full account takeover with one click by the victim). The [threat-rating lab](labs/threat-rating/README.md) has a Rapid Risk Assessment for the same service.

## 5. Did we do a good job?

- Every threat has a requirement, every requirement has a test, the tests run in CI.
- The vulnerable implementation fails all 11; the secure one passes all 11 (run `demo.py` in the lab).
- Re-model when the flow changes (adding SMS reset, a mobile deep link, SSO).

## 6. Scenario: one click from the victim

A pentester sends `POST /forgot` for the victim with `Host: attacker.example`. The application builds the email link from the Host header; the victim receives a genuine email from the real company, clicks, and the token arrives at the attacker's server. The attacker then resets the password. Fix: SR-03 (configured base URL) plus SR-05 (short expiry) and SR-08 (revoke sessions).

## 7. Modern threat modeling for Agile and DevOps, applied

This whole lesson is one feature-sized model: one DFD, one STRIDE pass, eleven requirements and tests in the repo. That is the "model the delta" approach from [chapter 03 lesson 02, section 9](../03-risk-management-and-threat-modeling-overview/02-threat-modeling-overview.md#9-modern-threat-modeling-approaches-for-agile-and-devops); chapter 05 of this course turns models into code (pytm-style).
