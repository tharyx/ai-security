# Lesson 01: OWASP ASVS for APIs

**Syllabus items covered:** "OWASP ASVS Framework", "Understanding OWASP ASVS", "Using ASVS To Secure Applications and APIs", "Creating Checklists With OWASP ASVS" ([CASP 9]).

**Time:** 45 minutes (plus chapter 02 if you have not done it). **Lab:** [api-asvs-at-scale](labs/api-asvs-at-scale/README.md).

> **Already taught in chapter 02.** The Security Champion course covers the same four ASVS lines. The full lesson (levels, the 17 chapters of ASVS 5.0, requirement ids, how to build a checklist) is [chapter 02 lesson 03](../02-secure-code-review-and-asvs/03-owasp-asvs.md), with the [asvs-checklist-generator lab](../02-secure-code-review-and-asvs/labs/asvs-checklist-generator/README.md). This lesson gives a short summary and adds only the **API** and **DevSecOps** angle.

## 1. OWASP ASVS framework in five sentences

The **Application Security Verification Standard** is OWASP's catalogue of testable security requirements for web applications and APIs. **Version 5.0.0** was released in May 2025 (verify at the OWASP ASVS project page). It has three **levels**: L1 baseline for all apps, L2 for apps with sensitive data (the usual target), L3 for critical systems. Requirements are grouped in **chapters** (V1 Encoding and Sanitization to V17 WebRTC in 5.0) and identified as `chapter.section.requirement`. Ids changed between 4.0.3 and 5.0, so keep **your own stable ids** and map them to the ASVS id and version.

## 2. Understanding OWASP ASVS from an API point of view

The chapters an API team reads first (5.0 names; verify):

| ASVS 5.0 chapter | API topics | Course chapter |
|---|---|---|
| V4 API and Web Service | HTTP methods, content types, GraphQL limits, SOAP/XML, WebSockets, webhooks | [14](../14-api-defenses-data-security-and-headers/README.md) |
| V2 Validation and Business Logic | Schema validation, anti-automation, business flows | [12](../12-input-validation-and-injection/README.md), [15](../15-implementing-api-security-mechanisms/README.md) |
| V6 Authentication, V7 Session Management | Credentials, MFA, sessions | [10](../10-api-authentication/README.md) |
| V8 Authorization | Function, object and property level | [11](../11-api-authorization-and-oauth/README.md) |
| V9 Self-contained Tokens, V10 OAuth and OIDC | JWT validation, OAuth flows, token lifetimes | [10](../10-api-authentication/README.md), [11](../11-api-authorization-and-oauth/README.md) |
| V11 Cryptography, V12 Secure Communication, V14 Data Protection | TLS, encryption, data minimisation, caching | [14](../14-api-defenses-data-security-and-headers/README.md), [15](../15-implementing-api-security-mechanisms/README.md) |
| V13 Configuration, V15 Secure Coding and Architecture | Dependencies, secrets, inventory, architecture | this chapter |
| V16 Security Logging and Error Handling | Security events, no secrets in logs | [15](../15-implementing-api-security-mechanisms/README.md) |

ASVS and the **OWASP API Security Top 10** answer different questions: the Top 10 lists the most common **risks**; ASVS lists what to **verify**. Map each Top 10 item to ASVS requirements and to tests.

## 3. Using ASVS to secure applications and APIs

Use ASVS at every stage, not only at the end:

- **Requirements:** pick a level per API and turn the relevant items into user stories and acceptance criteria.
- **Design:** use the architecture items in threat-model reviews (chapters 03 to 05).
- **Build:** link each requirement to an automated check (SAST rule, unit or integration test).
- **Test:** DAST and manual testing cover what automation cannot (business logic, authorization matrices).
- **Release:** the pipeline gate uses the checklist status (lab).
- **Procurement and pentests:** ask vendors and testers to report against ASVS ids.

## 4. Creating checklists with OWASP ASVS

The method is in chapter 02. For **many APIs** add:

1. A **feature profile** per API (JWT, OAuth, GraphQL, SOAP, webhooks, file upload, public) so each gets only relevant items.
2. A **verification method** per requirement (`sast:rule`, `sca:policy`, `dast:alert`, `test:name`, `manual`).
3. **Evidence collected by the pipeline**, not typed by hand; manual items need a record (ticket, review date).
4. A **portfolio view** (coverage %, failing items) for the champion and for management.

## 5. Scenario: the pentest report nobody could map

An external pentest of a banking API returns 40 findings in the tester's own format. The team cannot tell which internal controls failed, or whether the same issue exists in the other nine APIs. For the next test the champion sends the tester the API's ASVS L2 checklist and asks for findings by ASVS id. Each finding now maps to a requirement, to the automated check that should have caught it (and did not), and to every other API with the same requirement. Three new SAST rules and two integration tests come out of it.

## 6. Checklist

- [ ] I can summarise ASVS (purpose, version, levels, chapters, ids) in five sentences.
- [ ] I can name the ASVS chapters most relevant to APIs.
- [ ] I can explain how ASVS is used at each SDLC stage.
- [ ] I can extend a checklist with verification methods and pipeline evidence.

## References

- OWASP ASVS 5.0.0 (the GitHub releases include CSV/JSON exports; verify).
- OWASP API Security Top 10 2023; OWASP Proactive Controls.
- Repo: [chapter 02 lesson 03](../02-secure-code-review-and-asvs/03-owasp-asvs.md), [devsecops ch03 requirements as code](../../devsecops-course/03-security-requirements-and-threat-modeling/03-security-requirements-as-code.md).
