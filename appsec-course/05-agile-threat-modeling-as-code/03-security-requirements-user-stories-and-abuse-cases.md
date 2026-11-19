# Lesson 03: Security Requirements, User Stories and Abuse Cases (and BDD Security)

**Syllabus items covered:** [CTMP 3] "Security Requirements as Code With BDD Security", "Writing Security Requirements for Agile Software Development", "Writing Use Cases and Abuse Cases", "Writing Requirements in Threat Modeling".

**Time:** 1.5 hours plus lab. **Safety:** all systems are fictional.

> **DBA analogy.** A requirement nobody tests is like a constraint created with `DISABLE NOVALIDATE`: it exists in the data dictionary but enforces nothing. A security requirement "as code" is an enabled, validated constraint: the build fails when it is broken.

## 1. Writing security requirements for agile software development

In agile teams requirements are **user stories** with **acceptance criteria**, not a 100-page specification. Security requirements take three forms:

| Form | Example | Where it lives |
|---|---|---|
| **Security user story** (a feature the user or security team needs) | "As a security champion, I want reset requests rate limited per IP and per account so that tokens cannot be brute forced" | Product Backlog item |
| **Security acceptance criterion** on a normal story (`SEC:`) | "SEC: the reset token is single-use, at least 128 random bits and expires in 15 minutes" | Inside the story |
| **Constraint / non-functional requirement** (applies to every story) | "All endpoints require authentication unless listed as public"; "TLS 1.2+ on every external flow" | Definition of Done, team standards, ASVS level |

Good security requirements are:

- **Specific and testable:** "passwords at least 15 characters when used alone (NIST SP 800-63B-4; verify), checked against a breached-password list" instead of "strong passwords".
- **Traceable:** each has an id and points to the threat it answers and to an ASVS requirement (ASVS 5.0 renumbered its requirements; keep your own id and map it).
- **Written with the team** at refinement or Sprint Planning, sized like any other work.
- **INVEST-friendly:** independent, negotiable, valuable, estimable, small, testable.

Sources: **OWASP ASVS 5.0** (pick a level: L1 baseline, L2 for most apps with sensitive data, L3 for critical), OWASP Proactive Controls, the threat model, compliance (PCI DSS, privacy law), and incidents.

## 2. Use cases and abuse cases

A **use case** describes how a legitimate actor uses the system to reach a goal. An **abuse case** (also called a **misuse case**) describes how an attacker misuses the same feature. Writing them side by side makes developers think like an attacker for the one feature they are building.

| | Use case / user story | Abuse case |
|---|---|---|
| Actor | Customer, admin, partner system | Attacker, fraudster, malicious insider, bot |
| Template | As a customer, I want to download my orders as CSV so that I can do my taxes | As an attacker, I want to change the customer id in the export URL so that I can download other customers' orders |
| Result | Feature and acceptance criteria | Threat (STRIDE category), mitigation story, and a test |
| Test | "CSV has one row per order" | Given I am logged in as "mallory", When I request the export for "alice", Then the response status is 403 |

A good abuse case:

1. is written **from the attacker's point of view** (otherwise it is just a negative test);
2. names the **story it threatens** and a **STRIDE** category;
3. links to the **story or criterion that mitigates it**;
4. has **Given / When / Then** that describe the **defense**, so it becomes an automated test.

Ideas for abuse cases: the OWASP Top 10 and API Security Top 10 (2023), OWASP Cornucopia and Elevation of Privilege cards, CAPEC, and your own incident history. Misuse case diagrams (UML as code) are in [Lesson 02 section 3](02-threat-modeling-as-code-pytm-and-diagrams.md#3-diagrams-as-code-and-uml-as-code).

## 3. Writing requirements in threat modeling

The threat model is the main **source** of security requirements. Every finding should end as one of: a requirement (and test), an accepted risk (with owner and date), or "not applicable" (with a reason).

```text
Threat (model)          ->  Requirement (backlog)      ->  Test (BDD / unit / DAST)     ->  Evidence (CI)
DF01 login over HTTP        REQ-TLS-01 TLS 1.2+ on         "login redirects to HTTPS,       green build,
                            every boundary flow            HSTS present"                   report artifact
```

In the [pytm-lite lab](labs/pytm-lite/README.md) each threat rule carries a `requirement` id, so `tm.requirements()` turns findings straight into a backlog checklist. In the DevSecOps course the [requirements-as-code lab](../../devsecops-course/03-security-requirements-and-threat-modeling/labs/security-requirements-as-code/README.md) shows the next step: a requirement catalog where every requirement names an automated check, and a gate that fails on `NO_TEST`.

## 4. Security requirements as code with BDD security

**BDD (behaviour-driven development)** writes requirements as Gherkin scenarios (`Given`, `When`, `Then`) that run as tests. For security this means **abuse cases that execute on every build**:

```gherkin
@threat-AB-2 @information-disclosure
Scenario: AB-2 is blocked (US-2)
  Given I am logged in as "mallory"
  When I request the CSV export for customer "alice"
  Then the response status is 403
```

- The original **BDD-Security** project (Continuum Security, later IriusRisk) and **Gauntlt** look unmaintained (verify). Use **pytest-bdd**, **behave**, **Cucumber** or ZAP Automation Framework tests.
- The DevSecOps course has the full runner, steps and simulated app: [BDD security lab](../../devsecops-course/03-security-requirements-and-threat-modeling/labs/bdd-security-threats/README.md) and [its lesson](../../devsecops-course/03-security-requirements-and-threat-modeling/02-threat-modeling-tools-and-ci-cd.md#4-bdd-security-codifying-threats-as-executable-specs). This chapter does not rebuild it.
- What is new here: the [agile-security-stories lab](labs/agile-security-stories/README.md) **generates** Gherkin from the abuse cases in the backlog, tagged with the threat id, so the chain backlog → scenario → test result is automatic.

## 5. Scenario: "strong passwords" that were not

A bank's story said "users must have strong passwords". Developers added a rule: 8 characters, one digit, one symbol, change every 90 days. Users chose `Summer2026!`. The pen test cracked 30% of accounts with a seasonal word list. In the retrospective the team rewrote it as testable criteria: "SEC: at least 15 characters if no MFA, 8 with MFA; no composition rules; reject passwords found in the breached-password list; no forced rotation" (NIST SP 800-63B-4, verify), plus the abuse case "As an attacker, I want to spray common passwords so that I can log in", with a rate-limit test. Vague requirement, vague result; testable requirement, testable result.

## 6. Common mistakes

- "The system shall be secure." Not testable.
- Abuse cases written from the user's view ("as a customer I want to enter a wrong password"). That is a negative test, not an attacker's goal.
- Security requirements kept in a separate document the team never opens.
- BDD scenarios that only check the happy path, or steps that pass without asserting anything.
- No link from requirement back to the threat: nobody knows why it exists, so it gets deleted.

## 7. Checklist

- [ ] I can write a security user story, a `SEC:` acceptance criterion and a team-wide constraint.
- [ ] I can write an abuse case with STRIDE, mitigation and Given/When/Then.
- [ ] I can trace threat → requirement → test → evidence.
- [ ] I know BDD-Security is legacy and which tools replace it.

## References

- OWASP ASVS 5.0 (verify version), OWASP Proactive Controls, OWASP Cornucopia.
- G. Sindre and A. L. Opdahl, misuse cases (2005); J. McDermott and C. Fox, abuse cases (1999).
- Cucumber Gherkin reference; pytest-bdd and behave documentation.
- Repo: [devsecops-course lesson 03 requirements as code](../../devsecops-course/03-security-requirements-and-threat-modeling/03-security-requirements-as-code.md).
