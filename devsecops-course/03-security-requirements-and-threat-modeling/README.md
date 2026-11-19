# Chapter 03: Security Requirements and Threat Modeling

This chapter covers the **Requirements** and **Design** steps of a secure pipeline: what threat modeling is, STRIDE versus DREAD, the classic tools and how they fit CI/CD, and then three labs that turn requirements and threats into **code that runs on every build**: a requirements catalog with a gate, ThreatSpec-style annotations that produce a report and a diagram, and BDD (Gherkin) security scenarios. All labs run offline with fixtures and tests; no tool installation is required.

> **Safety.** Every lab is a simulation: fictional shop code that is only parsed, a simulated app function (no sockets), JSON and YAML fixtures. Nothing is scanned or attacked. Only test systems you own or have written permission to test.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Tool status and version numbers are hedged: **verify at the source**.

## Syllabus coverage

| Syllabus item | Where to study | Lab |
|---|---|---|
| [CDE 2] Security Requirements and Threat Modeling (TM) | [Lesson 01](01-threat-modeling-stride-dread-and-challenges.md), [02](02-threat-modeling-tools-and-ci-cd.md), [03](03-security-requirements-as-code.md) | all three labs |
| [CDE 2] What is Threat Modeling? | [01 section 1](01-threat-modeling-stride-dread-and-challenges.md#1-what-is-threat-modeling); repo [AI threat modeling](../../01-ai-security-fundamentals/03-ai-threat-modeling.md), [CAISP ch5](../../caisp-course/ch5-threat-modeling-ai-systems/README.md) | [threat-modeling-as-code](labs/threat-modeling-as-code/README.md) |
| [CDE 2] STRIDE vs. DREAD approaches | [01 sections 2 and 3](01-threat-modeling-stride-dread-and-challenges.md#2-stride) (SVG) | [threat-modeling-as-code](labs/threat-modeling-as-code/README.md) (STRIDE names enforced) |
| [CDE 2] Threat modeling and its challenges. | [01 section 4](01-threat-modeling-stride-dread-and-challenges.md#4-challenges-of-threat-modeling-and-what-to-do) | n/a |
| [CDE 2] Classical Threat modeling tools and how they fit in CI/CD pipeline | [02 sections 1 and 2](02-threat-modeling-tools-and-ci-cd.md#1-the-classical-tools) (SVG); [real-tools/threat-modeling-tools.md](real-tools/threat-modeling-tools.md) | [threat-modeling-as-code](labs/threat-modeling-as-code/README.md) |
| [CDE 2] Hands-on Labs: | Labs below | [Lab index](#lab-index) |
| [CDE 2] Automate security requirements as code. | [Lesson 03](03-security-requirements-as-code.md) (SVG); [real-tools/bdd-and-asvs.md](real-tools/bdd-and-asvs.md) | [security-requirements-as-code](labs/security-requirements-as-code/README.md) |
| [CDE 2] Using ThreatSpec to do Threat Modeling as Code. | [02 section 3](02-threat-modeling-tools-and-ci-cd.md#3-threat-modeling-as-code-with-annotations-the-threatspec-idea) (ThreatSpec is legacy; pytm, Threagile, Threat Dragon are current) | [threat-modeling-as-code](labs/threat-modeling-as-code/README.md) |
| [CDE 2] Using BDD security to codify threats. | [02 section 4](02-threat-modeling-tools-and-ci-cd.md#4-bdd-security-codifying-threats-as-executable-specs) | [bdd-security-threats](labs/bdd-security-threats/README.md) |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| **ThreatSpec** | Low or no development since about 2020. Teach the **threat-modeling-as-code idea** and use **OWASP pytm**, **Threagile** or **OWASP Threat Dragon** for new work. |
| **BDD security** (BDD-Security by Continuum Security, later IriusRisk) | Appears unmaintained since about 2022; Gauntlt is also old. Keep the idea (Gherkin security specs) and implement it with **pytest-bdd** or **behave**, or with **ZAP Automation Framework** tests. |
| "Security requirements" without a named catalog | Use **OWASP ASVS**; **version 5.0 was released in May 2025**. Requirement numbering differs from 4.x, so keep your own ids and map to ASVS in a field. |
| **DREAD** presented as a peer of STRIDE | DREAD is a (weak) rating scheme, little used today; STRIDE is a threat-finding checklist. Rate with CVSS, OWASP Risk Rating or an agreed likelihood-times-impact rubric. |
| **Microsoft Threat Modeling Tool** as "the classical tool" | Still a known free tool; check its current support status. Text-based models (pytm, Threagile) fit CI/CD better. |

## Learning order

1. [Lesson 01](01-threat-modeling-stride-dread-and-challenges.md): do the 15-minute shop exercise on paper. About 1.5 hours.
2. [Lesson 02](02-threat-modeling-tools-and-ci-cd.md), then the [threat-modeling-as-code lab](labs/threat-modeling-as-code/README.md) and the [real-tools notes](real-tools/threat-modeling-tools.md). About 3 hours.
3. [Lesson 03](03-security-requirements-as-code.md), then the [requirements-as-code lab](labs/security-requirements-as-code/README.md). About 2 hours.
4. The [BDD security lab](labs/bdd-security-threats/README.md) and [real-tools/bdd-and-asvs.md](real-tools/bdd-and-asvs.md). About 2 hours.
5. Then [Chapter 04: Software Component Analysis](../04-software-component-analysis/README.md).

## Lab index

All labs run offline: `.venv/Scripts/python -m pytest devsecops-course/03-security-requirements-and-threat-modeling`.

| Lab | Course exercise | Tests |
|---|---|---|
| [security-requirements-as-code](labs/security-requirements-as-code/README.md) | Automate security requirements as code | 9 |
| [threat-modeling-as-code](labs/threat-modeling-as-code/README.md) | Using ThreatSpec to do Threat Modeling as Code | 8 |
| [bdd-security-threats](labs/bdd-security-threats/README.md) | Using BDD security to codify threats | 8 |

Hedged guides for real tools: [threat modeling tools](real-tools/threat-modeling-tools.md), [BDD and ASVS](real-tools/bdd-and-asvs.md).

## How the three courses overlap here

- **CDE 2 only** owns this chapter. The **CDP** course touches the same ideas in its Secure SDLC chapter (a "Threat Modelling (Design)" step and "Security Requirements (Requirements)") and lists "Using BDD security to codify threats." again under tools: those rows live in [chapter 02](../02-tools-pipelines-and-secure-sdlc/README.md) and point back to the BDD lesson and lab here, so nothing is taught twice.
- **CCSE** does not cover threat modeling, but its supply-chain threat tables ([CSE chapter 2](../../csse-course/ch2-attacking-code-and-application-supply-chain/README.md)) are a ready-made input for a pipeline threat model.
- The repo's AI threat modeling lessons cover AI-specific methods. This chapter is the classic DevSecOps view.

## Exam tips

- **STRIDE finds, DREAD ranks.** Give the broken property for each STRIDE letter.
- **List three DREAD weaknesses:** subjective, not repeatable, discoverability rewards obscurity.
- **Threat model is a living artifact.** Say "in the repo, checked in CI".
- **A pipeline checks consistency, not completeness** of a threat model.
- **Every high threat needs a requirement, a test and evidence.**
- **A requirement with no test fails the gate** (`NO_TEST`), not silently passes.
- **ThreatSpec and BDD-Security are legacy:** name pytm, Threagile, Threat Dragon, pytest-bdd and behave as current options.
- **ASVS has three levels;** level 2 is the usual target for apps with sensitive data. Say "verify the version; 5.0 is current".

## 15 exam-style questions

<details>
<summary>1. What is threat modeling and when should you do it?</summary>

A structured way to find, rate and decide on threats to a system, using a model of the system (usually a DFD with trust boundaries). Do it at design time and again whenever the design changes (new component, data flow or trust boundary), because fixes are cheapest then.
</details>

<details>
<summary>2. Name the four questions of threat modeling.</summary>

What are we building? What can go wrong? What are we going to do about it? Did we do a good job?
</details>

<details>
<summary>3. Expand STRIDE and give the property each letter breaks.</summary>

Spoofing (authentication), Tampering (integrity), Repudiation (non-repudiation), Information disclosure (confidentiality), Denial of service (availability), Elevation of privilege (authorization).
</details>

<details>
<summary>4. How do STRIDE and DREAD differ?</summary>

STRIDE is a checklist to find threats by category. DREAD is a rating scheme (Damage, Reproducibility, Exploitability, Affected users, Discoverability). They answer different questions and are not alternatives.
</details>

<details>
<summary>5. Give three weaknesses of DREAD.</summary>

Scores are subjective and differ between raters; results are not repeatable; discoverability encourages security by obscurity; it mixes likelihood and impact in one sum; little current use. Prefer CVSS, OWASP Risk Rating or a calibrated likelihood-times-impact rubric.
</details>

<details>
<summary>6. What is a trust boundary and why does it matter?</summary>

A line in the DFD where the level of trust changes (Internet to DMZ, app to database). Data crossing it must be authenticated, validated and often encrypted. Most threats appear where a flow crosses a boundary.
</details>

<details>
<summary>7. Name five challenges of threat modeling and one remedy for each.</summary>

Skipped for time (small frequent sessions); goes stale (model in the repo, checked in CI); needs expertise (threat libraries, champions); no priority (rating rubric); no link to tests (requirements and BDD); silent risk acceptance (accepts with owner and date).
</details>

<details>
<summary>8. How can threat modeling fit into a CI/CD pipeline?</summary>

The model lives in the repo as text (annotations, pytm, Threagile, Threat Dragon JSON). CI parses it, generates a report and diagram, and fails on unmitigated high threats, malformed annotations or expired risk acceptances. Reviewers see model changes in the merge request.
</details>

<details>
<summary>9. What can a pipeline not prove about a threat model?</summary>

Completeness. It can prove every declared exposure has a decision; it cannot know about a data flow nobody wrote down. People in the design session cover that.
</details>

<details>
<summary>10. Explain the four ThreatSpec-style tags and the state of the project.</summary>

`@exposes` (a threat exists), `@mitigates` (this code reduces it), `@accepts` (risk accepted, with reason), `@connects` (data flow between components). ThreatSpec itself has had little or no development since about 2020 (verify); use pytm, Threagile or Threat Dragon for new work.
</details>

<details>
<summary>11. What is BDD security and what is its current tooling?</summary>

Gherkin scenarios (Given, When, Then) that express abuse cases and run as automated tests. BDD-Security and Gauntlt were the classic tools and look unmaintained; today use pytest-bdd, behave, Cucumber or ZAP Automation Framework tests.
</details>

<details>
<summary>12. What is OWASP ASVS and what are its levels?</summary>

A catalog of testable security requirements for web apps and APIs, grouped by chapter, with three verification levels: 1 baseline, 2 for apps handling sensitive data (common target), 3 for the most critical systems. Version 5.0 was released in May 2025 (verify).
</details>

<details>
<summary>13. What makes a requirement "as code"?</summary>

A machine-readable record with a stable id, level, link to the threat it answers, and a named automated check that runs in CI. The result is evidence, not a document.
</details>

<details>
<summary>14. Why must a gate fail when a requirement has no test?</summary>

Otherwise coverage can shrink silently and the build stays green. Failing on `NO_TEST` forces the team to say how every in-scope requirement will be verified, or record a reviewed, dated exception.
</details>

<details>
<summary>15. A scenario passes but never asserts anything. How does the lab runner avoid this trap?</summary>

Undefined steps are reported and fail the run (`UNDEFINED`), tags such as `@wip` skip visibly, and each scenario carries the threat id so reviewers can see what it protects. In real frameworks fail on undefined and pending steps.
</details>

## References

- Adam Shostack, *Threat Modeling: Designing for Security*; Threat Modeling Manifesto; OWASP Threat Modeling Cheat Sheet.
- OWASP ASVS (current version, verify), OWASP Proactive Controls, NIST SP 800-218 (SSDF).
- Project pages for OWASP pytm, OWASP Threat Dragon, Threagile, ThreatSpec; Cucumber Gherkin reference; pytest-bdd and behave docs.
- Repo: [AI threat modeling](../../01-ai-security-fundamentals/03-ai-threat-modeling.md), [CAISP chapter 5](../../caisp-course/ch5-threat-modeling-ai-systems/README.md), [CSE chapter 2](../../csse-course/ch2-attacking-code-and-application-supply-chain/README.md).
