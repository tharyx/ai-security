# Chapter 04: Threat Modeling Methods and Rating

This chapter merges the Threat Modeling course's **basics chapter** with the Security Champion course's **threat modeling chapter**, which cover much of the same ground. You learn to draw DFDs, find threats with STRIDE (per element), attack trees, threat actor personas and MITRE ATT&CK, know the other methodologies (PASTA, VAST, Hybrid, RTMP, OCTAVE) and card games, rate threats (DREAD and why it faded, OWASP Risk Rating, bug bars, Rapid Risk Assessment), and turn threats into testable security requirements. Six offline labs cover every hands-on exercise, ending with a full password-reset threat model where 11 requirements fail on a vulnerable service and pass on a secure one.

> **Safety.** Every lab is a simulation: fictional systems, JSON fixtures and in-process toy services. Attacks run only against the lab's own code. Only test systems you own or have written permission to test.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Tool status and version numbers are hedged: **verify at the source**.

## Syllabus coverage

| Syllabus item | Where to study | Lab |
|---|---|---|
| [CTMP 2] Threat Modeling and Security Requirements | [01 section 1](01-security-requirements-and-diagramming.md#1-threat-modeling-and-security-requirements) | [password-reset-threat-model](labs/password-reset-threat-model/README.md) (`requirements.py`) |
| [CTMP 2] Threat Modeling vs. Threat Rating | [01 section 2](01-security-requirements-and-diagramming.md#2-threat-modeling-vs-threat-rating) | [threat-rating](labs/threat-rating/README.md) |
| [CTMP 2] Diagramming for Threat Modeling | [01 section 3](01-security-requirements-and-diagramming.md#3-diagramming-for-threat-modeling) (SVG) | [dfd-stride](labs/dfd-stride/README.md) |
| [CTMP 2] List Centric Threat Modeling | [02 section 1](02-stride.md#1-list-centric-threat-modeling); overview in [ch03 lesson 02](../03-risk-management-and-threat-modeling-overview/02-threat-modeling-overview.md#71-listlibrary-centric-threat-modeling) | [dfd-stride](labs/dfd-stride/README.md) |
| [CTMP 2] Exploring the STRIDE Model | [02 section 2](02-stride.md#2-the-stride-model) | [dfd-stride](labs/dfd-stride/README.md) |
| [CTMP 2] Spoofing | [02 section 2.1](02-stride.md#21-spoofing) | SR-01, SR-04, SR-05, SR-09 |
| [CTMP 2] Tampering | [02 section 2.2](02-stride.md#22-tampering) | SR-03 |
| [CTMP 2] Repudiation | [02 section 2.3](02-stride.md#23-repudiation) | SR-11 |
| [CTMP 2] Information Disclosure | [02 section 2.4](02-stride.md#24-information-disclosure) | SR-02, SR-06, SR-07 |
| [CTMP 2] Denial of Service | [02 section 2.5](02-stride.md#25-denial-of-service) | SR-10 |
| [CTMP 2] Elevation of Privileges | [02 section 2.6](02-stride.md#26-elevation-of-privilege) | SR-08 |
| [CTMP 2] Pros and Cons of STRIDE | [02 section 6](02-stride.md#6-pros-and-cons-of-stride) | n/a |
| [CTMP 2] STRIDE Defenses | [02 section 3](02-stride.md#3-stride-defenses) (SVG) | [password-reset-threat-model](labs/password-reset-threat-model/README.md) |
| [CTMP 2] Authentication | [02 section 3.1](02-stride.md#31-authentication) | SR-09 |
| [CTMP 2] Integrity | [02 section 3.2](02-stride.md#32-integrity) | SR-03 |
| [CTMP 2] Non-Repudiation | [02 section 3.3](02-stride.md#33-non-repudiation) | SR-11 |
| [CTMP 2] Confidentiality | [02 section 3.4](02-stride.md#34-confidentiality) | SR-06 |
| [CTMP 2] Availability | [02 section 3.5](02-stride.md#35-availability) | SR-10 |
| [CTMP 2] Authorization | [02 section 3.6](02-stride.md#36-authorization) | SR-08 |
| [CTMP 2] STRIDE Threat Examples | [02 section 5](02-stride.md#5-stride-threat-examples) | [dfd-stride](labs/dfd-stride/README.md), [threat-card-game](labs/threat-card-game/README.md) |
| [CTMP 2] Goal/Asset Based Modeling Approach | [03 section 1](03-goal-attacker-and-software-centric.md#1-goalasset-based-modeling-approach) | [attack-trees](labs/attack-trees/README.md) |
| [CTMP 2] Attack Trees | [03 section 2](03-goal-attacker-and-software-centric.md#2-attack-trees) (SVG) | [attack-trees](labs/attack-trees/README.md) |
| [CTMP 2] Attack Tree Analysis | [03 section 3](03-goal-attacker-and-software-centric.md#3-attack-tree-analysis) | [attack-trees](labs/attack-trees/README.md) (`cheapest_path`, `best_single_control`) |
| [CTMP 2] Attacker/Threat Actor Centric Modeling Approach | [03 section 4](03-goal-attacker-and-software-centric.md#4-attackerthreat-actor-centric-modeling-approach) | [threat-actor-personas](labs/threat-actor-personas/README.md) |
| [CTMP 2] Using MITRE ATT&CK for Attacker Centric Threat Modeling | [03 section 6](03-goal-attacker-and-software-centric.md#6-using-mitre-attck-for-attacker-centric-threat-modeling); [ATT&CK Navigator guide](real-tools/diagramming-attack-and-games.md#mitre-attck-navigator-lesson-03-lab-threat-actor-personas) | [threat-actor-personas](labs/threat-actor-personas/README.md) |
| [CTMP 2] Software Centric Threat Modeling | [03 section 7](03-goal-attacker-and-software-centric.md#7-software-centric-threat-modeling) | [dfd-stride](labs/dfd-stride/README.md) |
| [CTMP 2] Other Threat Modeling Methodologies | [Lesson 04](04-other-methodologies-and-games.md) (SVG) | n/a |
| [CTMP 2] PASTA | [04 section 1](04-other-methodologies-and-games.md#1-pasta) | n/a |
| [CTMP 2] VAST | [04 section 2](04-other-methodologies-and-games.md#2-vast) | n/a |
| [CTMP 2] Hybrid Threat modeling | [04 section 3](04-other-methodologies-and-games.md#3-hybrid-threat-modeling) | n/a |
| [CTMP 2] RTMP | [04 section 4](04-other-methodologies-and-games.md#4-rtmp) | n/a |
| [CTMP 2] OCTAVE | [04 section 5](04-other-methodologies-and-games.md#5-octave) | n/a |
| [CTMP 2] Gamified approaches for Threat Modeling | [04 section 7](04-other-methodologies-and-games.md#7-gamified-approaches-for-threat-modeling) | [threat-card-game](labs/threat-card-game/README.md) |
| [CTMP 2] Virtual Card Games | [04 section 7.1](04-other-methodologies-and-games.md#71-virtual-card-games) | [threat-card-game](labs/threat-card-game/README.md) |
| [CTMP 2] Adversary Card Games | [04 section 7.2](04-other-methodologies-and-games.md#72-adversary-card-games) | [threat-card-game](labs/threat-card-game/README.md) |
| [CTMP 2] Introduction to Threat Rating | [05 section 1](05-threat-rating.md#1-introduction-to-threat-rating) | [threat-rating](labs/threat-rating/README.md) |
| [CTMP 2] DREAD | [05 section 2](05-threat-rating.md#2-dread) | [threat-rating](labs/threat-rating/README.md) (`dread`, `rater_spread`) |
| [CTMP 2] OWASP Risk Rating Methodology | [05 section 3](05-threat-rating.md#3-owasp-risk-rating-methodology) | [threat-rating](labs/threat-rating/README.md) (`owasp_risk`) |
| [CTMP 2] Bug Bar | [05 section 4](05-threat-rating.md#4-bug-bar) | [threat-rating](labs/threat-rating/README.md) (`bug_bar`) |
| [CTMP 2] Rapid Risk Assessment | [05 section 5](05-threat-rating.md#5-rapid-risk-assessment) | [threat-rating](labs/threat-rating/README.md) (`rra_report`) |
| [CTMP 2] Creating a Data Flow Diagram for Threat Modeling | [01 section 4](01-security-requirements-and-diagramming.md#4-creating-a-data-flow-diagram-step-by-step) | [dfd-stride](labs/dfd-stride/README.md) |
| [CTMP 2] Threat Modeling a Password Reset Workflow | [Lesson 06](06-password-reset-workflow.md) | [password-reset-threat-model](labs/password-reset-threat-model/README.md) |
| [CTMP 2] Creating Threat Actor Personas | [03 section 5](03-goal-attacker-and-software-centric.md#5-creating-threat-actor-personas) | [threat-actor-personas](labs/threat-actor-personas/README.md) |
| [CTMP 2] Risk Rating with OWASP Risk Rating Methodology | [05 section 3.1](05-threat-rating.md#31-worked-example-risk-rating-with-the-owasp-risk-rating-methodology) | [threat-rating](labs/threat-rating/README.md) |
| [CSC 4] What is Threat Modeling? | [ch03 lesson 02 section 1](../03-risk-management-and-threat-modeling-overview/02-threat-modeling-overview.md#1-what-is-threat-modeling) (taught once) | [ch03 multi-tier-breakout](../03-risk-management-and-threat-modeling-overview/labs/multi-tier-breakout/README.md) |
| [CSC 4] Why Threat Model? | [ch03 lesson 02 section 5](../03-risk-management-and-threat-modeling-overview/02-threat-modeling-overview.md#5-why-threat-model) | n/a |
| [CSC 4] Threat modeling vs. Other Security Practices | [ch03 lesson 02 section 6](../03-risk-management-and-threat-modeling-overview/02-threat-modeling-overview.md#6-threat-modeling-vs-other-security-practices) | n/a |
| [CSC 4] Threat modeling and security requirements | [01 section 1](01-security-requirements-and-diagramming.md#1-threat-modeling-and-security-requirements) | [password-reset-threat-model](labs/password-reset-threat-model/README.md) |
| [CSC 4] Diagramming for Threat Modeling | [01 section 3](01-security-requirements-and-diagramming.md#3-diagramming-for-threat-modeling) | [dfd-stride](labs/dfd-stride/README.md) |
| [CSC 4] Exploring the STRIDE Model | [02 section 2](02-stride.md#2-the-stride-model) | [dfd-stride](labs/dfd-stride/README.md) |
| [CSC 4] Spoofing | [02 section 2.1](02-stride.md#21-spoofing) | SR-01 |
| [CSC 4] Tampering | [02 section 2.2](02-stride.md#22-tampering) | SR-03 |
| [CSC 4] Repudiation | [02 section 2.3](02-stride.md#23-repudiation) | SR-11 |
| [CSC 4] Information Disclosure | [02 section 2.4](02-stride.md#24-information-disclosure) | SR-02 |
| [CSC 4] Denial of Service | [02 section 2.5](02-stride.md#25-denial-of-service) | SR-10 |
| [CSC 4] Elevation of Privilege | [02 section 2.6](02-stride.md#26-elevation-of-privilege) | SR-08 |
| [CSC 4] STRIDE threat examples | [02 section 5](02-stride.md#5-stride-threat-examples) | [dfd-stride](labs/dfd-stride/README.md) |
| [CSC 4] Threat Rating | [05 section 1](05-threat-rating.md#1-introduction-to-threat-rating) | [threat-rating](labs/threat-rating/README.md) |
| [CSC 4] DREAD | [05 section 2](05-threat-rating.md#2-dread) | [threat-rating](labs/threat-rating/README.md) |
| [CSC 4] OWASP Risk Rating | [05 section 3](05-threat-rating.md#3-owasp-risk-rating-methodology) | [threat-rating](labs/threat-rating/README.md) |
| [CSC 4] Modern threat modeling approaches for Agile and DevOps | [ch03 lesson 02 section 9](../03-risk-management-and-threat-modeling-overview/02-threat-modeling-overview.md#9-modern-threat-modeling-approaches-for-agile-and-devops); applied in [06 section 7](06-password-reset-workflow.md#7-modern-threat-modeling-for-agile-and-devops-applied) | [devsecops threat-modeling-as-code](../../devsecops-course/03-security-requirements-and-threat-modeling/labs/threat-modeling-as-code/README.md) |
| [CSC 4] Creating Data Flow Diagrams | [01 section 4](01-security-requirements-and-diagramming.md#4-creating-a-data-flow-diagram-step-by-step) | [dfd-stride](labs/dfd-stride/README.md) |
| [CSC 4] Threat modeling for a Password Reset workflow | [Lesson 06](06-password-reset-workflow.md) | [password-reset-threat-model](labs/password-reset-threat-model/README.md) |
| [CSC 4] Threat rating using OWASP risk rating methodology | [05 section 3.1](05-threat-rating.md#31-worked-example-risk-rating-with-the-owasp-risk-rating-methodology) | [threat-rating](labs/threat-rating/README.md) |
| [CSC 4] Writing Security Requirements for Threat Modeling | [01 section 5](01-security-requirements-and-diagramming.md#5-writing-security-requirements-for-threat-modeling) | [password-reset-threat-model](labs/password-reset-threat-model/README.md) (SR-01 to SR-11) |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| **DREAD** as a rating method | Subjective and not repeatable; Microsoft moved away from it. Use **OWASP Risk Rating**, a calibrated matrix, **CVSS v4.0** (Nov 2023) for vulnerability severity, and bug bars for release gates. |
| **MITRE ATT&CK** (version not stated) | ATT&CK is versioned; Enterprise **v18** was released in October 2025. Re-check technique IDs (sub-techniques like T1110.004 change over time). Add **CAPEC** for app attack patterns and **MITRE ATLAS** for AI. |
| **OCTAVE** | Largely legacy; **OCTAVE Allegro** (2007) is the streamlined variant. For apps use STRIDE/PASTA/RTMP. |
| Card games (Elevation of Privilege, Cornucopia) | EoP is also maintained as an OWASP project; **OWASP Cornucopia v2** adds a mobile edition; **OWASP Cumulus** covers cloud/DevOps; **LINDDUN GO** for privacy. |
| Password policy examples with complexity rules and rotation | **NIST SP 800-63B-4** (final 2025): length over complexity (15+ characters when password is the only factor), blocklists, no forced rotation or composition rules. |
| Security requirements without a catalog | Map to **OWASP ASVS 5.0.0** (May 2025; IDs renumbered from 4.0.3). |

## How the three courses overlap here

- **CTMP 2** and **CSC 4** overlap on STRIDE (all six letters), DREAD, OWASP Risk Rating, DFDs, the password reset exercise and requirements. Each topic is taught **once**; both rows point to the same section.
- **CSC 4** also repeats overview topics ("What is Threat Modeling?", "Why Threat Model?", "vs. Other Security Practices", "Modern … Agile and DevOps"). These are taught in [chapter 03 lesson 02](../03-risk-management-and-threat-modeling-overview/02-threat-modeling-overview.md).
- **CTMP 3** (chapter 05) continues with threat modeling as code, LINDDUN privacy and BDD; **CTMP 4** (chapter 06) with tools (Threat Dragon, IriusRisk, Microsoft TMT, StrideGPT).
- Elsewhere: the short STRIDE/DREAD view in [devsecops ch03](../../devsecops-course/03-security-requirements-and-threat-modeling/README.md); STRIDE and rating for LLM apps in [CAISP ch5](../../caisp-course/ch5-threat-modeling-ai-systems/README.md).

## Learning order

1. [Lesson 01: requirements and diagramming](01-security-requirements-and-diagramming.md), then the [dfd-stride lab](labs/dfd-stride/README.md). About 2 hours.
2. [Lesson 02: STRIDE](02-stride.md). About 2 hours.
3. [Lesson 03: goal, attacker and software centric](03-goal-attacker-and-software-centric.md), then the [attack-trees](labs/attack-trees/README.md) and [threat-actor-personas](labs/threat-actor-personas/README.md) labs. About 3.5 hours.
4. [Lesson 04: other methodologies and games](04-other-methodologies-and-games.md), then the [threat-card-game lab](labs/threat-card-game/README.md). About 2.5 hours.
5. [Lesson 05: threat rating](05-threat-rating.md), then the [threat-rating lab](labs/threat-rating/README.md). About 3 hours.
6. [Lesson 06: password reset workflow](06-password-reset-workflow.md), then the [password-reset-threat-model lab](labs/password-reset-threat-model/README.md). About 2.5 hours.
7. Skim [real-tools](real-tools/diagramming-attack-and-games.md) and answer the 15 questions below. About 1 hour.

## Lab index

All labs run offline: `.venv/Scripts/python -m pytest appsec-course/04-threat-modeling-methods-and-rating -q -p no:cacheprovider` (50 tests).

| Lab | Course exercise | Tests |
|---|---|---|
| [dfd-stride](labs/dfd-stride/README.md) | Creating a Data Flow Diagram for Threat Modeling / Creating Data Flow Diagrams | 7 |
| [password-reset-threat-model](labs/password-reset-threat-model/README.md) | Threat Modeling a Password Reset Workflow; Writing Security Requirements for Threat Modeling | 10 |
| [attack-trees](labs/attack-trees/README.md) | Attack Trees, Attack Tree Analysis | 8 |
| [threat-actor-personas](labs/threat-actor-personas/README.md) | Creating Threat Actor Personas; MITRE ATT&CK | 8 |
| [threat-rating](labs/threat-rating/README.md) | Risk Rating with OWASP Risk Rating Methodology; DREAD; Bug Bar; RRA | 10 |
| [threat-card-game](labs/threat-card-game/README.md) | Gamified approaches, virtual and adversary card games | 7 |

Hedged guide for real tools: [DFD drawing, ATT&CK Navigator, attack trees, card games, rating calculators](real-tools/diagramming-attack-and-games.md).

## Exam tips

- **STRIDE = six threats = six properties = six defense families.** Be able to write the table from memory: S/authentication, T/integrity, R/non-repudiation, I/confidentiality, D/availability, E/authorization.
- **STRIDE per element:** externals S R; processes all six; stores T I D (+R for logs); flows T I D.
- **DFD rules:** no store-to-store, no external-to-store, no black holes or miracles; draw trust boundaries.
- **Finding vs rating:** STRIDE finds, OWASP Risk Rating ranks. DREAD = know its five letters and three weaknesses.
- **OWASP Risk Rating:** 8 likelihood factors + 8 impact factors, 0-9, LOW <3, MEDIUM <6, HIGH ≥6, 3x3 matrix to CRITICAL. Practise one calculation by hand.
- **Attack trees:** OR = min cost, AND = sum; the cheapest path is what to fix first.
- **PASTA has 7 stages** (objectives, technical scope, decomposition, threat analysis, vulnerability analysis, attack modeling, risk and impact).
- **Password reset:** know at least eight threats and the matching requirements.
- In a hands-on exam, show **threat → requirement → test**, not just a list.

## Interview / exam questions

<details>
<summary>1. How do threat modeling and security requirements relate?</summary>

Each threat in the model becomes a specific, testable requirement (and an abuse case), and each requirement gets a test and evidence. Catalogs like OWASP ASVS give the baseline; the threat model adds system-specific requirements (for example verifying payment webhook signatures).
</details>

<details>
<summary>2. What is the difference between threat modeling and threat rating?</summary>

Threat modeling finds threats (STRIDE, attack trees, personas); threat rating ranks them (OWASP Risk Rating, CVSS, bug bar, RRA, DREAD). Finding comes first; rating decides fix order and acceptance.
</details>

<details>
<summary>3. Name the DFD elements and three DFD rules.</summary>

External entity, process, data store, data flow, plus trust boundaries. Rules: data moves only through processes (no store-to-store or external-to-store flows); no black-hole or miracle processes; every flow is labelled; externals do not talk to each other in the model.
</details>

<details>
<summary>4. Expand STRIDE with the property each letter breaks and one defense.</summary>

Spoofing/authentication (MFA, mTLS); Tampering/integrity (validation, signatures); Repudiation/non-repudiation (audit logs); Information disclosure/confidentiality (encryption, access checks); Denial of service/availability (rate limits); Elevation of privilege/authorization (deny by default, least privilege).
</details>

<details>
<summary>5. What is STRIDE per element?</summary>

Applying only the relevant letters to each DFD element type: external entities S and R; processes all six; data stores T, I, D (plus R for logs); data flows T, I, D. It keeps sessions short and systematic.
</details>

<details>
<summary>6. Give the pros and cons of STRIDE.</summary>

Pros: simple, systematic, technology-neutral, maps to controls, well supported by tools. Cons: no prioritisation, can become checkbox work, weak on privacy, business logic and supply chain, many trivial candidates, depends on a good DFD.
</details>

<details>
<summary>7. What is an attack tree and how do you analyse one?</summary>

A tree with the attacker's goal at the root and ways to achieve it below, using OR (any child) and AND (all children) nodes, with attributes on leaves. Analysis: cheapest path (OR = min, AND = sum), probability, minimal attack scenarios, what an attacker with a given budget can do, and how much a control raises the attacker's cost.
</details>

<details>
<summary>8. What is attacker-centric threat modeling and how does MITRE ATT&CK help?</summary>

Starting from who attacks you (personas with motivation, skill, resources, access). ATT&CK supplies real tactics and techniques per actor type, so you can tag threats with technique IDs, judge likelihood, find missing personas, and give the SOC detection targets. It does not model most business-logic abuse.
</details>

<details>
<summary>9. What makes a good threat actor persona?</summary>

It is based on evidence (incidents, intel), and states motivation, skill, resources, access, goals and typical techniques. Keep few personas (3 to 6), make them specific to your sector, and use them to filter and prioritise threats.
</details>

<details>
<summary>10. Name PASTA's seven stages.</summary>

Define objectives; define technical scope; application decomposition; threat analysis; vulnerability and weakness analysis; attack modeling; risk and impact analysis.
</details>

<details>
<summary>11. Compare VAST, RTMP, Hybrid and OCTAVE in one line each.</summary>

VAST: visual, agile, simple, scalable, with separate application and operational models (ThreatModeler). RTMP: rapid, lightweight per-feature prototyping of DFD-based models. Hybrid (hTMM): Security Cards + Persona non Grata + STRIDE. OCTAVE: organisational, asset-based risk evaluation from CERT/SEI, largely legacy (Allegro is the lighter variant).
</details>

<details>
<summary>12. Why use card games for threat modeling? Name three.</summary>

They make sessions social, teach attacker thinking and lower the barrier for developers. Elevation of Privilege (STRIDE suits), OWASP Cornucopia (web, v2 mobile), OWASP Cumulus (cloud), LINDDUN GO (privacy), Backdoors & Breaches (incident response tabletop).
</details>

<details>
<summary>13. Explain DREAD and why it is rarely used now.</summary>

Damage, Reproducibility, Exploitability, Affected users, Discoverability, each scored and averaged. It is subjective and not repeatable (raters can differ by several points), discoverability rewards obscurity, and it mixes likelihood with impact. Microsoft moved away from it.
</details>

<details>
<summary>14. Walk through the OWASP Risk Rating Methodology.</summary>

Score 8 likelihood factors (threat agent: skill, motive, opportunity, size; vulnerability: ease of discovery, ease of exploit, awareness, intrusion detection) and 8 impact factors (technical: C, I, A, accountability; business: financial, reputation, non-compliance, privacy) from 0 to 9. Average each; 0 to <3 LOW, 3 to <6 MEDIUM, 6 to 9 HIGH; read the 3x3 matrix (NOTE to CRITICAL). Use technical impact only if business impact is unknown.
</details>

<details>
<summary>15. List the main threats to a password reset workflow and the matching requirements.</summary>

Predictable token (CSPRNG, 128+ bits); user enumeration (uniform response); Host header poisoning (fixed base URL); token reuse (single use); no expiry (15 minutes); tokens stored or logged in clear (hash at rest, no logging); sessions surviving reset (revoke all); weak new password (length + blocklist); mail flooding (per-account rate limit); no audit (audit event). Also: bug bar or OWASP rating to prioritise.
</details>

## References

- Adam Shostack, *Threat Modeling: Designing for Security*; Threat Modeling Manifesto; OWASP Threat Modeling Cheat Sheet; Microsoft SDL threat modeling and bug bar pages.
- Bruce Schneier, "Attack Trees" (1999); UcedaVélez and Morana, *Risk Centric Threat Modeling* (PASTA); CERT/SEI OCTAVE Allegro report; SEI hybrid threat modeling (hTMM) report.
- MITRE ATT&CK (attack.mitre.org), CAPEC, ATLAS; OWASP Risk Rating Methodology; FIRST CVSS v4.0; Mozilla Rapid Risk Assessment.
- OWASP Forgot Password Cheat Sheet; NIST SP 800-63B-4; OWASP ASVS 5.0.0.
- Repo: [chapter 03](../03-risk-management-and-threat-modeling-overview/README.md), [devsecops ch03](../../devsecops-course/03-security-requirements-and-threat-modeling/README.md), [CAISP ch5](../../caisp-course/ch5-threat-modeling-ai-systems/README.md), [AI threat modeling](../../01-ai-security-fundamentals/03-ai-threat-modeling.md).

**Next chapter:** [Chapter 05: Agile Threat Modeling as Code](../05-agile-threat-modeling-as-code/README.md)
