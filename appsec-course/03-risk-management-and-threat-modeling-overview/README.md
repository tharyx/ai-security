# Chapter 03: Risk Management and Threat Modeling Overview

This chapter joins the Security Champion course's **primer on risk management** with the Threat Modeling course's **overview chapter**. You learn how app security risks are identified, assessed and treated (mitigate, avoid, transfer, accept) without breaking business continuity, then what threat modeling is, why it pays off, the four families of methods, trust boundaries vs attack surfaces, and how it fits Agile and DevOps. Two offline labs turn this into practice: a risk register with treatment rules, and a breakout exercise on a multi-tier application with an answer key and a checker.

> **Safety.** Every lab is a simulation: a fictional company (ShopCo), JSON fixtures, nothing scanned or attacked. Only test systems you own or have written permission to test.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Tool status and version numbers are hedged: **verify at the source**.

## Syllabus coverage

| Syllabus item | Where to study | Lab |
|---|---|---|
| [CSC 3] Introduction to Risk Management | [01 section 1](01-risk-management-primer.md#1-introduction-to-risk-management); [cyber track 04 lesson 01](../../cybersecurity-track/04-risk-management-and-iso27001/01-risk-concepts.md) | [risk-register](labs/risk-register/README.md) |
| [CSC 3] Risk Management workflow | [01 section 2](01-risk-management-primer.md#2-risk-management-workflow) (SVG) | [risk-register](labs/risk-register/README.md) |
| [CSC 3] Risk Identification | [01 section 3](01-risk-management-primer.md#3-risk-identification) | [risk-register](labs/risk-register/README.md) (coverage gap check) |
| [CSC 3] Identifying compliance risks | [01 section 3.1](01-risk-management-primer.md#31-identifying-compliance-risks) | R-01 in the register fixtures |
| [CSC 3] Identifying security design issues | [01 section 3.2](01-risk-management-primer.md#32-identifying-security-design-issues); [02 section 4](02-threat-modeling-overview.md#4-design-flaws-and-risk-rating) | R-02, R-05 |
| [CSC 3] Identifying vulnerabilities | [01 section 3.3](01-risk-management-primer.md#33-identifying-vulnerabilities); [devsecops ch14](../../devsecops-course/14-vulnerability-management/README.md) | R-03, R-04 |
| [CSC 3] Understanding the current threat landscape | [01 section 3.4](01-risk-management-primer.md#34-understanding-the-current-threat-landscape) | R-06 |
| [CSC 3] Risk Assessment Methodologies | [01 section 4](01-risk-management-primer.md#4-risk-assessment-methodologies); OWASP Risk Rating in [ch04 lesson 05](../04-threat-modeling-methods-and-rating/05-threat-rating.md) | [risk-register](labs/risk-register/README.md); ch04 [threat-rating](../04-threat-modeling-methods-and-rating/labs/threat-rating/README.md) |
| [CSC 3] Risk Treatment | [01 section 5](01-risk-management-primer.md#5-risk-treatment-strategies-with-examples) | [risk-register](labs/risk-register/README.md) (`validate()`) |
| [CSC 3] How to mitigate risks | [01 section 5.1](01-risk-management-primer.md#51-mitigating-risks-how-to-mitigate-risks) | `MITIGATE_WITHOUT_CONTROL`, `CONTROL_WITH_NO_EFFECT` |
| [CSC 3] How to avoid risks | [01 section 5.2](01-risk-management-primer.md#52-avoiding-risks-how-to-avoid-risks) | `AVOID_WITHOUT_CHANGE` |
| [CSC 3] How to transfer risks | [01 section 5.3](01-risk-management-primer.md#53-transferring-risks-how-to-transfer-risks) | `TRANSFER_OVERCLAIMED` |
| [CSC 3] How to accept risks | [01 section 5.4](01-risk-management-primer.md#54-accepting-risks-how-to-accept-risks) | `ACCEPTED_WITHOUT_AUTHORITY`, `ACCEPTANCE_EXPIRED` |
| [CSC 3] Ensuring Business Continuity While Reducing Risk | [01 section 6](01-risk-management-primer.md#6-ensuring-business-continuity-while-reducing-risk); [cyber track BIA/BCDR](../../cybersecurity-track/04-risk-management-and-iso27001/04-third-party-risk-bia-bcdr.md) | `NO_CONTINUITY_PLAN` |
| [CTMP 1] What is Threat Modeling? | [02 section 1](02-threat-modeling-overview.md#1-what-is-threat-modeling) | [multi-tier-breakout](labs/multi-tier-breakout/README.md) |
| [CTMP 1] The Threat Model Parlance | [02 section 2](02-threat-modeling-overview.md#2-the-threat-model-parlance); [CAISP ch5 vocabulary](../../caisp-course/ch5-threat-modeling-ai-systems/01-threat-modeling-foundations.md) | n/a |
| [CTMP 1] Security is a Balancing Act | [02 section 3](02-threat-modeling-overview.md#3-security-is-a-balancing-act) | n/a |
| [CTMP 1] Design Flaws and Risk Rating | [02 section 4](02-threat-modeling-overview.md#4-design-flaws-and-risk-rating); rating in [ch04 lesson 05](../04-threat-modeling-methods-and-rating/05-threat-rating.md) | ch04 [threat-rating](../04-threat-modeling-methods-and-rating/labs/threat-rating/README.md) |
| [CTMP 1] Why Threat Model? | [02 section 5](02-threat-modeling-overview.md#5-why-threat-model) | n/a |
| [CTMP 1] Threat Modeling vs. Other Security Practices | [02 section 6](02-threat-modeling-overview.md#6-threat-modeling-vs-other-security-practices) | n/a |
| [CTMP 1] Threat Modeling Frameworks and Methodologies | [02 section 7](02-threat-modeling-overview.md#7-threat-modeling-frameworks-and-methodologies); depth in [chapter 04](../04-threat-modeling-methods-and-rating/README.md) | chapter 04 labs |
| [CTMP 1] List/Library Centric Threat Modeling | [02 section 7.1](02-threat-modeling-overview.md#71-listlibrary-centric-threat-modeling); [ch04 lesson 02](../04-threat-modeling-methods-and-rating/02-stride.md) | ch04 [dfd-stride](../04-threat-modeling-methods-and-rating/labs/dfd-stride/README.md) |
| [CTMP 1] Asset/Goal Centric Threat Modeling | [02 section 7.2](02-threat-modeling-overview.md#72-assetgoal-centric-threat-modeling); [ch04 lesson 03](../04-threat-modeling-methods-and-rating/03-goal-attacker-and-software-centric.md) | ch04 [attack-trees](../04-threat-modeling-methods-and-rating/labs/attack-trees/README.md) |
| [CTMP 1] Threat Actor/Attacker Centric Threat Modeling | [02 section 7.3](02-threat-modeling-overview.md#73-threat-actorattacker-centric-threat-modeling); [ch04 lesson 03](../04-threat-modeling-methods-and-rating/03-goal-attacker-and-software-centric.md) | ch04 [threat-actor-personas](../04-threat-modeling-methods-and-rating/labs/threat-actor-personas/README.md) |
| [CTMP 1] Software Centric Threat Modeling | [02 section 7.4](02-threat-modeling-overview.md#74-software-centric-threat-modeling) | ch04 [dfd-stride](../04-threat-modeling-methods-and-rating/labs/dfd-stride/README.md) |
| [CTMP 1] Trust Boundaries vs. Attack Surfaces | [02 section 8](02-threat-modeling-overview.md#8-trust-boundaries-vs-attack-surfaces) (SVG) | [multi-tier-breakout](labs/multi-tier-breakout/README.md) (`boundary_crossings`, `attack_surface`) |
| [CTMP 1] Modern Threat Modeling Approaches for Agile and DevOps | [02 section 9](02-threat-modeling-overview.md#9-modern-threat-modeling-approaches-for-agile-and-devops); [devsecops ch03](../../devsecops-course/03-security-requirements-and-threat-modeling/README.md) | [devsecops threat-modeling-as-code](../../devsecops-course/03-security-requirements-and-threat-modeling/labs/threat-modeling-as-code/README.md) |
| [CTMP 1] Risk Management Strategies with Examples | [01 section 5](01-risk-management-primer.md#5-risk-treatment-strategies-with-examples) (taught once with CSC 3) | [risk-register](labs/risk-register/README.md) |
| [CTMP 1] Avoiding Risks | [01 section 5.2](01-risk-management-primer.md#52-avoiding-risks-how-to-avoid-risks) | R-05 |
| [CTMP 1] Accepting Risks | [01 section 5.4](01-risk-management-primer.md#54-accepting-risks-how-to-accept-risks) | R-01 (bad), R-06 (good) |
| [CTMP 1] Mitigating Risks | [01 section 5.1](01-risk-management-primer.md#51-mitigating-risks-how-to-mitigate-risks) | R-01 to R-03 |
| [CTMP 1] Transferring Risks | [01 section 5.3](01-risk-management-primer.md#53-transferring-risks-how-to-transfer-risks) | R-04 |
| [CTMP 1] Breakout Sessions to Identify Threats for a Multi-Tiered Application | [Lesson 03](03-breakout-multi-tier-application.md) | [multi-tier-breakout](labs/multi-tier-breakout/README.md) |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| "Identifying compliance risks" with older regulation examples | For India add the **DPDP Act 2023** and the **DPDP Rules notified Nov 2025** (phased in to about May 2027). Card data: **PCI DSS v4.0.1** (future-dated requirements effective 31 March 2025). |
| Design flaws as "OWASP A04:2021 Insecure Design" | The **OWASP Top 10:2025** keeps Insecure Design (moved to A06; verify final naming). |
| Risk rating with **DREAD** as a default | Little used today; Microsoft moved away from it. Use OWASP Risk Rating, a calibrated 5x5 matrix, or CVSS v4.0 for vulnerability severity (see [ch04 lesson 05](../04-threat-modeling-methods-and-rating/05-threat-rating.md)). |
| "Modern approaches" naming ThreatSpec | ThreatSpec is legacy (little development since about 2020). Current threat-modeling-as-code: **OWASP pytm**, **Threagile**, **OWASP Threat Dragon** JSON. |

## How the three courses overlap here

- **CSC 3** (risk primer) and **CTMP 1** both teach the four treatment strategies. They are taught **once** in [lesson 01 section 5](01-risk-management-primer.md#5-risk-treatment-strategies-with-examples); both sets of rows point there.
- **CSC 4** repeats "What is Threat Modeling?", "Why Threat Model?", "Threat modeling vs. Other Security Practices" and "Modern … Agile and DevOps". Its rows live in [chapter 04](../04-threat-modeling-methods-and-rating/README.md) and link back to [lesson 02](02-threat-modeling-overview.md) here.
- **CASP** (API security) has no risk chapter; its API threat model (chapter 08) builds on the vocabulary here.
- Elsewhere in the repo: general risk, ISO 27001 and BIA in [cybersecurity-track 04](../../cybersecurity-track/04-risk-management-and-iso27001/README.md); AI threat modeling in [CAISP ch5](../../caisp-course/ch5-threat-modeling-ai-systems/README.md).

## Learning order

1. [Lesson 01: risk management primer](01-risk-management-primer.md). About 1.5 hours.
2. The [risk-register lab](labs/risk-register/README.md). About 45 minutes.
3. [Lesson 02: threat modeling overview](02-threat-modeling-overview.md). About 2 hours.
4. [Lesson 03: breakout session](03-breakout-multi-tier-application.md) with the [multi-tier-breakout lab](labs/multi-tier-breakout/README.md). About 1.5 hours.
5. Answer the 15 questions below without looking. About 30 minutes.

## Lab index

All labs run offline: `.venv/Scripts/python -m pytest appsec-course/03-risk-management-and-threat-modeling-overview -q -p no:cacheprovider` (18 tests).

| Lab | Course exercise | Tests |
|---|---|---|
| [risk-register](labs/risk-register/README.md) | Risk identification, assessment, treatment, business continuity | 10 |
| [multi-tier-breakout](labs/multi-tier-breakout/README.md) | Breakout Sessions to Identify Threats for a Multi-Tiered Application | 8 |

## Exam tips

- **Owners decide, security advises.** Say who owns a risk in every answer.
- **Four treatments, four evidence rules.** Mitigate = working controls; avoid = described change; transfer = named party (accountability stays); accept = authority + reason + review date.
- **Accept is not ignore.** Documented, owned, time-boxed, within appetite.
- **CVSS is severity, not risk.** Risk needs likelihood in your context and business impact.
- **Four questions** of threat modeling; know them word for word.
- **Bug vs design flaw:** scanners find bugs; threat modeling finds design flaws.
- **Trust boundary ≠ attack surface.** Boundary = where trust changes; surface = what outsiders can reach.
- **Agile:** model the delta per story, keep the model in the repo, champions run short sessions.
- In a hands-on exam, write threats as *element + STRIDE letter + sentence + mitigation*; it is fast and complete.

## Interview / exam questions

<details>
<summary>1. What is risk, and how do inherent and residual risk differ?</summary>

Risk is the likelihood that a threat exploits a vulnerability to harm an asset, combined with the impact. Inherent risk is before your controls; residual risk is what remains after the chosen treatment. Decisions are made on residual risk against the risk appetite.
</details>

<details>
<summary>2. Describe the risk management workflow.</summary>

Establish context (scope, assets, appetite); identify risks; assess likelihood and impact; treat (mitigate, avoid, transfer, accept); monitor and review through a register with review dates; communicate and consult throughout. It is a loop, re-entered whenever the system or the threat landscape changes.
</details>

<details>
<summary>3. Where do application security risks come from? Give four sources.</summary>

Compliance obligations (PCI DSS, DPDP, GDPR, contracts); security design issues (found by threat modeling and design review); vulnerabilities (SAST, SCA, DAST, pentest, CVEs); and the current threat landscape (active campaigns, KEV lists, sector intelligence) which changes likelihood.
</details>

<details>
<summary>4. Explain the four risk treatment strategies with an example each.</summary>

Mitigate: add redaction and tokenisation so card numbers never reach logs. Avoid: remove a rarely used full-customer CSV export. Transfer: cyber insurance for ransomware recovery costs (plus immutable backups). Accept: credential-stuffing risk at MEDIUM after rate limits, accepted by the product owner until MFA ships, with a review date.
</details>

<details>
<summary>5. Why can you not transfer a risk completely?</summary>

Transfer moves financial loss (insurer, contract), but customers, regulators and the press still hold you accountable, the outage still happens and data is still exposed. So transfer reduces impact only partly and normally comes with controls and a continuity plan.
</details>

<details>
<summary>6. What is the difference between accepting and ignoring a risk?</summary>

Acceptance is a documented decision by someone with authority for that risk level, with a reason, within appetite, and with a review or expiry date. Ignoring has none of these. Acceptances above appetite need escalation (CISO, executive).
</details>

<details>
<summary>7. How do you keep the business running while reducing risk?</summary>

Know critical services and their RTO/RPO from a BIA; keep BCP/DR plans and test restores; reference the plan in risk decisions for critical services; roll out controls safely (report-only mode, canary, feature flags) so a new control does not cause an outage.
</details>

<details>
<summary>8. What is threat modeling? State the four questions.</summary>

A structured way to find, rate and decide on threats using a model of the system. What are we working on? What can go wrong? What are we going to do about it? Did we do a good enough job?
</details>

<details>
<summary>9. What is the difference between a bug and a design flaw? Why does it matter?</summary>

A bug is an implementation mistake (string-concatenated SQL); a design flaw is a mistake in the plan (the client sends the price, a queue without producer authentication). Design flaws need redesign, are mostly invisible to scanners and are cheapest to fix at design time, which is why threat modeling exists.
</details>

<details>
<summary>10. Why threat model? Give four benefits.</summary>

Finds design flaws early and cheaply; focuses testing and review on risky parts; produces testable security requirements; builds a shared understanding of the system; provides audit evidence; gives pentesters a map.
</details>

<details>
<summary>11. How does threat modeling differ from SAST, DAST and pentesting?</summary>

Threat modeling is proactive and design-level: it asks what can go wrong before code exists. SAST and SCA find code and dependency issues; DAST and pentests find exploitable issues in running systems, late. Threat modeling directs them by telling them where to look.
</details>

<details>
<summary>12. Name the four families of threat modeling methods.</summary>

List/library centric (STRIDE, LINDDUN, card decks); asset/goal centric (attack trees, OCTAVE); attacker centric (personas, MITRE ATT&CK); software centric (DFD and STRIDE per element). Teams usually combine them.
</details>

<details>
<summary>13. Trust boundary vs attack surface?</summary>

A trust boundary is a line in the design where the trust level changes (Internet to DMZ, app to database); data crossing it must be authenticated, validated and often encrypted. The attack surface is the set of points an attacker can reach (endpoints, webhooks, admin consoles). Entry points cross boundaries, but internal boundaries are not on the external surface.
</details>

<details>
<summary>14. How do you threat model in Agile and DevOps?</summary>

Model the delta for each story that adds a flow, store, boundary or sensitive data; keep sessions short (RTMP style); keep the model as code in the repo and check it in CI; turn threats into backlog items with tests; let security champions run sessions; update the model when the design changes.
</details>

<details>
<summary>15. In a breakout session, which threats do teams most often miss, and why?</summary>

Those behind the first tier: forged queue messages, worker over-privilege, forged partner webhooks, phished admins, missing audit trails. Teams assume "internal" or "partner" means trusted and focus on the public website.
</details>

## References

- Adam Shostack, *Threat Modeling: Designing for Security*; the Threat Modeling Manifesto; OWASP Threat Modeling Cheat Sheet.
- ISO 31000, ISO/IEC 27005, NIST SP 800-30 Rev. 1, FAIR (verify current editions).
- OWASP Top 10:2021 and 2025 (Insecure Design); PCI DSS v4.0.1; India DPDP Act 2023 and DPDP Rules 2025.
- Repo: [cybersecurity-track 04](../../cybersecurity-track/04-risk-management-and-iso27001/README.md), [devsecops ch03](../../devsecops-course/03-security-requirements-and-threat-modeling/README.md), [CAISP ch5](../../caisp-course/ch5-threat-modeling-ai-systems/README.md), [AI threat modeling](../../01-ai-security-fundamentals/03-ai-threat-modeling.md).

**Next chapter:** [Chapter 04: Threat Modeling Methods and Rating](../04-threat-modeling-methods-and-rating/README.md)
