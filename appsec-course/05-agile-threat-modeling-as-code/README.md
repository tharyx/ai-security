# Chapter 05: Agile Threat Modeling and Threat Modeling as Code

This chapter moves threat modeling from a yearly workshop into the sprint: agile threat modeling approaches and Rapid Threat Model Prototyping, where security fits in each Scrum event, security user stories and abuse cases, and threat models kept **inside, alongside, with and as code** (pytm, diagrams and UML as code, attack trees as code). It also covers compliance and audit as code for **PCI DSS v4.0.1** and privacy threat modeling with **LINDDUN** and PIA/DPIA. Five offline labs turn each idea into code with tests; ThreatSpec-style annotations, requirements as code and the BDD runner are **linked** from the DevSecOps course instead of being rebuilt.

> **Safety.** Every lab is a simulation: fictional systems described in Python and JSON, text generation and rule checks. Nothing is scanned or attacked. Only test systems you own or have written permission to test.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Tool status and version numbers are hedged: **verify at the source**.

## Syllabus coverage

| Syllabus item | Where to study | Lab |
|---|---|---|
| [CTMP 3] Agile Threat Modeling Approaches | [01 section 2](01-agile-threat-modeling-and-scrum.md#2-agile-threat-modeling-approaches) | [agile-security-stories](labs/agile-security-stories/README.md) |
| [CTMP 3] Threat Modeling Diagrams as Code | [02 section 3](02-threat-modeling-as-code-pytm-and-diagrams.md#3-diagrams-as-code-and-uml-as-code) (SVG) | [diagrams-and-attack-trees-as-code](labs/diagrams-and-attack-trees-as-code/README.md), [pytm-lite](labs/pytm-lite/README.md) (`dfd()`) |
| [CTMP 3] Threat Modeling Inside The Code | [02 section 1](02-threat-modeling-as-code-pytm-and-diagrams.md#1-four-ways-to-keep-the-model-next-to-the-code); [devsecops-course ch03 lesson 02 section 3](../../devsecops-course/03-security-requirements-and-threat-modeling/02-threat-modeling-tools-and-ci-cd.md#3-threat-modeling-as-code-with-annotations-the-threatspec-idea) | [devsecops-course ThreatSpec-style annotations lab](../../devsecops-course/03-security-requirements-and-threat-modeling/labs/threat-modeling-as-code/README.md) (linked, not rebuilt) |
| [CTMP 3] Threat Modeling as Code | [02 sections 1 and 5](02-threat-modeling-as-code-pytm-and-diagrams.md#5-threat-modeling-as-code-in-a-pipeline) | [pytm-lite](labs/pytm-lite/README.md) |
| [CTMP 3] Compliance and Audit as Code | [04 sections 1, 2 and 5](04-compliance-and-audit-as-code-pci-dss.md#1-what-compliance-as-code-and-audit-as-code-mean); [devsecops-course ch08](../../devsecops-course/08-iac-configuration-and-compliance-as-code/README.md) | [pci-compliance-as-code](labs/pci-compliance-as-code/README.md) (evidence bundle) |
| [CTMP 3] Rapid Threat Model Prototyping | [01 section 3](01-agile-threat-modeling-and-scrum.md#3-rapid-threat-model-prototyping-rtmp); chapter 04 compares methods | [diagrams lab](labs/diagrams-and-attack-trees-as-code/README.md) (feature-scoped sequence diagram) |
| [CTMP 3] Security Requirements as Code With BDD Security | [03 section 4](03-security-requirements-user-stories-and-abuse-cases.md#4-security-requirements-as-code-with-bdd-security) | [agile-security-stories](labs/agile-security-stories/README.md) (Gherkin from abuse cases); [devsecops-course BDD lab](../../devsecops-course/03-security-requirements-and-threat-modeling/labs/bdd-security-threats/README.md) (runner, linked) |
| [CTMP 3] Events of Agile Software Development Through Scrum | [01 section 4](01-agile-threat-modeling-and-scrum.md#4-scrum-events-and-where-security-fits) (SVG) | [agile-security-stories](labs/agile-security-stories/README.md) |
| [CTMP 3] Writing Security Requirements for Agile Software Development | [03 section 1](03-security-requirements-user-stories-and-abuse-cases.md#1-writing-security-requirements-for-agile-software-development) | [agile-security-stories](labs/agile-security-stories/README.md) |
| [CTMP 3] Writing Use Cases and Abuse Cases | [03 section 2](03-security-requirements-user-stories-and-abuse-cases.md#2-use-cases-and-abuse-cases) | [agile-security-stories](labs/agile-security-stories/README.md), misuse case diagram in the [diagrams lab](labs/diagrams-and-attack-trees-as-code/README.md) |
| [CTMP 3] Privacy Impact Assessments and Security Requirements | [05 section 2](05-privacy-threat-modeling-linddun-and-pia.md#2-privacy-impact-assessments-and-security-requirements) | [privacy-linddun-pia](labs/privacy-linddun-pia/README.md) |
| [CTMP 3] Identifying Privacy Related Threats | [05 section 3](05-privacy-threat-modeling-linddun-and-pia.md#3-identifying-privacy-related-threats-with-linddun) | [privacy-linddun-pia](labs/privacy-linddun-pia/README.md) |
| [CTMP 3] Threat Modeling Privacy for your system | [05 section 4](05-privacy-threat-modeling-linddun-and-pia.md#4-threat-modeling-privacy-for-your-system) | [privacy-linddun-pia](labs/privacy-linddun-pia/README.md) |
| [CTMP 3] Creating Threat Models With Pytm | [02 section 2](02-threat-modeling-as-code-pytm-and-diagrams.md#2-creating-threat-models-with-pytm-and-customizing-its-reports); [real-tools guide](real-tools/pytm-threagile-and-diagram-tools.md) | [pytm-lite](labs/pytm-lite/README.md) |
| [CTMP 3] Customizing Reporting Capabilities Of Pytm | [02 section 2](02-threat-modeling-as-code-pytm-and-diagrams.md#2-creating-threat-models-with-pytm-and-customizing-its-reports) | [pytm-lite](labs/pytm-lite/README.md) (three templates) |
| [CTMP 3] Writing Requirements in Threat Modeling | [03 section 3](03-security-requirements-user-stories-and-abuse-cases.md#3-writing-requirements-in-threat-modeling) | [pytm-lite](labs/pytm-lite/README.md) (`requirements()`); [devsecops-course requirements-as-code lab](../../devsecops-course/03-security-requirements-and-threat-modeling/labs/security-requirements-as-code/README.md) |
| [CTMP 3] Exploring UML as Code | [02 section 3](02-threat-modeling-as-code-pytm-and-diagrams.md#3-diagrams-as-code-and-uml-as-code) | [diagrams-and-attack-trees-as-code](labs/diagrams-and-attack-trees-as-code/README.md) |
| [CTMP 3] Creating Attack Trees Using Code | [02 section 4](02-threat-modeling-as-code-pytm-and-diagrams.md#4-attack-trees-as-code) | [diagrams-and-attack-trees-as-code](labs/diagrams-and-attack-trees-as-code/README.md); analysis in [chapter 04 attack-trees lab](../04-threat-modeling-methods-and-rating/labs/attack-trees/attack_tree.py) |
| [CTMP 3] Writing Threat Models Alongside Code | [02 section 1](02-threat-modeling-as-code-pytm-and-diagrams.md#1-four-ways-to-keep-the-model-next-to-the-code) | [devsecops-course annotations lab](../../devsecops-course/03-security-requirements-and-threat-modeling/labs/threat-modeling-as-code/README.md); every lab here keeps the model in the repo |
| [CTMP 3] Writing Threat Models With Code | [02 sections 1 and 2](02-threat-modeling-as-code-pytm-and-diagrams.md#1-four-ways-to-keep-the-model-next-to-the-code) | [pytm-lite](labs/pytm-lite/README.md) (`model_shop.py`) |
| [CTMP 3] Writing Threat Models As Code | [02 section 1](02-threat-modeling-as-code-pytm-and-diagrams.md#1-four-ways-to-keep-the-model-next-to-the-code) | [pytm-lite](labs/pytm-lite/README.md) (`shop_model.json`) |
| [CTMP 3] Writing Compliance As Code for PCI-DSS | [04 sections 3 and 4](04-compliance-and-audit-as-code-pci-dss.md#4-writing-compliance-as-code-for-pci-dss) | [pci-compliance-as-code](labs/pci-compliance-as-code/README.md); [devsecops-course Ansible PCI lab](../../devsecops-course/08-iac-configuration-and-compliance-as-code/labs/ansible-pci-dss-hardening/README.md) |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| **Threat Modeling Inside The Code** taught with ThreatSpec | ThreatSpec has had little or no development since about 2020. Keep the annotation idea; for new work use **OWASP pytm** or **Threagile**. |
| **Security Requirements as Code With BDD Security** | BDD-Security (Continuum Security, later IriusRisk) and Gauntlt look unmaintained. Use **pytest-bdd**, **behave**, Cucumber or ZAP Automation Framework tests. |
| **PCI-DSS** without a version | **PCI DSS v4.0.1** is current; v3.2.1 retired March 2024; future-dated v4.0 requirements mandatory since **31 March 2025**. Re-map old rule ids. |
| InSpec as the default compliance-as-code tool | **InSpec 6+ needs a licence key**; **CINC Auditor** is the community build; **OPA/Conftest**, OpenSCAP and Checkov are common alternatives. |
| **Privacy Impact Assessments** (generic) | GDPR **DPIA** (Art. 35) for high-risk processing; in India the **DPDP Act 2023** with **DPDP Rules notified Nov 2025**, phased in. LINDDUN's 2023 update merged Unawareness and Unintervenability. |
| Scrum events from older guides | The **2020 Scrum Guide**: Sprint, Sprint Planning, Daily Scrum, Sprint Review, Sprint Retrospective; refinement is an activity; "Developers" replaced "Development Team". |

## How the three courses overlap here

- **CTMP 3 only** owns this chapter. The Security Champion course's threat modeling and "Modern threat modeling approaches for Agile and DevOps" rows live in [chapter 04](../04-threat-modeling-methods-and-rating/) and [chapter 03](../03-risk-management-and-threat-modeling-overview/); this chapter is the hands-on follow-up.
- The **DevSecOps course** ([chapter 03](../../devsecops-course/03-security-requirements-and-threat-modeling/README.md)) already has the ThreatSpec-style annotation lab, requirements as code and the BDD runner; this chapter links to them and adds pytm-style models, diagrams, attack trees as code, agile backlog checks, PCI checks and privacy.
- Attack tree **analysis** (AND/OR, cost, probability as a method) is in chapter 04; here the focus is writing trees as code.

## Learning order

1. [Lesson 01](01-agile-threat-modeling-and-scrum.md) and the [agile-security-stories lab](labs/agile-security-stories/README.md). About 2 hours.
2. [Lesson 02](02-threat-modeling-as-code-pytm-and-diagrams.md), the [pytm-lite lab](labs/pytm-lite/README.md) and the [diagrams lab](labs/diagrams-and-attack-trees-as-code/README.md); skim the [devsecops annotations lab](../../devsecops-course/03-security-requirements-and-threat-modeling/labs/threat-modeling-as-code/README.md). About 4 hours.
3. [Lesson 03](03-security-requirements-user-stories-and-abuse-cases.md); revisit the agile lab's Gherkin output. About 1.5 hours.
4. [Lesson 04](04-compliance-and-audit-as-code-pci-dss.md) and the [PCI lab](labs/pci-compliance-as-code/README.md). About 1.5 hours.
5. [Lesson 05](05-privacy-threat-modeling-linddun-and-pia.md) and the [privacy lab](labs/privacy-linddun-pia/README.md). About 2 hours.
6. Optional: install real pytm with the [real-tools guide](real-tools/pytm-threagile-and-diagram-tools.md). About 1 hour.

## Lab index

All labs run offline: `.venv/Scripts/python -m pytest appsec-course/05-agile-threat-modeling-as-code -q -p no:cacheprovider`.

| Lab | Course exercises | Tests |
|---|---|---|
| [pytm-lite](labs/pytm-lite/README.md) | Creating threat models with pytm; customizing pytm reports; threat models with code / as code; requirements in threat modeling | 12 |
| [diagrams-and-attack-trees-as-code](labs/diagrams-and-attack-trees-as-code/README.md) | Diagrams as code; UML as code; attack trees using code | 10 |
| [agile-security-stories](labs/agile-security-stories/README.md) | Security requirements for agile; use and abuse cases; Scrum events; BDD security requirements | 8 |
| [privacy-linddun-pia](labs/privacy-linddun-pia/README.md) | PIA and security requirements; privacy threats; privacy threat model | 9 |
| [pci-compliance-as-code](labs/pci-compliance-as-code/README.md) | Compliance and audit as code; compliance as code for PCI DSS | 9 |
| Linked: [annotations](../../devsecops-course/03-security-requirements-and-threat-modeling/labs/threat-modeling-as-code/README.md), [requirements as code](../../devsecops-course/03-security-requirements-and-threat-modeling/labs/security-requirements-as-code/README.md), [BDD security](../../devsecops-course/03-security-requirements-and-threat-modeling/labs/bdd-security-threats/README.md) | Threat modeling inside / alongside the code; BDD runner | in devsecops-course |

Hedged real-tools guide: [pytm, Threagile and diagram tools](real-tools/pytm-threagile-and-diagram-tools.md).

## Exam tips

- **Trigger on change:** new interface, data store, trust boundary, sensitive data, third party or auth change → delta threat model.
- **Scrum 2020:** Sprint (container), Sprint Planning, Daily Scrum, Sprint Review, Sprint Retrospective. Refinement is an activity.
- **Threat model at Sprint Planning; show security results at the Sprint Review; improve at the Retrospective.**
- **Inside / alongside / with / as code:** comments; file in the same repo; Python objects (pytm); declarative YAML/JSON (Threagile).
- **pytm outputs:** `--dfd` (Graphviz), `--seq` (PlantUML), `--report template`, `--json`, `--list`.
- **Abuse case = attacker's user story + mitigation + Given/When/Then of the defense.**
- **Attack trees:** OR takes the cheapest child, AND adds children; block the cheapest path first.
- **PCI DSS v4.0.1;** missing setting = fail; waivers need owner and expiry; evidence tied to a config hash.
- **LINDDUN:** Linking, Identifying, Non-repudiation, Detecting, Data disclosure, Unawareness, Non-compliance. DPIA when two or more EDPB criteria apply.

## Interview / exam questions

<details>
<summary>1. Why does classic threat modeling struggle in agile teams, and what replaces it?</summary>

The design changes every sprint, a long workshop does not fit, and findings in a PDF never reach the backlog. Replace it with a baseline model plus short delta models per security-relevant story, timeboxed sessions run by the team or a champion, output as backlog items, and the model kept as code in the repository.
</details>

<details>
<summary>2. What is Rapid Threat Model Prototyping?</summary>

A lightweight method (Geoffrey Hill): quickly sketch a feature-scoped DFD, mark trust boundaries, apply STRIDE per element, map each threat to a control written as a story, and refine the prototype in later sprints. Fast, feature-scoped, backlog-oriented.
</details>

<details>
<summary>3. Name the Scrum events and one security activity for each.</summary>

Sprint: security in the Sprint Goal and Definition of Done. Sprint Planning: delta threat model, abuse cases, SEC criteria. Daily Scrum: raise security blockers. Sprint Review: demo security criteria and test results. Sprint Retrospective: turn findings into process changes. (Refinement, an activity: write security stories.)
</details>

<details>
<summary>4. Distinguish threat models inside, alongside, with and as code.</summary>

Inside: annotations in source comments (ThreatSpec). Alongside: model file in the same repository, versioned with the code. With code: the model is a program (pytm Python objects). As code: declarative data a tool processes (Threagile YAML, Threat Dragon JSON).
</details>

<details>
<summary>5. How does pytm find threats?</summary>

Elements carry attributes (encrypted, sanitizes input, stores PII). The threat library lists threats with target element types and a condition on those attributes. `process()` evaluates every threat against every element and reports matches with severity and mitigations. Conditions are Python, so review custom libraries like code.
</details>

<details>
<summary>6. How do you customise pytm reports, and why?</summary>

Write your own Markdown template using pytm's `{findings:repeat:...}` blocks and pass it with `--report`. Different audiences need different views (executive summary, developer list, CSV for tickets, compliance mapping) from the same model; never hand-edit generated reports.
</details>

<details>
<summary>7. What does UML as code add to a DFD?</summary>

Sequence diagrams show the order of calls and when tokens travel (finds missing checks and replay windows); class diagrams show which objects hold sensitive fields; misuse case diagrams put attacker goals next to use cases. As text they are reviewed in merge requests and linted in CI.
</details>

<details>
<summary>8. Why write attack trees as code?</summary>

They are versioned and reviewable, and you can compute the cheapest attack (OR = min, AND = sum) and success probability, and show how each control moves the attacker to a costlier path. That justifies control priority.
</details>

<details>
<summary>9. Write an abuse case for a CSV export feature.</summary>

"As an attacker, I want to change the customer id in the export URL so that I can download other customers' orders." STRIDE: Information Disclosure. Mitigation: owner check on export. Test: Given I am logged in as mallory, When I request the export for alice, Then the status is 403.
</details>

<details>
<summary>10. What makes a good agile security requirement?</summary>

Specific, testable, traceable to a threat and an ASVS id, written with the team, and expressed as a security story, a SEC acceptance criterion or a team-wide constraint in the Definition of Done.
</details>

<details>
<summary>11. What is BDD security today?</summary>

Gherkin abuse-case scenarios executed as tests. BDD-Security and Gauntlt are legacy; use pytest-bdd, behave, Cucumber or ZAP Automation Framework tests, tagged with threat ids.
</details>

<details>
<summary>12. Define compliance as code and audit as code.</summary>

Compliance as code: each control written as a versioned automated check or policy (InSpec, OPA/Conftest, OpenSCAP). Audit as code: evidence produced automatically, with what was checked, when, against which exact state (hash), results and approved exceptions.
</details>

<details>
<summary>13. Give five PCI DSS v4.0.1 requirements you can check as code.</summary>

2.2.2 no enabled vendor default accounts; 3.5.1 PAN unreadable at rest; 4.2.1 strong crypto in transit; 8.3.6 passwords at least 12 characters; 8.4.2 MFA for all CDE access; 10.5.1 logs kept 12 months. Verify numbering at PCI SSC.
</details>

<details>
<summary>14. Expand LINDDUN with an example each.</summary>

Linking (one device id shared with two vendors), Identifying (email in analytics), Non-repudiation (signed logs of sensitive actions), Detecting ("email already registered"), Data disclosure (date of birth with no purpose), Unawareness (no deletion request), Non-compliance (no DPIA when required).
</details>

<details>
<summary>15. When is a DPIA required and what does it produce?</summary>

Under GDPR Art. 35 when processing is likely high risk; the EDPB rule of thumb is two or more of nine criteria (sensitive data, large scale, monitoring, profiling...). It produces a description, necessity and proportionality analysis, risks to people and measures, which become privacy requirements in the backlog. In India, check the DPDP Act and Rules for Significant Data Fiduciaries.
</details>

## References

- Threat Modeling Manifesto; OWASP Threat Modeling Cheat Sheet; Adam Shostack, *Threat Modeling*.
- OWASP pytm, Threagile, OWASP Threat Dragon; PlantUML, Graphviz, Mermaid.
- The 2020 Scrum Guide; Autodesk Continuous Threat Modeling handbook (verify).
- PCI DSS v4.0.1 (PCI SSC); InSpec/CINC Auditor, OPA/Conftest, OpenSCAP.
- LINDDUN (linddun.org); GDPR Art. 25 and 35; India DPDP Act 2023 and DPDP Rules 2025.
- Repo: [devsecops-course chapter 03](../../devsecops-course/03-security-requirements-and-threat-modeling/README.md), [devsecops-course chapter 08](../../devsecops-course/08-iac-configuration-and-compliance-as-code/README.md), [CAISP ch5](../../caisp-course/ch5-threat-modeling-ai-systems/README.md).

**Next chapter:** [Chapter 06: Threat model tools, reporting and AI threat modeling](../06-threat-model-tools-reporting-and-ai/README.md)
