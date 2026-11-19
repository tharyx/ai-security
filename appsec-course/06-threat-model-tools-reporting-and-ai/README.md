# Chapter 06: Threat Model Tools, Reporting and AI Threat Modeling

A threat model is only useful if it is managed, checked against reality and turned into work. This chapter covers how to manage threat models (documentation, backlog, bugs and tickets, code, automation), the main tools and templates (Microsoft Threat Modeling Tool, OWASP Threat Dragon, CAIRIS, IriusRisk, threat modeling as code, freemium tools), how to validate a model ("are we done?"), and AI-assisted threat modeling with StrideGPT and ThreatCompass, with a human review gate. Five offline labs simulate each tool's core idea; GUI and commercial tools get hedged walkthroughs.

> **Safety.** Every lab is a simulation: JSON and XML fixtures, a dict as a ticket tracker, a deterministic stub instead of a real LLM. No network and no API keys. Fake secrets are built at runtime and labelled FAKE. Only test systems you own or have written permission to test.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Tool status and version numbers are hedged: **verify at the source**.

## Syllabus coverage

| Syllabus item | Where to study | Lab |
|---|---|---|
| [CTMP 4] How To Manage Threat Models | [01 section 1](01-managing-threat-models.md#1-how-to-manage-threat-models) (SVG) | [threat-model-management](labs/threat-model-management/README.md) |
| [CTMP 4] Documentation | [01 section 2](01-managing-threat-models.md#2-documentation); [template](templates/threat-model-template.md) | [threat-model-management](labs/threat-model-management/README.md) (`to_markdown`) |
| [CTMP 4] Backlog | [01 section 3](01-managing-threat-models.md#3-backlog) | [threat-model-management](labs/threat-model-management/README.md) (`sync`) |
| [CTMP 4] Bugs, and Tickets | [01 section 4](01-managing-threat-models.md#4-bugs-and-tickets) | [threat-model-management](labs/threat-model-management/README.md) (ticket types, drift) |
| [CTMP 4] Code | [01 section 5](01-managing-threat-models.md#5-code) | [threat-model-management](labs/threat-model-management/README.md) (`check_code_links`) |
| [CTMP 4] Automation | [01 section 6](01-managing-threat-models.md#6-automation) | [threat-model-management](labs/threat-model-management/README.md) (`ci_gate`) |
| [CTMP 4] Threat Modeling Tools and Templates | [02 section 1](02-threat-modeling-tools-and-templates.md#1-the-landscape) | all labs |
| [CTMP 4] Microsoft Threat Modeling Tool | [02 section 2](02-threat-modeling-tools-and-templates.md#2-microsoft-threat-modeling-tool); [real-tools guide](real-tools/microsoft-threat-modeling-tool.md) | [threat-dragon-and-cairis-models](labs/threat-dragon-and-cairis-models/README.md) (same DFD + STRIDE skill, offline) |
| [CTMP 4] OWASP Threat Dragon | [02 section 3](02-threat-modeling-tools-and-templates.md#3-owasp-threat-dragon); [real-tools guide](real-tools/owasp-threat-dragon.md) | [threat-dragon-and-cairis-models](labs/threat-dragon-and-cairis-models/README.md) |
| [CTMP 4] CAIRIS Platform | [02 section 5](02-threat-modeling-tools-and-templates.md#5-cairis-platform); [real-tools guide](real-tools/cairis.md) | [threat-dragon-and-cairis-models](labs/threat-dragon-and-cairis-models/README.md) |
| [CTMP 4] Threat Modeling As Code Tools | [02 section 6](02-threat-modeling-tools-and-templates.md#6-threat-modeling-as-code-tools); [chapter 05](../05-agile-threat-modeling-as-code/README.md) | [chapter 05 pytm-lite](../05-agile-threat-modeling-as-code/labs/pytm-lite/README.md) |
| [CTMP 4] Freemium Tools | [02 section 7](02-threat-modeling-tools-and-templates.md#7-freemium-tools) | [rules-engine-multitier-multicloud](labs/rules-engine-multitier-multicloud/README.md) (IriusRisk CE pattern) |
| [CTMP 4] Threat Model Templates and Examples | [02 section 8](02-threat-modeling-tools-and-templates.md#8-threat-model-templates-and-examples); [template](templates/threat-model-template.md) | fixtures in every lab are worked examples |
| [CTMP 4] Validating Threat Models | [03 section 1](03-validating-threat-models.md#1-what-validation-means) | [threat-model-validation](labs/threat-model-validation/README.md) |
| [CTMP 4] Threat Model Versus Reality | [03 section 2](03-validating-threat-models.md#2-threat-model-versus-reality) | [threat-model-validation](labs/threat-model-validation/README.md) (`model_vs_reality`) |
| [CTMP 4] All Threats Accounted For Risk | [03 section 3](03-validating-threat-models.md#3-all-threats-accounted-for) | [threat-model-validation](labs/threat-model-validation/README.md) (`accounted_for`) |
| [CTMP 4] Mitigations Are Tested | [03 section 4](03-validating-threat-models.md#4-mitigations-are-tested) | [threat-model-validation](labs/threat-model-validation/README.md) (`mitigations_tested`) |
| [CTMP 4] Are We Done Threat Modeling? | [03 section 5](03-validating-threat-models.md#5-are-we-done-threat-modeling) | [threat-model-validation](labs/threat-model-validation/README.md) (`are_we_done`) |
| [CTMP 4] Threat Modeling with OWASP Threat Dragon | [real-tools/owasp-threat-dragon.md](real-tools/owasp-threat-dragon.md) | [threat-dragon-and-cairis-models](labs/threat-dragon-and-cairis-models/README.md) |
| [CTMP 4] Threat Modeling Multi-Tiered Application with Irius Risk | [02 section 4](02-threat-modeling-tools-and-templates.md#4-iriusrisk-multi-tier-and-multi-cloud); [real-tools guide part A](real-tools/iriusrisk-multi-tier-and-multi-cloud.md) | [rules-engine-multitier-multicloud](labs/rules-engine-multitier-multicloud/README.md) (`multitier.json`) |
| [CTMP 4] Threat Modeling for Multi-Cloud with Irius Risk | [02 section 4](02-threat-modeling-tools-and-templates.md#4-iriusrisk-multi-tier-and-multi-cloud); [real-tools guide part B](real-tools/iriusrisk-multi-tier-and-multi-cloud.md) | [rules-engine-multitier-multicloud](labs/rules-engine-multitier-multicloud/README.md) (`multicloud.json`) |
| [CTMP 4] Threat Modeling with StrideGPT | [04 section 2](04-ai-assisted-threat-modeling.md#2-stride-gpt); [real-tools guide](real-tools/stridegpt-and-threatcompass.md) | [llm-assisted-threat-modeling](labs/llm-assisted-threat-modeling/README.md); [CMCPSE stridegpt twin](../../cmcpse-course/ch3-threat-modeling-mcp-architectures/labs/stridegpt/README.md) |
| [CTMP 4] AI Threat Modeling with ThreatCompass | [04 section 3](04-ai-assisted-threat-modeling.md#3-threatcompass) (hedged); [real-tools guide](real-tools/stridegpt-and-threatcompass.md) | [llm-assisted-threat-modeling](labs/llm-assisted-threat-modeling/README.md) (SVG) |
| [CTMP 4] Exploring Completed CAIRIS Models | [02 section 5](02-threat-modeling-tools-and-templates.md#5-cairis-platform); [real-tools/cairis.md](real-tools/cairis.md) | [threat-dragon-and-cairis-models](labs/threat-dragon-and-cairis-models/README.md) (`cairis_explore.py`) |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| **Microsoft Threat Modeling Tool** as a main tool | Still free, Windows-only, infrequent updates; fine for learning STRIDE, weak for CI. |
| **OWASP Threat Dragon** (version not given) | **Version 2.x**, desktop and web; JSON format changed from 1.x, so old models may need migration. |
| **CAIRIS Platform** | Open source; check project activity and the current Docker install before relying on it. |
| **Irius Risk** | Spelled **IriusRisk**; commercial with a free **Community Edition** (limits change). |
| **Threat Modeling As Code Tools** | ThreatSpec is legacy; **OWASP pytm** and **Threagile** are the common choices. |
| **StrideGPT** | Spelled **STRIDE GPT**; open source, multi-provider and local-model support, adds attack trees, DREAD and test cases (verify). |
| **ThreatCompass** | We could not reliably verify its current details; follow the course lab and apply the generic AI-assistant checklist. |

## How the three courses overlap here

- **CTMP 4 only** owns this chapter. The Security Champion course's "Writing Security Requirements for Threat Modeling" row lives in chapter 04 and the agile requirements lessons are in [chapter 05](../05-agile-threat-modeling-as-code/README.md).
- Threat modeling **as code** tools are taught in chapter 05; this chapter only places them in the tool landscape.
- Threat modeling **of** AI systems (prompt injection, poisoning) is in [CAISP chapter 5](../../caisp-course/ch5-threat-modeling-ai-systems/README.md); this chapter is about using AI **to help** threat model.

## Learning order

1. [Lesson 01](01-managing-threat-models.md) and the [management lab](labs/threat-model-management/README.md). About 1.5 hours.
2. [Lesson 02](02-threat-modeling-tools-and-templates.md), the [Threat Dragon and CAIRIS lab](labs/threat-dragon-and-cairis-models/README.md) and the [rules-engine lab](labs/rules-engine-multitier-multicloud/README.md); then one real tool from [real-tools](real-tools/owasp-threat-dragon.md). About 4 hours.
3. [Lesson 03](03-validating-threat-models.md) and the [validation lab](labs/threat-model-validation/README.md). About 1.5 hours.
4. [Lesson 04](04-ai-assisted-threat-modeling.md) and the [LLM-assisted lab](labs/llm-assisted-threat-modeling/README.md); optionally STRIDE GPT with a local model. About 2 hours.
5. Fill in the [template](templates/threat-model-template.md) for one system you know. About 1 hour.

## Lab index

All labs run offline: `.venv/Scripts/python -m pytest appsec-course/06-threat-model-tools-reporting-and-ai -q -p no:cacheprovider`.

| Lab | Course exercises | Tests |
|---|---|---|
| [threat-model-management](labs/threat-model-management/README.md) | How to manage threat models: documentation, backlog, bugs and tickets, code, automation | 8 |
| [threat-model-validation](labs/threat-model-validation/README.md) | Validating threat models; versus reality; accounted for; tested; are we done | 7 |
| [threat-dragon-and-cairis-models](labs/threat-dragon-and-cairis-models/README.md) | Threat modeling with OWASP Threat Dragon; exploring completed CAIRIS models | 8 |
| [rules-engine-multitier-multicloud](labs/rules-engine-multitier-multicloud/README.md) | Multi-tiered application and multi-cloud with IriusRisk (offline pattern) | 7 |
| [llm-assisted-threat-modeling](labs/llm-assisted-threat-modeling/README.md) | Threat modeling with StrideGPT; AI threat modeling with ThreatCompass | 6 |

Hedged real-tool guides: [Microsoft TMT](real-tools/microsoft-threat-modeling-tool.md), [Threat Dragon](real-tools/owasp-threat-dragon.md), [IriusRisk](real-tools/iriusrisk-multi-tier-and-multi-cloud.md), [CAIRIS](real-tools/cairis.md), [STRIDE GPT and ThreatCompass](real-tools/stridegpt-and-threatcompass.md).

## Exam tips

- **Five homes of a threat model:** documentation, backlog, bugs/tickets, code, automation.
- **Bug vs story vs risk acceptance:** exploitable now → bug; design gap → story; not fixing → acceptance with owner, approver, expiry.
- **Stable fingerprint + upsert** stops duplicate tickets; detect drift both ways.
- **Microsoft TMT:** Windows, STRIDE per interaction, `.tm7` models, `.tb7` templates. **Threat Dragon:** OWASP, v2, desktop + web, JSON. **CAIRIS:** environments, personas/tasks, assets, attackers, risks. **IriusRisk:** components + questionnaire → rules → countermeasures → residual risk.
- **Validation = versus reality + accounted for + tested + exit criteria.**
- **AI drafts, humans decide:** ground, check coverage, parse as data, redact, sign off.

## Interview / exam questions

<details>
<summary>1. How do you keep a threat model alive after the workshop?</summary>

Store it next to the code, give each threat a stable id, put mitigations in the backlog, track vulnerabilities as bugs and acceptances as tickets with expiry, link mitigations to code and tests, and automate report generation, ticket sync, validation and review reminders.
</details>

<details>
<summary>2. When is a threat a bug and when is it a story?</summary>

A bug when the weakness is already exploitable in existing code (it has an affected version and a fix SLA). A story when it is a design gap or a control still to build. An accepted risk is a separate ticket with owner, approver and expiry.
</details>

<details>
<summary>3. Why does a naive "create a ticket per open threat" integration fail?</summary>

It creates duplicates on every run and floods the backlog until people filter security tickets out. Use a stable fingerprint, upsert, update severity in place, and report drift instead.
</details>

<details>
<summary>4. Compare Microsoft Threat Modeling Tool and OWASP Threat Dragon.</summary>

Both draw DFDs and record STRIDE threats. TMT is a free Windows desktop app with a strong template that auto-generates threats per interaction, but its files are hard to diff. Threat Dragon is an OWASP open-source desktop and web app with JSON models that fit git and CI, and a simpler rule engine.
</details>

<details>
<summary>5. What is special about CAIRIS?</summary>

It integrates usability (personas, tasks), requirements and security (assets, attackers, threats, vulnerabilities, risks, countermeasures) and models them per environment, so the same asset can have different risks in different contexts.
</details>

<details>
<summary>6. How do you explore a completed CAIRIS model?</summary>

List environments; sort risks by score; follow attacker → threat → vulnerability → asset for the top risks; find assets at risk with no requirement or countermeasure; check which persona tasks touch high-risk assets.
</details>

<details>
<summary>7. Describe how IriusRisk generates a threat model.</summary>

Components from a library are placed in trust zones; questionnaire answers set their properties; a rules engine adds threats and countermeasures from libraries; you set countermeasure states and see inherent versus residual risk; required countermeasures can be pushed to a tracker; reports are generated.
</details>

<details>
<summary>8. What changes when you threat model a multi-cloud system?</summary>

Each cloud is a trust zone with its own services, controls and shared responsibility split; generic threats map to provider-specific controls; and the links between clouds (copy jobs, federation, shared static keys) become first-class elements with their own threats. Prefer workload identity federation to static keys.
</details>

<details>
<summary>9. What questions do you ask before using a freemium threat modeling tool?</summary>

Limits of the free tier, where the model is stored and who can access it, export in an open format, licence terms for commercial use, and integrations.
</details>

<details>
<summary>10. What does "threat model versus reality" mean and how do you automate it?</summary>

Compare the model with what is deployed and observed: cloud inventory, Kubernetes services, gateway routes, OpenAPI specs, flow logs. Report shadow components, stale components and unmodeled flows in CI.
</details>

<details>
<summary>11. When is a threat "accounted for"?</summary>

When it has a valid decision: mitigated (described, implemented, tested), accepted (owner, approver, reason, expiry), transferred (to whom, with evidence), avoided (feature removed) or not applicable (with a reason). Also every component and boundary flow must have been analysed.
</details>

<details>
<summary>12. How do you prove a mitigation works?</summary>

Link it to a test that performs the attack or checks the control (unit, BDD abuse case, DAST rule, policy test), run it in CI and require it to pass. A missing or failing test means "not proven".
</details>

<details>
<summary>13. When are you done threat modeling?</summary>

For a version: model matches reality, every threat has a decision, every mitigation has a passing test, the model was reviewed for this version and a next review date is set. For the product: never; re-model on change triggers and periodically.
</details>

<details>
<summary>14. What are the main risks of LLM-assisted threat modeling?</summary>

Hallucinated components or threats, missed context and uneven coverage, non-determinism, leakage of architecture data and secrets to a provider, prompt injection from documents, and ratings without context. Controls: redact or use local models, parse output as data, ground against the DFD, check coverage, human sign-off.
</details>

<details>
<summary>15. What is STRIDE GPT and how should you use its output?</summary>

An open-source Streamlit app that uses an LLM to draft STRIDE threats, attack trees, mitigations, DREAD scores and tests from an app description, with cloud or local models. Treat its output as a draft: review every threat, add missing ones, and keep the reviewed model in your own tool or repository.
</details>

## References

- Adam Shostack, *Threat Modeling: Designing for Security*; Threat Modeling Manifesto; OWASP Threat Modeling Cheat Sheet.
- Microsoft Threat Modeling Tool docs; OWASP Threat Dragon; CAIRIS (cairis.org) and S. Faily, *Designing Usable and Secure Software with IRIS and CAIRIS*; IriusRisk; OWASP pytm; Threagile.
- STRIDE GPT (GitHub); OWASP Top 10 for LLM Applications; MITRE ATLAS.
- Repo: [chapter 05](../05-agile-threat-modeling-as-code/README.md), [CMCPSE chapter 3 labs](../../cmcpse-course/ch3-threat-modeling-mcp-architectures/README.md), [CAISP chapter 5](../../caisp-course/ch5-threat-modeling-ai-systems/README.md).

**Next chapter:** [Chapter 07: Secure design principles and case studies](../07-secure-design-principles-and-case-studies/README.md)
