# Chapter 5: Threat modeling AI systems

> **Time:** ~15 hours · **You will:** model an LLM application with a data flow diagram and STRIDE, use AI threat libraries (OWASP LLM Top 10, MITRE ATLAS, BIML, the MIT AI Risk Repository, the AI Incident Database, an AI threat map), and rate and manage the risks.

## Syllabus coverage

Every syllabus line of the chapter, in course order. "Existing" links go to lessons that were already in this repository.

| Syllabus item | Where to study | Lab |
|---|---|---|
| What is Threat Modeling | [01 Foundations, section 1](01-threat-modeling-foundations.md); existing: [Module 01, lesson 03](../../01-ai-security-fundamentals/03-ai-threat-modeling.md) | exercise 1 in lesson 01 |
| Why Threat Model? | [01 Foundations, section 2](01-threat-modeling-foundations.md) | - |
| Threat Modeling Challenges | [01 Foundations, section 3](01-threat-modeling-foundations.md) | - |
| Threat Modeling Benefits | [01 Foundations, section 4](01-threat-modeling-foundations.md) | - |
| The Threat Model Parlance | [01 Foundations, section 5](01-threat-modeling-foundations.md) | - |
| &nbsp;&nbsp;What are Assets? | [01 Foundations, 5.1](01-threat-modeling-foundations.md) | `assets:` in [`dfd.yaml`](labs/threat-model-ai-system/dfd.yaml) |
| &nbsp;&nbsp;Weaknesses and Vulnerability | [01 Foundations, 5.3](01-threat-modeling-foundations.md) | - |
| &nbsp;&nbsp;Risk Management Stages | [01 Foundations, 5.5](01-threat-modeling-foundations.md); [05 Rating, section 1](05-rating-and-managing-risks.md) | - |
| STRIDE Methodology | [03 STRIDE, sections 1-2](03-stride-for-llm-apps.md); existing: [Module 01 lesson 03, 2.2](../../01-ai-security-fundamentals/03-ai-threat-modeling.md) | [`tm_tool.py`](labs/threat-model-ai-system/tm_tool.py) `STRIDE_PER_ELEMENT` |
| Diagramming for Threat Modeling | [02 DFDs](02-dfd-and-llm-architecture.md) | `--mermaid` output |
| &nbsp;&nbsp;Data Flow Diagram | [02 DFDs, sections 1-2](02-dfd-and-llm-architecture.md) | [`dfd.yaml`](labs/threat-model-ai-system/dfd.yaml) |
| &nbsp;&nbsp;DFD Components | [02 DFDs, section 2](02-dfd-and-llm-architecture.md) ([notation SVG](../../images/caisp-ch5-dfd-notation.svg)) | `validate_dfd()` rules |
| An LLM Application Architecture | [02 DFDs, sections 3-4](02-dfd-and-llm-architecture.md) | - |
| &nbsp;&nbsp;Simple LLM Architecture | [02 DFDs, section 3](02-dfd-and-llm-architecture.md) ([SVG](../../images/caisp-ch5-llm-architecture.svg)) | - |
| &nbsp;&nbsp;DFD for an LLM Architecture | [02 DFDs, section 4](02-dfd-and-llm-architecture.md) ([SVG](../../images/caisp-ch5-llm-dfd.svg)) | [`dfd.yaml`](labs/threat-model-ai-system/dfd.yaml) |
| STRIDE Threats for LLM Applications | [03 STRIDE, section 3](03-stride-for-llm-apps.md) | [`tm_tool.py`](labs/threat-model-ai-system/tm_tool.py) |
| AI Threat Libraries | [04 Threat libraries](04-ai-threat-libraries.md) | [`threat_library.yaml`](labs/threat-model-ai-system/threat_library.yaml) |
| &nbsp;&nbsp;STRIDE | [04, section 2](04-ai-threat-libraries.md); [03](03-stride-for-llm-apps.md) | `stride` field |
| &nbsp;&nbsp;OWASP LLM Top 10 | [04, section 3](04-ai-threat-libraries.md); existing: [Module 01 lesson 03, 2.5](../../01-ai-security-fundamentals/03-ai-threat-modeling.md); [2023 vs 2026](../ch3-llm-top-10-vulnerabilities/owasp-llm-2023-vs-2026.md) | `owasp_llm` field |
| &nbsp;&nbsp;Mitre ATLAS | [04, section 4](04-ai-threat-libraries.md); existing: [Module 01 lesson 03, 2.4](../../01-ai-security-fundamentals/03-ai-threat-modeling.md) | `atlas` field |
| &nbsp;&nbsp;BIML Risk Framework | [04, section 5](04-ai-threat-libraries.md) | `biml` field |
| &nbsp;&nbsp;AI Risk Repository | [04, section 6](04-ai-threat-libraries.md) | - (browse airisk.mit.edu) |
| &nbsp;&nbsp;AI Incident Database | [04, section 7](04-ai-threat-libraries.md) | - (search incidentdatabase.ai) |
| &nbsp;&nbsp;AI Threat Map | [04, section 8](04-ai-threat-libraries.md) | - |
| Rating and Managing Risks | [05 Rating and managing risks](05-rating-and-managing-risks.md) | `rate()`, `build_register()` |
| &nbsp;&nbsp;Risk Management Meets Threat Modeling | [05, section 1](05-rating-and-managing-risks.md) | risk register output |
| &nbsp;&nbsp;Risk Management Strategies | [05, section 2](05-rating-and-managing-risks.md) | `treatment()` |
| &nbsp;&nbsp;Example Risk Rating Methodology | [05, section 3](05-rating-and-managing-risks.md) ([matrix SVG](../../images/caisp-ch5-risk-matrix.svg)); IriusRisk and free tools in [05, section 5](05-rating-and-managing-risks.md) | `rate()`, `SEVERITY_MATRIX` |
| Hands-On Exercises: Threat Modeling an AI System | [06 Hands-on](06-hands-on-threat-modeling-an-ai-system.md) | [`labs/threat-model-ai-system/`](labs/threat-model-ai-system/) |
| Course outcome: Apply STRIDE methodology to model AI threats | [03](03-stride-for-llm-apps.md), [06](06-hands-on-threat-modeling-an-ai-system.md) | `demo.py` |
| Course outcome: Leverage AI threat libraries and frameworks | [04](04-ai-threat-libraries.md) | `threat_library.yaml` |
| Course outcome: Perform risk rating with IriusRisk tools | [05, sections 3 and 5](05-rating-and-managing-risks.md) (method, then the IriusRisk workflow, hedged) | `rate()`; the commercial tool itself is not run here |

**Not covered in depth:** IriusRisk is a commercial product. The lab teaches the same steps (import architecture, generate threats, rate, record countermeasures) with code. Follow the course's own IriusRisk lab for the clicks.

## Learning order

1. [01 Foundations](01-threat-modeling-foundations.md): vocabulary and the four questions.
2. [02 DFDs and an LLM architecture](02-dfd-and-llm-architecture.md): draw the system.
3. [03 STRIDE for LLM apps](03-stride-for-llm-apps.md): find threats per element.
4. [04 AI threat libraries](04-ai-threat-libraries.md): enrich with OWASP, ATLAS, BIML and the other libraries.
5. [05 Rating and managing risks](05-rating-and-managing-risks.md): score, rank, treat.
6. [06 Hands-on](06-hands-on-threat-modeling-an-ai-system.md): run the lab end to end.

Run the chapter tests: `python -m pytest caisp-course/ch5-threat-modeling-ai-systems` (17 tests).

## Exam and interview tips for this chapter

* **Know the DFD symbols and the STRIDE-per-element table by heart.** Questions often give a small diagram and ask which threats apply to an element.
* **Say the edition** when you quote the OWASP LLM Top 10 ("2023 v1.1, LLM01 Prompt Injection"). The numbering changed in 2025 and 2026.
* **Separate the words:** asset, threat, weakness, vulnerability, risk, control. Wrong word choice costs marks.
* **Risk = likelihood × impact.** Be ready to run the OWASP matrix on a small example, and to name the four treatments.
* **Libraries answer different questions.** OWASP is a checklist, ATLAS is attacker steps, BIML is architecture, MIT is breadth, AIID is evidence.
* **Hedge unstable facts** (counts, versions, tactic names) and say where you would verify them.

## 15 interview / exam-style questions

<details><summary><b>Q1. What is threat modeling, and when should you do it?</b></summary>

A structured way to find and rank what can go wrong with a system, and decide what to do about it. Do it at design time (cheapest), again when the design changes, and when new threat information appears. The four questions: what are we working on, what can go wrong, what will we do, did we do a good job.
</details>

<details><summary><b>Q2. Why is threat modeling especially useful for LLM applications?</b></summary>

Many risks are design-level: instructions and data share one text channel, model output can trigger tools, and untrusted content (documents, web pages, emails) enters the prompt. Scanners do not see these. A diagram review shows the flows (retrieved text back into the prompt, model output into a tool) where the dangerous paths are.
</details>

<details><summary><b>Q3. Weakness, vulnerability, threat, risk: define each.</b></summary>

A weakness is a type of flaw (CWE). A vulnerability is a specific exploitable instance in a system (CVE). A threat is a possible event that uses it. Risk is the likelihood and impact of that event. A control reduces likelihood or impact.
</details>

<details><summary><b>Q4. Name the five DFD symbols and the rule about data flows.</b></summary>

External entity, process, data store, data flow, trust boundary. Every data flow must have a process at one end: data does not move by itself, so entity-to-store flows are invalid.
</details>

<details><summary><b>Q5. Which STRIDE letters apply to each DFD element type?</b></summary>

External entity: S, R. Process: S, T, R, I, D, E. Data store: T, R, I, D (R mostly for logs). Data flow: T, I, D.
</details>

<details><summary><b>Q6. Give one AI-specific example for each STRIDE letter.</b></summary>

S: look-alike model endpoint or fake MCP server. T: prompt injection or data poisoning. R: no record of which prompt, context and model version caused a tool call. I: cross-tenant retrieval or system prompt leak. D: huge or looping prompts (denial of wallet). E: an agent uses a powerful shared token for a low-privilege user (confused deputy).
</details>

<details><summary><b>Q7. Why is prompt injection filed under Tampering?</b></summary>

It changes the behavior (logic) of the process through its input. It is also an entry point for Elevation of privilege (the injected text triggers a privileged tool) and Information disclosure, so a good threat statement names the flow and the asset.
</details>

<details><summary><b>Q8. What is the OWASP Top 10 for LLM Applications, and what are its limits?</b></summary>

A community list of the ten most critical LLM application risks (2023 v1.1 in the course; 2025 and 2026 editions renumber and rename items). It is a coverage checklist, not a threat model: categories are broad, the order is not your priority, and the list changes between editions.
</details>

<details><summary><b>Q9. What is MITRE ATLAS and how do you use it in a threat model?</b></summary>

An ATT&CK-style knowledge base of tactics, techniques and case studies for attacks on AI systems. Use it to name how an attacker would carry out a threat, to feed red-team and detection work, and to give threats shared IDs. Copy IDs from the live site because they and the tactic names change (for example "ML Model Access" is now "AI Model Access").
</details>

<details><summary><b>Q10. What is BIML and what is different about it?</b></summary>

The Berryville Institute of Machine Learning publishes architectural risk analyses: 78 risks for generic ML systems (2020) and 81 for LLMs (2024, with 23 tied to black-box issues). It is architecture-first: risks are grouped by component of the ML/LLM system, so it finds design flaws, especially when you own the model or data pipeline.
</details>

<details><summary><b>Q11. What are the MIT AI Risk Repository and the AI Incident Database used for?</b></summary>

The Repository (airisk.mit.edu) is a living database of 1,700+ risks from 74 frameworks with a causal and a domain taxonomy (7 domains, 23 subdomains): a breadth check and vocabulary source. The AI Incident Database (incidentdatabase.ai) holds real reported incidents: evidence that a threat is real. Neither is a threat model of your system.
</details>

<details><summary><b>Q12. What is an "AI threat map"?</b></summary>

A map of AI threats across the lifecycle (data, training, model, deployment, use). There is no single authoritative public standard; examples include CSA MAESTRO layers and vendor or OWASP threat maps. Use it to see where each threat appears and who owns the control.
</details>

<details><summary><b>Q13. Walk through the OWASP risk rating method.</b></summary>

Score 8 likelihood factors (threat agent: skill, motive, opportunity, size; vulnerability: discovery, exploit, awareness, detection) and 8 impact factors (technical: C, I, A, accountability; business: financial, reputation, non-compliance, privacy) from 0 to 9. Average each side, convert to LOW (under 3), MEDIUM (3 to under 6), HIGH (6 to 9), then read the matrix: HIGH likelihood and HIGH impact is CRITICAL.
</details>

<details><summary><b>Q14. What are the four risk treatments? Give an AI example of each.</b></summary>

Avoid: remove the email tool. Mitigate: ACL filter before retrieval, tool authorization with the user's identity. Transfer: insurance or a provider contract (you still carry reputation risk). Accept: low risk in an internal FAQ bot, with an owner, a reason and a review date.
</details>

<details><summary><b>Q15. Why do many teams avoid DREAD, and what is IriusRisk?</b></summary>

DREAD scores are subjective and not repeatable, "Discoverability" rewards obscurity, and it mixes likelihood and impact. Many teams, and later Microsoft guidance, moved away from it. IriusRisk is a commercial threat-modeling platform (verify the current free community edition): you import or draw the architecture, rules generate threats and countermeasures, you rate and track residual risk. Free alternatives: OWASP Threat Dragon, Microsoft Threat Modeling Tool, or threat modeling as code as in this lab.
</details>

## References

* Threat Modeling Manifesto: threatmodelingmanifesto.org
* OWASP Top 10 for LLM Applications (genai.owasp.org), OWASP Risk Rating Methodology, OWASP Threat Dragon
* MITRE ATLAS: atlas.mitre.org
* BIML: berryvilleiml.com
* MIT AI Risk Repository: airisk.mit.edu · AI Incident Database: incidentdatabase.ai
* Microsoft STRIDE and Threat Modeling Tool documentation: learn.microsoft.com
* IriusRisk: iriusrisk.com
* NIST AI RMF (AI 100-1): nist.gov/itl/ai-risk-management-framework
* Existing repo lessons: [Module 01 lesson 02](../../01-ai-security-fundamentals/02-ai-system-architecture-and-trust-boundaries.md), [lesson 03](../../01-ai-security-fundamentals/03-ai-threat-modeling.md), [Module 07 lesson 03](../../07-ai-governance/03-ai-risk-management.md)
