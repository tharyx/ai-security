# Lesson 04: AI threat libraries

> **Chapter 5** · **Time:** ~3 hours · **You will:** name the seven threat libraries in the course (STRIDE, OWASP LLM Top 10, MITRE ATLAS, BIML, the MIT AI Risk Repository, the AI Incident Database, an AI threat map), say what each is good and bad at, and combine them in one threat model.

| | |
|---|---|
| **Syllabus lines** | AI Threat Libraries · STRIDE · OWASP LLM Top 10 · Mitre ATLAS · BIML Risk Framework · AI Risk Repository · AI Incident Database · AI Threat Map |
| **Already in this repo** | [Module 01, lesson 03](../../01-ai-security-fundamentals/03-ai-threat-modeling.md), sections 2.3 to 2.5 (AI lenses, ATLAS, OWASP LLM / Agentic / MCP lists); [OWASP LLM 2023 vs 2026](../ch3-llm-top-10-vulnerabilities/owasp-llm-2023-vs-2026.md) |
| **Lab** | [`labs/threat-model-ai-system/threat_library.yaml`](labs/threat-model-ai-system/threat_library.yaml): a local library that tags each threat with OWASP, ATLAS and BIML-style fields |
| **Prerequisite** | [Lesson 03](03-stride-for-llm-apps.md) |

---

## 1. What is a threat library?

A **threat library** is a reusable catalogue of threats, attacks or risks. You use it so that you do not start from a blank page and do
not forget a whole category. Libraries differ in *what kind of thing* they list, so they answer different questions:

| Library | Kind of list | Best question it answers |
|---|---|---|
| STRIDE | Six generic threat classes | "Which threat classes apply to this element?" |
| OWASP Top 10 for LLM Applications | Ten risk categories for LLM apps | "Did we cover the well-known LLM application risks?" |
| MITRE ATLAS | Tactics and techniques of attacks on AI, with case studies | "How would an attacker actually do this, step by step?" |
| BIML risk framework | Architectural risks by component of an ML or LLM system | "Which design-level risks sit in each component?" |
| MIT AI Risk Repository | A large database of risks from many frameworks, with taxonomies | "What risks have other frameworks named, and how do they group?" |
| AI Incident Database | Real-world AI incidents reported in the news and by researchers | "Has this really happened to someone?" |
| AI threat map | A map of AI threats across the lifecycle | "Where in the lifecycle does each threat appear?" |

> Facts about these projects change (versions, counts, names). Treat every number below as "as of November 2026, verify at the source".

## 2. STRIDE (as a library)

* **What:** six generic classes. Already covered in [lesson 03](03-stride-for-llm-apps.md).
* **How to use:** per element, to decide *where to look*.
* **Strengths:** simple, complete in theory, works on any system, easy to teach.
* **Limits:** not AI-specific; it will not name "poisoned embedding" or "model backdoor"; it does not rate risk.

## 3. OWASP Top 10 for LLM Applications

* **What:** a community list of the ten most critical risks for LLM applications, from the OWASP GenAI Security Project (genai.owasp.org).
* **Editions.** The course uses the **2023 (v1.1)** names. Newer editions exist, with different numbering. Always say which edition you mean.

| 2023 v1.1 (course) | 2025 edition | 2026 edition |
|---|---|---|
| LLM01 Prompt Injection | 01 Prompt Injection | 01 Prompt Injection |
| LLM02 Insecure Output Handling | 05 Improper Output Handling | 10 Improper Output Handling |
| LLM03 Training Data Poisoning | 04 Data and Model Poisoning | 05 Data and Model Poisoning |
| LLM04 Model Denial of Service | 10 Unbounded Consumption | 06 Unbounded Consumption |
| LLM05 Supply Chain Vulnerabilities | 03 Supply Chain | 04 Supply Chain |
| LLM06 Sensitive Information Disclosure | 02 Sensitive Information Disclosure | 02 Sensitive Information Disclosure |
| LLM07 Insecure Plugin Design | folded into Excessive Agency / Improper Output Handling (tool and MCP security today) | same |
| LLM08 Excessive Agency | 06 Excessive Agency | 03 Excessive Agency |
| LLM09 Overreliance | 09 Misinformation | 07 Misinformation |
| LLM10 Model Theft | not a separate entry; covered under other items | same |
| (new) | 07 System Prompt Leakage; 08 Vector and Embedding Weaknesses | 08 Hidden Context Exposure; 09 Vector and Embedding Weaknesses |

(See [`owasp-llm-2023-vs-2026.md`](../ch3-llm-top-10-vulnerabilities/owasp-llm-2023-vs-2026.md) for the detailed mapping, and verify the lists at genai.owasp.org.)

* **How to use in a threat model:** as a **coverage checklist** after STRIDE. For each of the ten, ask "does this apply to one of our elements or flows?" and tag the threat. The lab's `owasp_llm` field does this (2023 names).
* **Strengths:** familiar to everyone, good for communication and training, has mitigations.
* **Limits:** it is a *risk list*, not a threat model; categories are broad ("Prompt Injection" hides many attacks); the order is not *your* priority; it changes between editions.

## 4. MITRE ATLAS

* **What:** ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) is a knowledge base of **tactics** (attacker goals) and **techniques** (how), plus real **case studies**, modeled on MITRE ATT&CK.
* **Tactics in the course (14, in attack order):** Reconnaissance, Resource Development, Initial Access, ML Model Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Collection, ML Attack Staging, Exfiltration, Impact.
* **Newer naming.** In 2026 ATLAS has about 16 tactics, 14 adapted from ATT&CK plus two AI-specific. The course's "ML Model Access" and "ML Attack Staging" are now called **AI Model Access** and **AI Attack Staging** (ATLAS data 2026.07). Secondary sources report a further rename of "AI Attack Staging" to "AI Attack Adaptation" in v2026.08; this is unconfirmed. Tactic and technique IDs differ across sources, so **copy IDs from atlas.mitre.org**, not from slides.
* **How to use:** to give each AI threat a **shared name** and to design detections and red-team tests. For a threat "indirect prompt injection", find the matching technique and cite its current ID. The lab's `atlas` field stores technique **names** on purpose.
* **Strengths:** attacker-centric, step by step, real case studies, familiar to SOC and red teams (ATT&CK style).
* **Limits:** knowledge of *known* attacks, so it lags new ones; techniques are not rated for your system; IDs and names move.

## 5. BIML risk framework

* **What:** the Berryville Institute of Machine Learning publishes **architectural risk analyses**. The 2020 analysis of a generic ML process listed **78 risks**. The 2024 "An Architectural Risk Analysis of Large Language Models" lists **81 risks**, **23** of them tied to black-box issues. Risks are grouped by component of the ML/LLM system.
* **Component view (the 2020 ML structure, paraphrased):** raw data in the world, dataset assembly, datasets, learning algorithm, evaluation, inference algorithm, model. The 2024 LLM work reorganizes and adds black-box themes. **Check the current documents at berryvilleiml.com for exact component names and risk numbers.**
* **How to use:** after STRIDE, walk the **components** and ask "which BIML-style risks sit here?". The lab's `biml:` field gives a *BIML-style* component and theme (paraphrased by us, **not** the official risk numbers).
* **Strengths:** architecture-first (design flaws, not just attacks); fits the "secure by design" step; useful when you build or fine-tune models, not only call an API.
* **Limits:** long (80+ risks), written for ML builders rather than app teams, no ratings or detections, and it is a document, not a data feed.

## 6. MIT AI Risk Repository

* **What:** a living database at airisk.mit.edu that collected **1,700+ risks from 74 frameworks**, with two taxonomies: a **causal taxonomy** (who or what caused it: human or AI, intentional or unintentional, before or after deployment) and a **domain taxonomy** (**7 domains and 23 subdomains**, for example discrimination and toxicity, privacy and security, misinformation, malicious actors, human-computer interaction, socioeconomic and environmental, AI system safety and limitations).
* **How to use:** as a **breadth check and a vocabulary source**. Filter by domain (for example "Privacy and security") to see how other frameworks name risks, then map them to your elements. Use the causal view to separate "attacker did it" from "the system failed by itself".
* **Strengths:** very broad, cites sources, good for governance and risk teams, downloadable.
* **Limits:** a catalogue of risks, not threats on *your* architecture; not ranked; overlaps between source frameworks; counts grow as it is updated.

## 7. AI Incident Database (AIID)

* **What:** incidentdatabase.ai, a public collection of reports of harms or near-harms caused by AI systems (chatbots, vision, recommendation, autonomous systems).
* **How to use:** to **prove a threat is real** and to write convincing scenarios ("this happened to another company"). Search by technology or harm type; cite the incident ID. Add your own lessons to the model: "incident X shows that threat T applies to our F9 flow".
* **Strengths:** real-world evidence, wide range of harms (not only security), useful for awareness and for executives.
* **Limits:** based on public reports, so quality and detail vary; many entries are about safety or ethics, not security; absence of an incident does not mean absence of a threat.

## 8. AI threat map

* **What:** the term "AI threat map" does not point to one single authoritative public resource that we could confirm. It is used for **a map of AI threats across the lifecycle** (data, training, model, deployment, use). The course provides its own version.
* **Public examples of the idea:** the CSA **MAESTRO** layered threat-modeling framework (layers from foundation models up to agent ecosystems), the Check Point "AI Risk Map" white paper, and OWASP GenAI threat maps. Verify each at its source.
* **How to use:** to see **where in the lifecycle** a threat appears and who owns the control (data team, ML team, platform team, app team). Mark each threat from your table on the map, then check whether every stage has an owner.
* **Strengths:** shows lifecycle and ownership; helps non-security teams see their part.
* **Limits:** no standard, so two maps do not agree; usually coarse; not a source of IDs.

## 9. Putting the libraries together

A practical order for a 90-minute session:

1. **STRIDE per element** finds where to look. (Lesson 03.)
2. **OWASP LLM Top 10** checks nothing obvious is missing. Tag threats.
3. **ATLAS** names how an attacker would do it. Tag techniques; hand the list to red team and detection engineers.
4. **BIML** gives design-level risks per component, especially when you own the model or the data pipeline.
5. **MIT Repository** is a breadth check and a link to governance frameworks.
6. **AIID** supplies real incidents to make the findings credible.
7. **A threat map** shows the lifecycle stage and the owning team.

The lab bakes steps 1 to 3 (and a BIML-style tag) into one YAML file. One entry looks like this:

```yaml
- id: TL-04
  title: Indirect prompt injection through retrieved or ingested content
  stride: T
  applies_to: [data_flow, process]
  when_tags: [untrusted_content]
  owasp_llm: [LLM01 Prompt Injection]
  atlas: [LLM Prompt Injection]
  biml: {component: raw data in the world, theme: attacker-controlled text reaches the prompt}
  factors: {agent: 7, vuln: 8, tech: 7, business: 7}
  mitigated_by: [schema_validation, tool_authz, human_approval, integrity_check]
```

All 20 entries are **paraphrases written for this lab**. They are not official text from OWASP, MITRE or BIML.

## 10. Hands-on

1. Open [`threat_library.yaml`](labs/threat-model-ai-system/threat_library.yaml). Pick the 18 `GENERIC` rows from the tool output (for example *Elevation of privilege on the LLM*). Write one new entry for one of them. Use `stride`, `applies_to`, `when_tags`, `owasp_llm`, `atlas`, `biml`, `factors` and `mitigation`.
2. Re-run `tm_tool.py`. The count of `GENERIC` threats should drop. The tests check that the library still loads and covers all six STRIDE letters.
3. Visit atlas.mitre.org and replace one technique name in your entry by its current ID in a comment. Note the date.
4. Search incidentdatabase.ai for one incident that matches one of your threats and write its ID next to the entry.

## 11. Common mistakes

* Treating the OWASP Top 10 as a complete threat model.
* Copying technique IDs from old slides. They change.
* Using one library only. OWASP is good for checklists, ATLAS for attacker steps, BIML for architecture.
* Quoting counts (risks, frameworks) without a date and a source.

## 12. Quick check

1. Which library would you open to see *how* an attacker poisons training data step by step?
2. What is the difference between a risk list (OWASP, MIT) and a technique catalogue (ATLAS)?
3. Why does the lab store ATLAS technique *names* rather than IDs?
4. Name one strength and one limit of the AI Incident Database.

## 13. References

* OWASP GenAI Security Project, Top 10 for LLM Applications: genai.owasp.org
* MITRE ATLAS: atlas.mitre.org
* Berryville Institute of Machine Learning (BIML): berryvilleiml.com (2020 ARA of ML systems; 2024 ARA of LLMs)
* MIT AI Risk Repository: airisk.mit.edu
* AI Incident Database: incidentdatabase.ai
* CSA MAESTRO threat modeling framework for agentic AI (cloudsecurityalliance.org)
