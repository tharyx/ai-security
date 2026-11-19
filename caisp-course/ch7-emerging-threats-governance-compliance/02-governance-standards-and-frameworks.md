# AI Governance: Standards, Frameworks, Guidelines and Checklists

> **Chapter:** 7 · **Time:** ~4 hours · **Lab:** none new; use the labs in [07-ai-governance/lab](../../07-ai-governance/lab/) and [08-ai-compliance/lab](../../08-ai-compliance/lab/)
> **You will:** tell apart laws, certifiable standards, voluntary frameworks, guidance and checklists; explain what "NIST RMF" means (two different things); and pick the right document for a given job.

| | |
|---|---|
| **Prerequisites** | [Module 07: AI governance](../../07-ai-governance/README.md), especially [risk management](../../07-ai-governance/03-ai-risk-management.md) and [ISO/IEC 42001](../../07-ai-governance/04-iso-42001-ai-management-system.md) |
| **Deep dives in this repo** | [07 lessons 01 to 06](../../07-ai-governance/README.md) · [08 lesson 05: ISO standards and law vs standard](../../08-ai-compliance/05-iso-standards-and-law-vs-standard.md) · [08 lesson 03: control mapping and evidence](../../08-ai-compliance/03-control-mapping-and-evidence.md) |

> **Educational, not legal advice.** Standards are revised. Check the publisher's site for the current edition and record the date you checked.

---

## 1. Why this matters

Teams ask "are we compliant?" without saying with what. Four kinds of document answer different questions:

| Kind | Question it answers | Binding? | Example |
|---|---|---|---|
| **Law / regulation** | What must we do, or face penalties? | Yes | EU AI Act, state AI laws |
| **Certifiable standard** | Can an auditor certify our management system? | Only if a customer or regulator asks | ISO/IEC 42001, ISO/IEC 27001 |
| **Framework / guidance** | How should we organize our work? | Voluntary | NIST AI RMF, ISO/IEC 23894, Google SAIF, NCSC guidelines |
| **Checklist / catalog** | What should we not forget? What threats exist? | Voluntary | OWASP lists and checklists, MITRE ATLAS |

Simple rule: **law sets the "must", a standard gives a certifiable system, a framework gives a method, a checklist gives a reminder.** Mix them in one program, but never describe a framework as if it were law.

---

## 2. "NIST RMF": two different things

The course syllabus says "NIST RMF". In practice that can mean two documents. Know both so you do not get confused in an interview.

| | **NIST AI RMF 1.0** (NIST AI 100-1, January 2023) | **NIST RMF, SP 800-37 Rev. 2** (December 2018) |
|---|---|---|
| About | Managing risks of **AI systems** | Managing security and privacy risk of **information systems**, mainly US federal |
| Structure | Four functions: **GOVERN, MAP, MEASURE, MANAGE** | Seven steps: Prepare, Categorize, Select, Implement, Assess, Authorize, Monitor |
| Status | Voluntary framework | Required for US federal systems (via FISMA and OMB policy), used widely elsewhere |
| Companion | **NIST AI 600-1** Generative AI Profile (July 2024), 12 GenAI risks | SP 800-53 controls, SP 800-53A assessments |
| Use for | AI risk program, GenAI risk catalog | Authorizing a system to operate (ATO), control selection |

**This course's "NIST RMF" is the AI RMF** (with the GenAI Profile). Learn SP 800-37 as the general security risk process that your AI system may also have to pass through if you sell to US government. They fit together: the AI RMF tells you what AI-specific risks to consider; the 800-37 process records and authorizes the system.

**AI RMF in 60 seconds:**

- **GOVERN:** policies, roles, culture. Applies to everything else.
- **MAP:** understand the context, intended use, who can be harmed.
- **MEASURE:** test and track risks with metrics (security tests, bias tests, monitoring).
- **MANAGE:** prioritize and treat risks, respond to incidents.

Deep lesson with the 12 GenAI risks and the lab: [07 lesson 03](../../07-ai-governance/03-ai-risk-management.md).

---

## 3. The landscape: what each one is, what it is, and when to use it

| Document | What it is | Law, standard or guidance? | When to use it |
|---|---|---|---|
| **NIST AI RMF 1.0 + GenAI Profile (AI 600-1)** | Risk management framework and a GenAI risk catalog | Voluntary guidance (US) | Build the AI risk process; shared language with US customers |
| **NIST SP 800-37 RMF** | Seven-step security risk process for information systems | Required for US federal systems; guidance elsewhere | Authorization to operate; selling to US federal agencies |
| **ISO/IEC 42001:2023** | AI Management System (AIMS): policies, roles, risk, controls, audit, improvement | **Certifiable standard** (voluntary unless a customer or regulator asks) | Prove to customers you run AI responsibly; one system for the whole organization. Lesson: [07 lesson 04](../../07-ai-governance/04-iso-42001-ai-management-system.md) |
| **ISO/IEC 23894:2023** | Guidance on AI risk management, built on ISO 31000 | Guidance (not certifiable) | The risk process inside an AIMS. See [08 lesson 05](../../08-ai-compliance/05-iso-standards-and-law-vs-standard.md) |
| **ISO/IEC 27001:2022** | Information security management system | **Certifiable standard** | The security base. Many AI controls live in Annex A (access control, supplier security, logging). Pair it with 42001 |
| **OWASP GenAI projects** (Top 10 for LLM Apps, Agentic Top 10, MCP Top 10, AI Testing Guide) | Community threat lists and testing guidance | Guidance | Threat modeling, test plans, secure-by-design reviews. See [Chapter 3](../ch3-llm-top-10-vulnerabilities/README.md) |
| **OWASP LLM AI Security & Governance Checklist** (name may differ by version; verify at source) | A checklist for adopting LLMs covering threats, governance, legal, deployment | Guidance / checklist | Kick-off review for a new LLM project; board-level discussion |
| **CSA AI Controls Matrix (AICM)** and **MAESTRO** (Cloud Security Alliance; verify current versions) | AICM is a control matrix for AI cloud services; MAESTRO is a layered threat modeling method for agentic AI | Guidance | AICM: map cloud AI controls and vendor assessments. MAESTRO: threat model agents (see [01 lesson 03](../../01-ai-security-fundamentals/03-ai-threat-modeling.md)) |
| **Google SAIF** (Secure AI Framework, 2023) | A set of AI security principles and practices from Google | Vendor framework (guidance) | Checklist of secure-by-default ideas, especially if you use Google Cloud ([09 lesson 04](../../09-enterprise-architecture/04-gcp-ai-security.md)) |
| **UK NCSC guidelines for secure AI system development** (2023, with CISA and international partners) | Practices across four stages: secure design, development, deployment, operation and maintenance | Government guidance (not law) | Engineering baseline for a delivery team; good for secure SDLC reviews |
| **MITRE ATLAS** | Knowledge base of adversary tactics and techniques against AI systems | Reference | Threat modeling and red team reporting; check atlas.mitre.org for current tactic names |
| **CERT-In AI security audit guidelines** (India) | Audit guidance for AI systems | Guidance for the Indian context | Indian clients and auditors. See [08 lesson 06](../../08-ai-compliance/06-cert-in-ai-security-audit.md) |
| **EU AI Act** | Regulation by risk category | **Law** (EU) | If your AI is placed on the EU market or its output is used in the EU. See [lesson 03](03-eu-ai-act-summary.md) |

Verify at source for anything with a version number or a date. Names and editions of OWASP, CSA and similar community projects change often.

---

## 4. How they fit together: a simple stack

```text
LAW                 EU AI Act, US state laws, GDPR, DPDP        <- what you MUST do
CERTIFIABLE SYSTEM  ISO/IEC 42001 (AI) + ISO/IEC 27001 (security) <- prove it with an audit
RISK METHOD         NIST AI RMF + AI 600-1, ISO/IEC 23894       <- how you decide and treat risk
ENGINEERING         NCSC guidelines, SAIF, CSA AICM             <- how teams build it securely
THREAT CATALOGS     OWASP Top 10s, MITRE ATLAS, MAESTRO         <- what can go wrong
CHECKLISTS          OWASP governance checklist, your own        <- do not forget anything
```

One control, many names: "log model inputs and outputs and review them" maps to NIST AI RMF MEASURE and MANAGE, ISO/IEC 42001 monitoring and Annex A controls, ISO/IEC 27001 logging, and EU AI Act record-keeping for high-risk systems. Build the control once; map it many times ([08 lesson 03](../../08-ai-compliance/03-control-mapping-and-evidence.md) has the lab).

## 5. Which one should I start with? (decision guide)

| Your situation | Start with |
|---|---|
| Small team, first AI feature | OWASP LLM Top 10 + the OWASP governance checklist + NIST AI RMF (GOVERN and MAP) |
| Enterprise AI program | ISO/IEC 42001 as the management system, NIST AI RMF for the risk method, ISO/IEC 27001 as base |
| Selling in the EU | EU AI Act classification first ([08 lesson 01](../../08-ai-compliance/01-eu-ai-act.md)) |
| Selling to US federal agencies | NIST SP 800-37 RMF plus AI RMF |
| Building agents | MAESTRO or OWASP Agentic Top 10 for the threat model; NCSC guidelines for the SDLC |
| Customer asks "are you certified?" | ISO/IEC 27001 and 42001 certificates (explain what the scope covers) |

---

## 6. Common mistakes

- Saying "we follow NIST" without saying which document, or confusing AI RMF with SP 800-37.
- Treating ISO/IEC 42001 certification as proof that a model is safe. It proves a management system exists and is audited, not that every model is secure.
- Calling voluntary frameworks "law".
- Collecting checklists but producing no evidence (see [08 lesson 04](../../08-ai-compliance/04-audit-readiness-and-ai-incidents.md)).

## 7. Interview preparation

<details><summary><b>Q1. Law, standard, framework, checklist: what is the difference?</b></summary>

Law is binding with penalties. A certifiable standard (ISO/IEC 42001, 27001) defines requirements an auditor can certify. A framework (NIST AI RMF) is a voluntary method. A checklist or catalog (OWASP, ATLAS) is a reminder or a threat list.
</details>

<details><summary><b>Q2. What does "NIST RMF" mean?</b></summary>

It can mean the NIST AI Risk Management Framework (AI 100-1, GOVERN, MAP, MEASURE, MANAGE) or the NIST Risk Management Framework SP 800-37 (seven steps for authorizing information systems). I clarify which one is meant. In an AI security course it usually means the AI RMF.
</details>

<details><summary><b>Q3. What is NIST AI 600-1?</b></summary>

The Generative AI Profile (July 2024) for the AI RMF. It lists 12 risks specific to or worsened by GenAI and suggested actions for each.
</details>

<details><summary><b>Q4. What is ISO/IEC 42001 and is it mandatory?</b></summary>

The first certifiable AI Management System standard (2023). It is voluntary unless a customer, partner or regulator requires it. It certifies the management system, not a particular model.
</details>

<details><summary><b>Q5. How do ISO/IEC 42001, 23894 and 27001 relate?</b></summary>

42001 is the AI management system, 23894 is guidance for the AI risk process inside it, and 27001 is the information security management system that provides the security base. They are used together.
</details>

<details><summary><b>Q6. Where does OWASP fit?</b></summary>

OWASP provides threat catalogs (LLM Top 10, Agentic Top 10, MCP Top 10), testing guides and governance checklists. They are guidance, great for threat modeling and test plans, but not a certification.
</details>

<details><summary><b>Q7. What are CSA AICM and MAESTRO?</b></summary>

Cloud Security Alliance projects: AICM is a control matrix for AI in cloud services; MAESTRO is a layered threat modeling approach for agentic AI. Verify the current versions at the source.
</details>

<details><summary><b>Q8. What are the UK NCSC guidelines for secure AI system development?</b></summary>

Government guidelines (published 2023 with CISA and international partners) covering four stages: secure design, secure development, secure deployment, secure operation and maintenance. They are guidance, not law.
</details>

<details><summary><b>Q9. What is Google SAIF?</b></summary>

Google's Secure AI Framework: a set of principles and practices for building and operating AI securely. It is a vendor framework you can use as a checklist of ideas.
</details>

<details><summary><b>Q10. How would you start an AI governance program in a mid-size company?</b></summary>

Inventory AI systems, assign roles, adopt an AI policy, use the NIST AI RMF for risk assessment, add controls from ISO/IEC 27001 and the OWASP lists, and consider ISO/IEC 42001 certification if customers ask. See [Module 07](../../07-ai-governance/README.md).
</details>

---

## 8. Checklist

- [ ] I can sort ten documents into law, standard, framework, catalog or checklist.
- [ ] I can explain both meanings of "NIST RMF".
- [ ] I can say when I would use ISO/IEC 42001 vs NIST AI RMF.
- [ ] I read at least the introduction of the NIST AI RMF and AI 600-1 on nist.gov.

## 9. References

- NIST AI 100-1, Artificial Intelligence Risk Management Framework 1.0 (January 2023); NIST AI 600-1, Generative AI Profile (July 2024); NIST SP 800-37 Rev. 2 (December 2018) at nist.gov.
- ISO/IEC 42001:2023, ISO/IEC 23894:2023, ISO/IEC 27001:2022 at iso.org.
- OWASP Gen AI Security Project (genai.owasp.org); MITRE ATLAS (atlas.mitre.org).
- Cloud Security Alliance AI resources (cloudsecurityalliance.org); Google Secure AI Framework (SAIF); UK NCSC and CISA "Guidelines for secure AI system development" (2023).
