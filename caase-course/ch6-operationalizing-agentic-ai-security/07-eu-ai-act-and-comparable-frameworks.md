# 07. EU AI Act and Comparable Frameworks for Autonomous Systems

> **Chapter 6 · Time:** ~2.5 hours · **You will:** place an autonomous agent under the EU AI Act, know the Digital Omnibus dates, and compare it with other frameworks.
> **Maps to:** EU AI Act (Reg. (EU) 2024/1689) as amended by the Digital Omnibus (Reg. (EU) 2026/1744) · [08-ai-compliance lesson 01](../../08-ai-compliance/01-eu-ai-act.md) · [CAISP ch7](../../caisp-course/ch7-emerging-threats-governance-compliance/README.md) · ISO/IEC 42001 · NIST AI RMF
> **This is education, not legal advice.** Dates and article details change: verify at EUR-Lex and with counsel.

## 1. Why this matters

- Agents act, so the question is not "what does the model say?" but "what decisions and actions does the system take, in which use case?" That use case decides your obligations.
- Dates moved in 2026. Learners who memorized the original 2026 and 2027 deadlines need the updated ones.

## 2. Understand it

### 2.1 How the EU AI Act sees an agent

The Act regulates by **risk of the use case**, not by technology. There is no separate "agent" category (verify for new guidance). An agent can be:

| Role in the Act | Example | Main obligations (summary) |
|---|---|---|
| **Prohibited practice** | Manipulative or social-scoring uses | Banned |
| **High-risk AI system** | Agent making or supporting decisions on hiring, credit, education, essential services, safety components of regulated products | Risk management, data governance, technical documentation, **logging (Art. 12)**, transparency, **human oversight (Art. 14)**, **accuracy, robustness and cybersecurity (Art. 15)**, conformity assessment, registration, post-market monitoring, serious-incident reporting |
| **Limited-risk / transparency** | Chatbots, deepfake generation | Tell people they interact with AI; label synthetic content |
| **General-purpose AI (GPAI) model** | The foundation model under your agent | Provider obligations since **2 Aug 2025**; stricter for systemic-risk models. If you only *use* a GPAI model you are usually a deployer/downstream provider of the *system* |
| **Minimal risk** | Internal productivity helper | Voluntary codes; AI literacy duties may still apply |

Agent-specific implications: **logging** every autonomous decision (trace design in [02](02-observability-and-anomaly-detection.md)), **human oversight** that is real (HITL/HOTL design in [ch5 05](../ch5-multi-agent-systems-and-agent-identity/05-oversight-containment-and-failsafes.md)), **cybersecurity** against prompt injection and supply-chain attacks (the gate, AIBOM, signing), and **documentation** (AIBOM and the harness inventory).

### 2.2 Digital Omnibus timing (as reported; verify at source)

| Item | Date |
|---|---|
| AI Act entered into force | 1 Aug 2024 |
| Prohibitions and AI literacy | 2 Feb 2025 |
| GPAI obligations | 2 Aug 2025 |
| Digital Omnibus on AI: Regulation (EU) 2026/1744, in force | 27 Jul 2026 |
| **Stand-alone high-risk systems (Annex III) now apply from** | **2 Dec 2027** |
| **High-risk systems embedded in regulated products now apply from** | **2 Aug 2028** |

The Omnibus delayed the high-risk rules from the original 2026 and 2027 dates. Other transparency dates and details were also adjusted: read the consolidated text. Penalties can reach a share of global turnover (tiers by violation): see [08-ai-compliance](../../08-ai-compliance/01-eu-ai-act.md).

### 2.3 Comparable frameworks for autonomous systems

| Framework | Nature | Agent-relevant points |
|---|---|---|
| **NIST AI RMF 1.0, AI 600-1** (US) | Voluntary risk framework | GOVERN/MAP/MEASURE/MANAGE; generative AI profile. [06](06-nist-ai-rmf-asi-controls-and-zero-trust.md) |
| **ISO/IEC 42001** | Certifiable AI management system standard | Management processes, roles, supplier control. [07-ai-governance lesson 04](../../07-ai-governance/04-iso-42001-ai-management-system.md) |
| **UK approach** | Principles-based, regulator-led (no single AI statute as of this writing: verify). The UK AI Security Institute researches agent risks; the UK government published an **AI cyber security code of practice** (early 2025) | Use the code's secure design, supply chain and monitoring principles |
| **Singapore** | IMDA Model AI Governance Framework (2020 for traditional AI; a version for generative AI in 2024). A **Model AI Governance Framework for Agentic AI** has been reported from IMDA in early 2026 (verify at imda.gov.sg before citing) | Voluntary guidance: bounding risks upfront, meaningful human accountability, technical controls, end-user responsibility (as reported: verify) |
| **US states** | Colorado (replaced by a narrower law effective 1 Jan 2027), California SB 53, Texas TRAIGA (effective 1 Jan 2026) | Sector and use-case duties; verify current status ([CAISP ch7](../../caisp-course/ch7-emerging-threats-governance-compliance/README.md)) |
| **India** | DPDP Act for personal data; CERT-In guidance | [08-ai-compliance lesson 02](../../08-ai-compliance/02-privacy-gdpr-and-india-dpdp.md) |
| **CISA / Five Eyes** | Joint practical guidance, not law | [09](09-cisa-five-eyes-agentic-ai-guidance.md) |

## 3. Defend it (compliance engineering)

| Need | What you build |
|---|---|
| Classification | A documented use-case risk assessment per agent |
| Logging | Trace schema, retention, tamper evidence |
| Oversight | Approval gates with evidence of reviews |
| Cybersecurity | Red-team gate results, AIBOM, signed releases |
| Documentation | Harness inventory, AIBOM, model cards, change history |
| Incident handling | Rogue-agent runbook and reporting path |

**What does NOT work on its own:** treating "we use a GPAI model" as compliance; a policy PDF without logs; assuming a US company is out of scope when outputs are used in the EU.

## 4. Hands-on

Pick a sample agent (a hiring-screening assistant, a customer-support bot, a building-control agent) and fill: use case, risk class, role (provider or deployer), top five obligations, evidence you already have from this course, and gaps.

## 5. Scenarios

1. *HR screening agent.* Likely high-risk (employment). You need logging, human oversight and documentation before the applicable date.
2. *Support chatbot.* Transparency duty: disclose that it is AI.
3. *Industrial control agent.* Safety component: possibly embedded in a regulated product (later date) and sector safety rules; see the fail-safe design in [ch5 05](../ch5-multi-agent-systems-and-agent-identity/05-oversight-containment-and-failsafes.md).

## 6. Interview questions

<details><summary><b>Q1. When do the EU AI Act's high-risk rules apply after the Digital Omnibus?</b></summary>
As reported: stand-alone high-risk systems from 2 December 2027 and systems embedded in regulated products from 2 August 2028, after the Omnibus (Regulation (EU) 2026/1744, in force 27 July 2026) postponed the earlier dates. GPAI obligations have applied since 2 August 2025. Verify at source.
</details>

<details><summary><b>Q2. Is there an "agent" risk class in the EU AI Act?</b></summary>
No separate class: risk follows the use case. An agent is high-risk if its use case is in Annex III or it is a safety component of a regulated product.
</details>

<details><summary><b>Q3. Which Act obligations map most directly to agent engineering?</b></summary>
Logging (Art. 12), human oversight (Art. 14), accuracy, robustness and cybersecurity (Art. 15), technical documentation, and post-market monitoring and incident reporting.
</details>

## 7. Checklist

- [ ] Each agent has a recorded use case and risk class.
- [ ] I know the updated dates and where to verify them.
- [ ] I can name two non-EU frameworks and what they add.

## 8. References

- EU AI Act (Regulation (EU) 2024/1689) and Regulation (EU) 2026/1744: EUR-Lex.
- [08-ai-compliance](../../08-ai-compliance/README.md), [07-ai-governance](../../07-ai-governance/README.md).
- Singapore IMDA and UK AISI/DSIT publications: verify current titles at the source sites.
- Next: [08 Confidential computing and attestation](08-confidential-computing-and-attestation.md).
