# The EU AI Act: Chapter Summary

> **Chapter:** 7 · **Time:** ~2 hours (summary) · **Full lesson and lab:** [08 lesson 01: The EU AI Act](../../08-ai-compliance/01-eu-ai-act.md)
> **You will:** explain the Act's risk categories, roles and timeline (including the 2026 Digital Omnibus changes) in a few minutes, and know where to go for depth.

> **Educational, not legal advice.** Dates and guidance change. Verify at the source (EUR-Lex, the European Commission AI Office pages) and record the date you checked.

This page is a short summary for the course syllabus line "EU AI Act". It does **not** repeat the full lesson. Read [08 lesson 01](../../08-ai-compliance/01-eu-ai-act.md) for the decision order, roles table and the classifier lab.

---

## 1. What it is

Regulation (EU) 2024/1689 is the first broad, binding AI law. It is a **law** (not guidance). It applies to organizations outside the EU when their AI is placed on the EU market or its output is used in the EU. It is risk-based: the higher the risk, the heavier the duties.

## 2. Risk categories in one table

| Category | Meaning | Examples | Result |
|---|---|---|---|
| **Prohibited (Art 5)** | Unacceptable practices | Social scoring, manipulative techniques causing significant harm, untargeted scraping of faces for databases, workplace emotion recognition (narrow exceptions) | Not allowed |
| **High-risk (Art 6, Annex I and III)** | Safety components of regulated products, and listed areas such as employment, education, credit, essential services, law enforcement | CV screening, credit scoring | Strict duties: risk management, data governance, documentation, logging, human oversight, accuracy, robustness, cybersecurity, conformity assessment |
| **Transparency (Art 50)** | People must know when they deal with AI or see synthetic content | Chatbots, deepfakes, generated media | Disclosure and marking |
| **GPAI models (Chapter V)** | General-purpose model providers; extra duties for systemic-risk models | Large foundation models | Documentation, copyright policy, training-content summary; for systemic risk: evaluations, incident reporting, cybersecurity |
| **Minimal risk** | Everything else | Spam filters | No new duties beyond AI literacy; voluntary codes |

**Roles matter:** provider, deployer, importer, distributor. The same system gives different duties to each ([08 lesson 01, section 2.3](../../08-ai-compliance/01-eu-ai-act.md)).

## 3. Timeline, with the Digital Omnibus

| Date | What | Status note |
|---|---|---|
| 1 Aug 2024 | The Act entered into force | |
| 2 Feb 2025 | Prohibitions and AI literacy apply | |
| 2 Aug 2025 | GPAI model obligations apply | |
| 27 Jul 2026 | **Digital Omnibus on AI, Regulation (EU) 2026/1744, entered into force** (published in the Official Journal 24 Jul 2026) | Changed some dates |
| **2 Dec 2027** | Stand-alone high-risk systems (Annex III) apply | Moved by the Omnibus |
| **2 Aug 2028** | High-risk AI embedded in regulated products (Annex I) applies | Moved by the Omnibus |

Prohibitions and GPAI obligations were not changed by the Omnibus. Other dates (for example transparency obligations and penalties) have their own rules: **check the current consolidated text and [08 lesson 01](../../08-ai-compliance/01-eu-ai-act.md)** instead of relying on a memorized table.

## 4. Penalties (maximums; verify at source)

Up to EUR 35 million or 7% of worldwide annual turnover for prohibited practices, and up to EUR 15 million or 3% for many other obligations. Lower caps apply to small companies.

## 5. What it means for a security architect

- Article 15 requires high-risk systems to reach an appropriate level of **accuracy, robustness and cybersecurity**, including resilience to attacks such as data poisoning and adversarial inputs. That is your threat model work ([Chapter 5](../ch5-threat-modeling-ai-systems/README.md)).
- **Logging and record-keeping** for high-risk systems drives your logging design ([05 monitoring and response](../../05-agent-security/monitoring-and-response/README.md)).
- **Serious incident reporting** needs an incident process ([07 lesson 06](../../07-ai-governance/06-model-approval-lifecycle-and-ai-incidents.md), [08 lesson 04](../../08-ai-compliance/04-audit-readiness-and-ai-incidents.md)).
- **Supply chain:** providers must manage third-party components, which links to [Chapter 6](../ch6-supply-chain-attacks-in-ai/README.md).
- An AI inventory is step one ([07 lesson 01](../../07-ai-governance/01-ai-inventory-and-system-register.md)).
- ISO/IEC 42001 can help you build the processes, but certification is **not** the same as conformity with the Act ([08 lesson 05](../../08-ai-compliance/05-iso-standards-and-law-vs-standard.md)).

## 6. Other jurisdictions (pointers)

| Jurisdiction | Pointer (verify at source) |
|---|---|
| **UK** | Has taken a principles-based, regulator-led approach rather than one broad AI Act; the NCSC publishes secure AI guidance ([lesson 02](02-governance-standards-and-frameworks.md)) |
| **China** | Has several targeted rules for algorithms, deep synthesis and generative AI services |
| **India** | No single AI Act; DPDP Act (data protection) and CERT-In AI security audit guidelines apply: [08 lesson 02](../../08-ai-compliance/02-privacy-gdpr-and-india-dpdp.md), [08 lesson 06](../../08-ai-compliance/06-cert-in-ai-security-audit.md) |
| **US** | No single federal AI Act; see [lesson 04](04-us-ai-legislation.md) |

## 7. Interview preparation

<details><summary><b>Q1. Is the EU AI Act a standard or a law?</b></summary>

A law (Regulation (EU) 2024/1689) with penalties. ISO/IEC 42001 is a voluntary standard.
</details>

<details><summary><b>Q2. Name the risk categories.</b></summary>

Prohibited, high-risk, transparency-obligation systems, GPAI models (with a systemic-risk tier), and minimal risk.
</details>

<details><summary><b>Q3. What did the Digital Omnibus change?</b></summary>

Regulation (EU) 2026/1744 (in force 27 July 2026) moved stand-alone high-risk (Annex III) obligations to 2 December 2027 and embedded high-risk (Annex I) to 2 August 2028. Prohibitions and GPAI duties stay. Verify at source.
</details>

<details><summary><b>Q4. Does it apply to a US company?</b></summary>

Yes, if its AI is placed on the EU market or its output is used in the EU.
</details>

<details><summary><b>Q5. Which article ties most directly to AI security?</b></summary>

Article 15: accuracy, robustness and cybersecurity for high-risk systems, including resilience to poisoning and adversarial attacks.
</details>

## 8. References

- Regulation (EU) 2024/1689 and Regulation (EU) 2026/1744 on EUR-Lex; European Commission AI Office pages.
- [08 lesson 01](../../08-ai-compliance/01-eu-ai-act.md) in this repo.
