# ISO Standards for AI Security, and Law vs Standard vs Framework

> **Module:** 08 · AI Compliance · **Weeks:** 31–32 · **Time:** ~6 hours
> **You will:** tell laws, certifiable standards, guidance and frameworks apart without hesitation; use ISO/IEC 23894 for the AI risk process; interpret ISO/IEC 27001:2022 Annex A controls for AI systems; and place ISO/IEC 42001, 27701, 42005 and 27090 correctly.

| | |
|---|---|
| **Prerequisites** | [Module 07 Lesson 03](../07-ai-governance/03-ai-risk-management.md) (risk), [Lesson 04](../07-ai-governance/04-iso-42001-ai-management-system.md) (ISO/IEC 42001), [Lesson 03](03-control-mapping-and-evidence.md) (mapping) |
| **Lab** | [`lab/fixtures/controls.yaml`](lab/fixtures/controls.yaml) (`iso_27001` and `iso_42001` columns), `evidence_checker.py` coverage, `compliance_matrix.py` |
| **Maps to** | ISO/IEC 42001:2023 · ISO/IEC 23894:2023 · ISO/IEC 27001:2022 and 27002:2022 · ISO/IEC 27701 · ISO/IEC 42005 · ISO/IEC 27090 · NIST AI RMF GOVERN 1.1 |

> **Educational.** ISO standards are copyrighted and sold by ISO and national bodies. This lesson describes them at the level of public summaries and clause titles. Use your licensed copy for real work and verify editions (for example, check whether a newer edition or amendment exists).

---

## 1. Why this matters

- **ISO/IEC 27001:2022** reorganized Annex A into 93 controls in four themes; certified organizations had to move to the 2022 version by October 2025. Most companies selling AI services already hold 27001, so AI controls are usually added *into* that system rather than built from zero.
- **ISO/IEC 42001:2023** was the first certifiable AI management-system standard. Certification bodies began issuing certificates soon after publication, and customers now ask for it in AI vendor questionnaires (see the Module 07 [third-party questionnaire](../07-ai-governance/policies/05-ai-third-party-risk-assessment.md), Q6).
- **ISO/IEC 27090** (cybersecurity guidance for AI systems) is reported as published in 2026 in the ISC2 AI Security study guide in your library. **Verify its status and edition on iso.org before citing it.**
- Interviewers often ask, "Is NIST AI RMF mandatory?" or "Does ISO/IEC 42001 certification make us EU AI Act compliant?" The correct answers are "no" and "no", and you need to explain why.

---

## 2. Understand it

### 2.1 Law vs standard vs framework: the table to remember

| Instrument | Kind | Legally binding? | Certifiable? | Who checks | What it gives you |
|---|---|---|---|---|---|
| **EU AI Act** (Reg. (EU) 2024/1689, amended by Reg. (EU) 2026/1744) | **Law** (EU regulation) | **Yes**, in its scope (EU market or EU use of output) | Conformity assessment for high-risk systems (CE marking); not a general certificate | Market surveillance authorities, AI Office | Duties by role and risk category; fines |
| **GDPR** (Reg. (EU) 2016/679) | **Law** | **Yes**, for personal data in its scope | Optional certification schemes exist | Data protection authorities | Lawful basis, rights, DPIA, breach notice; fines |
| **India DPDP Act 2023 + DPDP Rules 2025** | **Law** | **Yes** (Rules phased to about May 2027) | No | Data Protection Board of India | Consent/legitimate use, notice, safeguards, breach intimation; penalties |
| **CERT-In Directions (2022)** | **Legal directions** under the IT Act (India) | **Yes**, for covered entities | No | CERT-In | 6-hour incident reporting, log retention |
| **CERT-In AI Security Auditing Guidelines** (2026) | Government **audit guideline** | Applied through audits, contracts and sector rules; check what binds you | No (but sets audit depth and empanelled auditors) | Auditors | Risk tiers, nine audit domains, finding severity |
| **ISO/IEC 42001** | **Management-system standard** (requirements, "shall") | No, unless a contract or regulator requires it | **Yes** (accredited certification body) | Certification body | A running AI management system with an audit trail |
| **ISO/IEC 27001** | Management-system standard | No, unless required by contract | **Yes** | Certification body | ISMS + Annex A controls |
| **ISO/IEC 23894** | **Guidance** standard ("should") | No | **No** | – | AI risk-management process on ISO 31000 |
| **ISO/IEC 27090** | Guidance standard (verify status) | No | No | – | AI-specific security threats and controls |
| **NIST AI RMF 1.0 + AI 600-1 + Playbook** | **Voluntary framework** | **No** | **No** | Yourself, customers | Outcomes and vocabulary (Govern, Map, Measure, Manage) |
| **OWASP LLM / Agentic / MCP Top 10** | Community **awareness lists** | **No** | **No** | Yourself, testers | Threat catalogs for risk identification and testing |
| **MITRE ATLAS** | Threat **knowledge base** | No | No | Red teams | Adversary tactics and techniques |
| **SOC 2** | **Attestation** report (AICPA) | No, unless contract | Not a certificate: a CPA opinion | CPA firm | Report on controls over a period (Type II) |

Three sentences to say in any interview: **NIST AI RMF and OWASP are not laws. ISO/IEC 42001 is a certifiable management-system standard. GDPR, the DPDP Act and the EU AI Act are law.** A certificate shows a management system works for a defined scope; it does not prove legal compliance, and it does not prove the AI system is secure today.

### 2.2 ISO/IEC 23894: the AI risk process

ISO/IEC 23894:2023 gives **guidance** for AI risk management, built on **ISO 31000**. It keeps ISO 31000's three parts (principles, framework, process) and adds what is special about AI.

| ISO 31000 process step | What 23894 adds for AI (summary) | Where you do it in this repo |
|---|---|---|
| Scope, context, criteria | AI-specific context: intended use, stakeholders incl. affected people, the AI life cycle stage, legal context | System card (Module 07 Lesson 01); applicability engine (Lesson 01) |
| Risk identification | AI risk sources: data quality and provenance, lack of transparency, changes in environment (drift), level of automation, complexity, hardware and supply-chain issues, misuse | Risk catalogs: OWASP 2026 lists, ATLAS, NIST AI 600-1 |
| Risk analysis | Consider impacts on individuals and society, not only on the organization; uncertainty of ML behaviour | 5×5 scoring with impact on people |
| Risk evaluation | Compare with criteria and appetite, including legal requirements | Appetite rule (residual > 9) |
| Risk treatment | Controls across the AI life cycle; human oversight; documentation | Treatments with owners; Model Approval Policy |
| Monitoring and review | Continuous, because models and data change | Re-assessment triggers; evidence freshness |
| Recording and reporting | Traceable records, communication to stakeholders | Risk register export; board report |

**How it fits with ISO/IEC 42001:** 42001 clause 6.1 requires you to assess and treat AI risks and to run AI system impact assessments; it does not prescribe *how*. ISO/IEC 23894 is a common "how". ISO/IEC 42005 gives guidance specifically on **AI system impact assessment** (effects on individuals and society).

### 2.3 ISO/IEC 27001:2022 and AI: interpreting Annex A controls

You rarely need new control *categories* for AI; you need AI-aware *interpretations* of existing ones, plus AI-specific controls that 27001 does not have (human oversight, model evaluation, AI impact assessment, which come from 42001 and the AI Act).

| ISO/IEC 27001:2022 Annex A control | AI interpretation | Repo control / module |
|---|---|---|
| A.5.9 Inventory of information and other associated assets | Inventory includes models, prompts and system prompts, vector stores, agent identities, MCP servers, datasets | CTL-INV; Module 07 register |
| A.5.12 / A.5.13 Classification and labelling | Labels propagate to embeddings, chunks, logs and fine-tune sets | Module 07 DS-04; Data Governance Policy DGP-04 |
| A.5.15 Access control; A.8.2 Privileged access; A.8.3 Information access restriction | Least privilege for agents and tools; retrieval enforces the user's permissions | CTL-ACCESS; Modules 03, 05 |
| A.5.19 – A.5.22 Supplier relationships and monitoring | Model providers, AI SaaS, MCP servers; training-use and change-notice clauses | CTL-VEND; Third-Party Risk Assessment |
| A.5.23 Information security for use of cloud services | Managed AI services (for example Bedrock, Azure AI, Vertex AI) and their shared responsibility | Module 09 |
| A.5.24 – A.5.28 Incident management and evidence | AI incident categories, kill switch, evidence (prompts, tool calls, model hash) | CTL-IR; Module 07 Lesson 06 |
| A.5.34 Privacy and protection of PII | DPIA for AI; erasure across RAG stores | CTL-PRIV; Lesson 02 |
| A.8.9 Configuration management | System prompts, guardrail rules, tool allowlists and model versions under change control | Model Approval Policy |
| A.8.10 Information deletion | Erasure reaches indexes, caches, logs, backups | `privacy_rights.py` |
| A.8.11 Data masking; A.8.12 Data leakage prevention | PII redaction before prompts; output DLP at the AI gateway | AI Security Standard SEC-01, SEC-07 |
| A.8.15 Logging; A.8.16 Monitoring activities | Prompt, tool-call and decision logs with redaction; abuse detection | CTL-LOG; Module 06 |
| A.8.25 – A.8.29 Secure development, coding and security testing | Prompt-injection and leakage regression suites in CI; red-team before release; review of AI-generated code (OWASP LLM10:2026 Improper Output Handling) | CTL-EVAL; Modules 02, 06 |
| A.8.24 Use of cryptography | Encrypt vector stores, model artifacts, memory | SEC-14 |

**What 27001 does not ask for** (and why the lab's `controls.yaml` has empty `iso_27001` cells for some controls): human oversight of AI decisions, AI system documentation such as model cards, fairness evaluation, AI impact assessment. That is the gap ISO/IEC 42001 Annex A fills (A.5 impact assessment, A.6 life cycle, A.8 information for interested parties, A.9 use of AI systems).

### 2.4 One management system, several standards

Organizations certified to 27001 usually build an **integrated management system**: the same clause structure (context, leadership, planning, support, operation, performance evaluation, improvement) serves 27001, 27701 (privacy information management) and 42001. Shared parts: document control, internal audit, management review, corrective action, competence. Separate parts: the risk criteria, the Statement of Applicability for each Annex A, and the impact assessments.

| Standard | Scope question | Typical owner |
|---|---|---|
| ISO/IEC 27001 | Is information secure? | CISO |
| ISO/IEC 27701 | Is personal data handled properly (privacy extension)? | DPO |
| ISO/IEC 42001 | Is AI developed, provided and used responsibly? | Head of AI governance |
| ISO/IEC 23894 / 42005 | How do we assess AI risks / AI system impacts? | Risk and governance teams |
| ISO/IEC 27090 | Which AI-specific security threats and controls apply? (verify status) | Security architecture |
| ISO/IEC 22989 | What do the AI terms mean? | Everyone |

---

## 3. Defend it

| Layer | Control | Type | What it buys you |
|---|---|---|---|
| L1 | Instrument register: every law, standard and framework with kind, binding status, edition, date checked, owner | Process | No confusion between "must" and "should" |
| L2 | One control set mapped to all of them (`controls.yaml`), empty cells visible | **Hard** (data) | Gaps per framework are computed, not guessed |
| L3 | 27001 Annex A interpretation sheet for AI assets | Process | Existing ISMS covers models, prompts, vector stores |
| L4 | Integrated internal audit and management review across 27001 / 27701 / 42001 | Process | One cycle, fewer audits |
| L5 | Evidence freshness and integrity checks feed all of them | **Hard** | The same proof serves every framework |

### What does NOT work on its own

- "We are ISO/IEC 27001 certified, so our AI is covered." The certificate's scope may not include the AI service, and 27001 does not ask for AI oversight or evaluations.
- "We follow NIST AI RMF, so we comply with the EU AI Act." A voluntary framework does not replace legal duties.
- Citing a standard you have not read in its current edition.
- Treating OWASP Top 10 numbers as stable: the 2026 LLM list renumbered most entries.

---

## 4. Hands-on lab

### Step 1: Find what 27001 misses

```powershell
python 08-ai-compliance/lab/demo.py
```

In section 2, compare the `iso_27001` and `iso_42001` coverage lines. Then open `lab/fixtures/controls.yaml` and list every control whose `iso_27001` list is empty. Run the test that proves the point:

```powershell
python -m pytest 08-ai-compliance/lab/test_evidence_checker.py -v -k soc2_and_iso27001
```

### Step 2: Build an instrument register (week-31 deliverable)

Make a table for your capstone with one row per instrument from section 2.1: kind, binding for us (yes/no/by contract), certifiable, edition, date checked, owner, and the controls in your `controls.yaml` that map to it.

### Step 3: Write an AI interpretation sheet for 27001

Take ten Annex A controls from section 2.3. For each, write one sentence on what it means for your capstone's AI assets and which evidence file proves it. Add any missing `iso_27001` references to your copy of `controls.yaml` and re-run the checker.

### Step 4: Break it yourself (predict, then run)

1. Add `"A.8.16 monitoring activities"` to `CTL-HO`'s `iso_27001` list. What happens to the coverage numbers? Is the mapping honest? (Monitoring is not human oversight of decisions.)
2. Remove `iso_42001` mappings from `CTL-DOC`. Which Annex A area becomes a gap?

### Stretch goals

- Add an `iso_23894` column that maps controls to risk-process steps (identify, analyse, evaluate, treat, monitor, record).
- Draft a combined internal-audit plan for 27001 and 42001 with shared and separate evidence.

---

## 5. Real-world scenarios

**Scenario A: the certificate that did not cover the product (hypothetical).** A customer accepts a vendor's ISO/IEC 27001 certificate; later the AI assistant leaks data. The certificate's scope covered the corporate IT, not the AI service.
- *Fix:* read the scope statement and Statement of Applicability; ask for the AI service in scope (or 42001); test the service yourself.

**Scenario B: "we follow NIST, so we're compliant" (hypothetical).** A board slide says the company complies with the EU AI Act because it follows NIST AI RMF.
- *Fix:* the instrument register; map NIST outcomes to AI Act duties by role and category; run the applicability engine.

**Scenario C: one audit, three standards (hypothetical).** The company holds 27001, wants 42001 and must show DPDP readiness. Three teams collect the same evidence three times.
- *Fix:* integrated management system; one control set; one evidence store; framework coverage computed by the checker.

---

## 6. Common mistakes

- Calling ISO/IEC 23894 or 27090 "certifiable". They are guidance.
- Calling SOC 2 a certificate.
- Mapping controls to clause numbers from memory without the licensed text.
- Forgetting that India's DPDP Rules phase in until around May 2027 and that the EU AI Act high-risk dates moved after the Omnibus.

---

## 7. Interview preparation

<details><summary><b>Q1. Is the NIST AI RMF mandatory?</b></summary>

No. It is a voluntary framework from a US standards agency. Some contracts or government programs may require its use, but it is not a law. It is useful as a shared structure (Govern, Map, Measure, Manage) and, with AI 600-1, as a GenAI risk catalog.
</details>

<details><summary><b>Q2. Does ISO/IEC 42001 certification make us EU AI Act compliant?</b></summary>

No. 42001 shows that an AI management system exists and works for a defined scope. The AI Act has specific legal duties by role and risk category (for example conformity assessment, technical documentation, logging, registration for high-risk systems). A 42001 system helps you produce and maintain that evidence, but it is not legal compliance.
</details>

<details><summary><b>Q3. What is the difference between ISO/IEC 42001 and ISO/IEC 23894?</b></summary>

42001 is a certifiable management-system standard with requirements ("shall"). 23894 is guidance ("should") on how to run AI risk management, based on ISO 31000. You can use 23894 to meet 42001's risk clauses.
</details>

<details><summary><b>Q4. Which ISO/IEC 27001 controls need an AI interpretation?</b></summary>

Asset inventory (models, prompts, vector stores, agents), classification and labelling (propagate to embeddings), access control (agents and retrieval), supplier relationships (model providers), configuration management (prompts, guardrails, model versions), deletion (RAG erasure), DLP and masking, logging and monitoring, secure development and testing (prompt-injection suites), and incident management.
</details>

<details><summary><b>Q5. What does ISO/IEC 27001 not cover for AI?</b></summary>

Human oversight of AI decisions, fairness and bias evaluation, AI system documentation such as model cards, AI impact assessments on individuals and society, and transparency to affected people. ISO/IEC 42001 Annex A and laws like the AI Act cover those.
</details>

<details><summary><b>Q6. Where do OWASP lists fit in compliance?</b></summary>

They are threat and vulnerability catalogs, not requirements. They feed risk identification (ISO/IEC 23894, NIST MAP), test design (security evaluations as evidence) and the AI Security Standard. They change often (the 2026 LLM list renumbered entries), so record the edition you used.
</details>

<details><summary><b>Q7. What is ISO/IEC 27090?</b></summary>

An ISO/IEC standard giving guidance on addressing security threats specific to AI systems. The ISC2 study guide in the library lists it as published in 2026; verify the edition and status on iso.org before relying on it. It is guidance, not a certifiable requirement.
</details>

<details><summary><b>Q8. How would you combine 27001, 27701 and 42001 in one company?</b></summary>

An integrated management system: one set of shared processes (document control, internal audit, management review, corrective action, competence), separate risk criteria and Statements of Applicability, and one control set mapped to all three, with evidence produced once.
</details>

<details><summary><b>Q9. A customer asks: "Are you compliant with NIST AI RMF?" How do you answer?</b></summary>

Explain that NIST AI RMF is voluntary and not certifiable, so "compliant" is the wrong word. Say you have *aligned* your AI risk program to it, show the mapping of your controls to its functions and subcategories, and offer the evidence (for example the coverage report).
</details>

<details><summary><b>Q10. Explain to a board in one minute why we need both ISO certifications and legal compliance work.</b></summary>

"Laws tell us what we must do and can fine us. ISO certificates show customers that our management system runs and is audited. They overlap but are not the same: a certificate can be valid while a legal duty is missed, and we can be legally fine while customers still demand a certificate. One control set and one evidence store let us satisfy both without doing the work twice."
</details>

---

## 8. Checklist (definition of done)

- [ ] I can recite the law / standard / framework table from memory for the six main instruments.
- [ ] I wrote an instrument register for my capstone with dates checked.
- [ ] I wrote an AI interpretation for ten ISO/IEC 27001 Annex A controls.
- [ ] `python -m pytest 08-ai-compliance` passes.

## 9. References

- ISO/IEC 42001 (AI management system): https://www.iso.org/standard/42001
- ISO/IEC 23894 (AI risk management guidance): https://www.iso.org/standard/77304.html
- ISO/IEC 27001 (information security management systems): https://www.iso.org/standard/27001
- ISO 31000 (risk management): https://www.iso.org/iso-31000-risk-management.html
- ISO/IEC 42005 (AI system impact assessment) and ISO/IEC 27090 (AI security): search https://www.iso.org/ and verify status
- NIST AI RMF: https://www.nist.gov/itl/ai-risk-management-framework
- AICPA SOC 2: https://www.aicpa-cima.com/
