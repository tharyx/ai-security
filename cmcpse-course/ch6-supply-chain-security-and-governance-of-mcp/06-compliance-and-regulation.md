# 06. Compliance and Regulation for MCP Deployments

> **Syllabus:** Compliance and Regulation: EU AI Act implications for MCP server operators, US AI legislation and executive orders, building an organizational compliance posture for MCP, compliance checklists for MCP deployment.
> **Time:** 2 hours. **Companion file:** [mcp-compliance-checklist.md](mcp-compliance-checklist.md). **Read first:** [CAISP ch7 lesson 03: EU AI Act summary](../../caisp-course/ch7-emerging-threats-governance-compliance/03-eu-ai-act-summary.md), [lesson 04: US AI legislation](../../caisp-course/ch7-emerging-threats-governance-compliance/04-us-ai-legislation.md), and the repo's [08 AI compliance](../../08-ai-compliance/README.md) module ([EU AI Act lesson](../../08-ai-compliance/01-eu-ai-act.md)).

> **This is not legal advice.** Laws change, and applicability depends on facts (what the system is, who you are, where users and data are). Everything below is an engineer's orientation. **Verify at the source and ask counsel** before relying on any date, article number or conclusion. Dates here follow the repo's reference notes as of Nov 2026.

## 1. EU AI Act implications for MCP server operators

### 1.1 The key question: is an MCP server an "AI system"?

The Act defines an **AI system** broadly, in terms of a machine-based system that infers from input how to generate outputs such as predictions, content, recommendations or decisions (Article 3; verify the exact wording and the Commission's guidelines on the definition). An MCP server is a **protocol endpoint that exposes tools, resources and prompts**. Then:

- A *typical* MCP server (reads files, queries a database, calls an API, runs a deterministic function) is **ordinary software**. By itself it usually does **not** infer outputs in the AI-system sense. It is a **component** that an AI system uses.
- A server that **wraps a model** (for example a "summarize" tool that calls an LLM, a classifier, a recommender) contains or is part of an AI system.
- The **AI system** in most deployments is the *whole agent*: model plus host plus servers plus orchestration. Obligations attach to that system and to the roles around it.

So the honest answer is "**usually a component, sometimes part of or itself an AI system; decide per deployment and document the reasoning**".

### 1.2 Roles

| Role | Short definition | MCP example |
|---|---|---|
| **Provider** | Develops an AI system (or has it developed) and places it on the market or puts it into service under its own name | A company that ships an AI assistant product that includes MCP servers and a model |
| **Deployer** | Uses an AI system under its authority (professional use) | An enterprise that runs an agent with MCP servers for HR or customer support |
| **Importer / distributor** | Brings into the EU / makes available a system from elsewhere | A reseller of an agent platform |
| **Component or tool supplier** | Supplies software, tools or services used in an AI system | An MCP server vendor or open-source maintainer whose server is used by someone else's high-risk system |
| **GPAI model provider** | Provides a general-purpose AI model | The model vendor behind the agent (has its own obligations) |

A person can hold several roles at once; **a deployer that substantially modifies a system or changes its purpose can become a provider** (verify Article 25).

### 1.3 When do obligations reach an MCP server operator?

Think in layers and ask these questions in order:

1. **Prohibited practices (applied from 2 Feb 2025).** Does the overall system do anything prohibited (for example certain manipulative techniques, social scoring, some biometric uses)? An MCP tool that enables such a use is part of the problem. Stop here if yes.
2. **AI literacy (applied from 2 Feb 2025).** Providers and deployers must take measures so staff operating AI systems have sufficient AI literacy. Training the people who configure MCP servers and agents is part of this.
3. **Is the overall system high-risk?** High-risk includes systems used in listed areas such as employment, education, essential services, creditworthiness, law enforcement and others (Annex III), and AI that is a safety component of regulated products (Annex I). If your agent and its MCP tools make or support such decisions, the **provider** of that system must meet the high-risk requirements: risk management, data governance, technical documentation, **logging and record-keeping**, transparency to deployers, **human oversight**, **accuracy, robustness and cybersecurity** (Article 15), a quality management system and conformity assessment. The Digital Omnibus (Regulation (EU) 2026/1744, in force 27 Jul 2026) moved stand-alone high-risk obligations to **2 Dec 2027** and embedded ones to **2 Aug 2028** (verify in the consolidated text).
3. **Component supplier duties.** Where a third party supplies tools, services or components used in a high-risk system, the provider of the high-risk system is expected to agree in writing what information and cooperation they need from the supplier (Article 25; verify). Practically: an MCP server vendor or operator may be asked for **documentation, security evidence, SBOMs, logging features and incident cooperation**. Free and open-source components have special treatment in parts of the Act (verify).
4. **Transparency obligations (Article 50).** If the system interacts directly with people (chatbot), generates synthetic content, or does emotion recognition or biometric categorization, users must be informed or content marked. A tool that generates images, audio or text for publication through an agent can trigger the *marking* duty on the provider side. Timing of some transparency duties and penalties has its own rules: check the current text.
5. **GPAI models.** Obligations on general-purpose model providers apply from 2 Aug 2025 and sit with the model provider, not the MCP server operator, unless you provide the model.
6. **Other law that applies anyway:** GDPR (personal data flowing through tools, logs and prompts), the Cyber Resilience Act for products with digital elements (reporting and security obligations phase in during 2026 to 2027; verify; relevant to commercial server vendors), NIS2 for essential and important entities, sector rules, product liability.

**Penalties (maximums; verify):** up to EUR 35 million or 7% of worldwide turnover for prohibited practices; up to EUR 15 million or 3% for many other obligations; lower caps for SMEs.

**What an MCP server operator should do now (no matter the final classification):** keep an inventory and a short written classification memo; make **logging** (who called which tool, with what outcome) available; document tools, data and permissions; keep SBOMs and security evidence; define human-oversight points for sensitive tools; prepare to answer customer questionnaires from high-risk providers; train staff (AI literacy).

### 1.4 A worked example (illustrative, not a legal opinion)

*A company runs an HR assistant (LLM host) with MCP servers for the HR database, calendar and email.* The overall system supports employment decisions (screening candidates), which is an Annex III area: likely **high-risk**. The company that built the assistant is the **provider**; the HR department using it is a **deployer**. The HR database MCP server is a **component** with no inference of its own, so it is not an AI system alone, but its logging, access control, security and documentation are **inputs to the provider's obligations** (Article 15 cybersecurity, record-keeping, oversight). If the email server drafts text with a model, that part is a GPAI-model-powered feature, and transparency rules may apply. Contracts with the MCP server vendors should cover documentation, vulnerability handling and incident cooperation.

## 2. US AI legislation and executive orders

Covered in depth in [CAISP ch7 lesson 04](../../caisp-course/ch7-emerging-threats-governance-compliance/04-us-ai-legislation.md). A summary as of Nov 2026 (verify every item at the source):

- **No comprehensive federal AI statute.** Policy is made by executive action, agency guidance, sector law and states.
- **Executive orders:** EO 14110 (Oct 2023, Biden) was revoked in Jan 2025; EO 14179 set the new direction toward removing barriers to AI leadership; **America's AI Action Plan** followed on 23 Jul 2025; **EO 14365** (Dec 2025) created an **AI Litigation Task Force** to challenge state AI laws. An executive order cannot repeal state law, and no federal statute broadly preempts state AI laws.
- **State laws** are where much obligation sits: for example California SB 53 (frontier AI transparency) and Texas TRAIGA (HB 149), both effective 1 Jan 2026; Colorado's original AI Act (SB24-205) was repealed and replaced by SB 26-189 (signed 14 May 2026, a narrower automated-decision-making law, effective 1 Jan 2027); New York City Local Law 144 on automated employment decision tools.
- **Federal sector and general law:** the TAKE IT DOWN Act (2025) on non-consensual intimate imagery including AI deepfakes; FTC authority over unfair or deceptive practices; civil-rights, consumer-protection and sector (health, finance) rules.
- **Voluntary frameworks:** NIST AI RMF and NIST SSDF are widely used as the "reasonable security" yardstick and are referenced in procurement and in some state laws' safe harbors (verify specific laws).

**For MCP operators:** map where you have users and employees; identify whether any agent use is an "automated decision" in a regulated area (hiring, lending, housing, health); keep logs and notices; align to NIST AI RMF; watch litigation and preemption developments.

## 3. Building an organizational compliance posture for MCP

A posture is *the set of habits that let you answer an auditor in a day*, not a pile of documents.

| Building block | What good looks like |
|---|---|
| **Ownership** | An executive owner for AI risk; a named owner per MCP server; a security reviewer group; legal and privacy involved early |
| **Policy** | A short MCP/agent policy: who may connect which servers, tiers and approvals, banned patterns (token passthrough, unpinned launchers, shadow servers), incident duties |
| **Inventory** | A live inventory of agents, hosts, servers, tools, data classes, credentials, owners and versions, fed by discovery (not only by self-reporting) |
| **Risk and impact process** | Tiering ([lesson 02](02-vetting-third-party-mcp-servers.md)), impact assessments for tools that write or send, a risk register with dates |
| **Controls** | The technical controls from chapters 4 and 5 and lessons 01 to 04 here, mapped to frameworks ([lesson 05](05-ai-governance-frameworks.md)) |
| **Regulatory screening** | A one-page classification memo per deployment: EU role(s) and system class, US state laws touched, data protection laws, sector rules |
| **Evidence** | Automated: pipeline logs, signed SBOMs and attestations, test reports, audit logs. Manual: approvals, training records |
| **Supplier management** | Questionnaire and contract clauses for hosted/third-party MCP servers: security, incident notice, sub-processors, logging, SBOMs |
| **Monitoring and metrics** | Blocks, drift alerts, unapproved servers found, patch times, incident counts |
| **Incident response** | MCP scenarios in the runbook, notification clocks (privacy law, EU AI Act serious incidents for high-risk systems, CRA reporting where applicable; verify) |
| **Training** | Developers (secure MCP), users (what agents can do, how to spot injection), approvers (what to check) |
| **Review rhythm** | Quarterly risk review; re-assess on major change (new model, new tool class, new law) |

Maturity ladder: *ad hoc* (people install servers) → *inventoried* → *governed* (tiers, approvals, pinning) → *measured* (metrics, audits) → *continuously assured* (automated evidence, gateway enforcement).

## 4. Compliance checklists for MCP deployment

The full checklist is in [**mcp-compliance-checklist.md**](mcp-compliance-checklist.md). Use it at three moments: before a new server goes live, at each scheduled review, and when something major changes. Each item has an **evidence** column so the checklist doubles as audit preparation.

## 5. Hands-on

1. Write a one-page **classification memo** for an agent you know: components, EU role(s), is any MCP server itself an AI system, which Annex III area (if any), US states and data laws involved, open questions for counsel.
2. Fill the [checklist](mcp-compliance-checklist.md) for the `notes-mcp` fixture; mark each row done, partial or missing and give evidence.

## 6. Interview questions

- *Is an MCP server an AI system under the EU AI Act?* Usually it is a component of one; it can be part of or contain an AI system if it embeds a model. Classify per deployment and document why.
- *When can obligations reach an MCP server vendor?* When the vendor's server is a component of a customer's high-risk system (contract and cooperation duties), when it embeds a model or generates content that triggers transparency duties, or under other law (GDPR, CRA, NIS2).
- *What changed with the Digital Omnibus?* It moved the application dates of high-risk obligations (stand-alone to 2 Dec 2027, embedded to 2 Aug 2028); prohibitions and GPAI obligations were not changed. Verify the current text.
- *Is there a US federal AI law?* No comprehensive one. Executive orders, agency action, sector law and many state laws apply; an executive order cannot repeal state law.

## 7. References

- Regulation (EU) 2024/1689 (AI Act) and Regulation (EU) 2026/1744 (Digital Omnibus on AI): eur-lex.europa.eu. Commission guidelines on the AI system definition and on prohibited practices (verify).
- [CAISP ch7 03 EU AI Act](../../caisp-course/ch7-emerging-threats-governance-compliance/03-eu-ai-act-summary.md); [04 US legislation](../../caisp-course/ch7-emerging-threats-governance-compliance/04-us-ai-legislation.md); [08 compliance](../../08-ai-compliance/README.md).
