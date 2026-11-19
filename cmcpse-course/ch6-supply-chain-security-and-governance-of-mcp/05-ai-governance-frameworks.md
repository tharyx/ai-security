# 05. AI Governance Frameworks Applied to MCP

> **Syllabus:** AI Governance Frameworks: standards, guidelines and frameworks applicable to MCP; NIST AI Risk Management Framework (RMF); ISO/IEC 42001; other emerging standards and guidelines; applying governance frameworks to MCP deployments specifically.
> **Time:** 2.5 hours. **General background (read first, not repeated):** [CAISP ch7 lesson 02: governance, standards and frameworks](../../caisp-course/ch7-emerging-threats-governance-compliance/02-governance-standards-and-frameworks.md), and the repo's [07 AI governance](../../07-ai-governance/README.md) module (inventory, roles, risk management, [ISO 42001 AIMS](../../07-ai-governance/04-iso-42001-ai-management-system.md)).
> **Not legal advice.** Names, clause numbers and dates: verify at the source.

## 1. Why governance for MCP

Governance answers *who decided that this agent may use this server, on what evidence, and who will notice if it goes wrong?* MCP makes that urgent: tool access is added by configuration, often by individuals, and a single connection can give an agent write access to production systems. Frameworks give you shared language for auditors, customers and regulators, and a way to show that your technical controls (chapters 4 and 5, lessons 01 to 04 here) belong to a managed system.

## 2. Standards, guidelines and frameworks applicable to MCP

| Source | Type | What it gives you | Relevance to MCP |
|---|---|---|---|
| **NIST AI RMF 1.0** (AI 100-1, Jan 2023) and **Generative AI Profile** (AI 600-1, July 2024) | Voluntary framework | Four functions: Govern, Map, Measure, Manage; GenAI-specific risks and actions | Risk language for agents and tools (section 3) |
| **ISO/IEC 42001:2023** | Certifiable management system standard | AI management system (AIMS): policy, roles, risk, controls (Annex A), improvement | Certifiable governance wrapper (section 4) |
| **ISO/IEC 23894** | Guidance | AI risk management guidance (builds on ISO 31000) | Risk process |
| **ISO/IEC 27001 / 27002** | Certifiable ISMS | Information security controls | Most MCP controls already live here (access control, supplier relationships, logging, secure development) |
| **NIST SP 800-218 (SSDF)** and **SP 800-218A** (GenAI community profile) | Secure development framework | Secure software development practices, extended for generative AI | [Chapter 5](../ch5-devsecops-for-mcp-security/README.md) as an SSDF implementation |
| **NIST CSF 2.0** | Voluntary framework | Govern, Identify, Protect, Detect, Respond, Recover | Organization-level security program |
| **NIST SP 800-37 (the other "RMF")** | Risk management framework for systems | Authorization lifecycle for information systems | What "RMF" means in US government contexts; do not confuse with AI RMF |
| **OWASP MCP Top 10, LLM Top 10, Agentic Top 10 (2026), AI Testing Guide, AI Exchange** | Community guidance | Threat categories and test cases | Your control catalogue and test plan |
| **MITRE ATLAS** | Knowledge base | Adversary tactics and techniques for AI systems | Threat modeling and detection mapping |
| **CSA (Cloud Security Alliance) AI Controls Matrix, MAESTRO threat model** | Industry guidance | Control matrix and layered agentic threat model (verify current versions) | Mapping controls across cloud and agent layers |
| **Google SAIF, Microsoft and AWS AI security guidance** | Vendor frameworks | Practical controls for their platforms | Platform-specific hardening |
| **EU AI Act** and other laws | Regulation | Legal obligations | [Lesson 06](06-compliance-and-regulation.md) |

Treat standards as **layers**: laws set obligations, management-system standards (ISO 42001, 27001) give you a repeatable process, risk frameworks (NIST AI RMF) give you a risk method, and technical guides (OWASP, ATLAS) give you the controls and tests. Industry groups have also published MCP-specific security guidance (for example, reports describe work by CoSAI and the OWASP GenAI Security Project; verify what exists and its status). Use it as input, not as law.

## 3. NIST AI RMF applied to MCP

The AI RMF is voluntary and **non-prescriptive**. It describes four functions, each with categories and subcategories. The table maps each function to concrete MCP controls and evidence (a *mapping*, not an official profile).

| Function | What it asks | MCP controls | Evidence an assessor can see |
|---|---|---|---|
| **GOVERN** | Policies, accountability, culture, third-party risk | MCP usage policy; named owner per server; approval workflow for new servers and tool changes ([ch5 lesson 05](../ch5-devsecops-for-mcp-security/05-cicd-integration-and-policy-as-code.md)); vendor due diligence for third-party servers ([lesson 02](02-vetting-third-party-mcp-servers.md)); training for developers and users | Policy documents, RACI, approval records, vendor questionnaires |
| **MAP** | Context, intended use, stakeholders, risks and impacts identified | Inventory of agents, servers, tools and data flows (include shadow-server discovery); threat models ([chapter 3](../ch3-threat-modeling-mcp-architectures/README.md)); data classification per server; impact assessment for tools that write or send | Inventory export, DFDs, threat model, impact assessments |
| **MEASURE** | Analyze, test and track risks with suitable metrics | Pentest and abuse-case tests ([ch5 lessons 03, 04](../ch5-devsecops-for-mcp-security/03-dast-fuzzing-and-runtime-testing.md)); fuzzing; prompt-injection test suite; SAST/SCA results; Scorecard; firewall block/false-positive rates ([ch5 lesson 07](../ch5-devsecops-for-mcp-security/07-ai-firewalls-at-the-gateway.md)); drift and rug-pull alerts | Test reports, dashboards, metric definitions, retest records |
| **MANAGE** | Prioritize and act on risks; respond; improve | Risk register with owners and dates; gateway/firewall policy; kill switch; incident response plan with MCP scenarios (poisoned tool, leaked token, malicious update); patching SLAs; decommissioning | Risk register, runbooks, incident records, change log |

**GenAI Profile (AI 600-1).** It adds risks specific to generative AI (for example information security, data privacy, "confabulation", value chain and component integration) with suggested actions. For MCP, *value chain and component integration* maps directly to this chapter, and *information security* maps to prompt injection and tool abuse.

## 4. ISO/IEC 42001 applied to MCP

ISO/IEC 42001:2023 specifies an **AI management system (AIMS)**: you establish, implement, maintain and continually improve processes for responsible AI. It follows the common ISO management-system structure (context, leadership, planning, support, operation, performance evaluation, improvement) and has an **Annex A** of controls. Certification is against the main clauses plus the Annex A controls you select and justify in a *Statement of Applicability* (verify details in the standard).

Annex A control **themes** (verify the exact numbering and wording in your copy of the standard) and what they mean for an MCP deployment:

| Annex A theme | MCP deployment example |
|---|---|
| Policies related to AI | An AI/MCP acceptable-use and security policy, reviewed regularly |
| Internal organization | Named roles: MCP platform owner, server owners, security reviewers, escalation path |
| Resources for AI systems | Inventory of servers, models, data, tooling and the people with the skills to run them |
| Assessing impacts of AI systems | Impact and risk assessment before a tool that writes or sends is enabled; privacy impact where personal data is touched |
| AI system life cycle | The secure MCP SDLC ([ch5 lesson 01](../ch5-devsecops-for-mcp-security/01-devsecops-and-the-mcp-sdlc.md)): requirements, design, verification and validation, deployment, operation, change control |
| Data for AI systems | Data classification per server; provenance and quality of data the tools expose; retention |
| Information for interested parties | Documentation and transparency: what the agent can do, tool lists, user notices, incident communication |
| Use of AI systems | Rules for human oversight, approvals and acceptable use of agents with tools |
| Third-party and customer relationships | Supplier due diligence, contracts and SLAs for third-party and hosted MCP servers; customer-facing responsibilities |

**Evidence for an audit:** the inventory, risk assessments, approval records, vetting records, test reports, incident logs, review minutes, training records and the Statement of Applicability. The repo's [07 lesson 04](../../07-ai-governance/04-iso-42001-ai-management-system.md) walks through the AIMS in more depth. Remember: ISO 42001 certification is **not** a statement of conformity with the EU AI Act ([08 lesson 05](../../08-ai-compliance/05-iso-standards-and-law-vs-standard.md)).

## 5. Other emerging standards and guidelines (watch list)

These move fast; treat the list as pointers and verify status.

- **ISO/IEC 42005** (AI system impact assessment) and other ISO/IEC JTC 1/SC 42 work items on AI risk, data and lifecycle.
- **CEN-CENELEC JTC 21** harmonised standards under the EU AI Act (work in progress; timelines have slipped).
- **OWASP** work on agentic security, the MCP Top 10 (beta) and AI testing.
- **CSA** AI controls and agentic threat models; **CoSAI** workstreams (secure agentic systems, software supply chain for AI).
- **OpenSSF** work on AI/ML supply chain (model signing, SLSA for models).
- **NIST** profiles and overlays for AI (for example control overlays for AI systems; verify what has been published).
- **Industry protocols' own security guidance:** the MCP specification's security best practices (authorization, token handling, confused deputy) and the Linux Foundation / **Agentic AI Foundation** governance of MCP (Anthropic donated MCP to the AAIF in December 2025; verify the current governance and working groups).
- **National AI guidance and laws** ([lesson 06](06-compliance-and-regulation.md)).

## 6. Applying governance frameworks to MCP deployments specifically

A short, practical method. Do it once per deployment, then keep it alive.

1. **Scope the "AI system".** Draw the boundary: host, model(s), servers, tools, data, users. Decide what is in the AIMS or RMF scope.
2. **Inventory and classify.** Every server with owner, tier, data classes, credentials, transport, version, hash ([lesson 02](02-vetting-third-party-mcp-servers.md), [07 inventory](../../07-ai-governance/01-ai-inventory-and-system-register.md)).
3. **Assess risk and impact** using your framework's categories. For each tool: what is the worst thing it can do if the agent is tricked? Rate and record.
4. **Select controls** (SAST, pinning, gateway, approvals, egress control, logging) and map each to a framework item. Keep the mapping in a table so an auditor can follow it.
5. **Define human oversight.** Which tool calls need approval? Who may approve? What can the agent do alone?
6. **Define metrics and monitoring:** blocked injections, unapproved servers found, mean time to patch, drift alerts, incidents.
7. **Plan incident response and decommissioning.** MCP scenarios in the runbook; credential revocation steps.
8. **Review and improve:** scheduled reviews, post-incident updates, re-assessment on major changes (new model, new tool class, new regulation).

## 7. Hands-on

Fill the NIST AI RMF table in section 3 for a deployment you know: for each function write the **actual** control you have today and the missing one. Then pick three Annex A themes and write the evidence you could show.

## 8. Interview questions

- *What are the four functions of the NIST AI RMF?* Govern, Map, Measure, Manage. Govern cuts across the other three.
- *How is ISO/IEC 42001 different from the NIST AI RMF?* 42001 is a certifiable management-system standard; the AI RMF is a voluntary risk-management framework.
- *Which framework would you use to prove third-party MCP risk management to a customer?* ISO 42001 / 27001 evidence plus the vetting records; map to the AI RMF Govern function for the language.
- *Does ISO 42001 certification make you compliant with the EU AI Act?* No; it supports processes but is a different thing from legal conformity.

## 9. References

- NIST AI 100-1 and AI 600-1 (nist.gov/itl/ai-risk-management-framework); ISO/IEC 42001:2023 (iso.org); NIST SP 800-218 and 800-218A (csrc.nist.gov); OWASP GenAI Security Project (genai.owasp.org). Verify current versions.
- [CAISP ch7 lesson 02](../../caisp-course/ch7-emerging-threats-governance-compliance/02-governance-standards-and-frameworks.md); [07 AI governance](../../07-ai-governance/README.md); [07 lesson 03: AI risk management](../../07-ai-governance/03-ai-risk-management.md).
