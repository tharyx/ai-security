# Lesson 02: Threat Modeling Tools and Templates

**Syllabus items covered:** [CTMP 4] "Threat Modeling Tools and Templates", "Microsoft Threat Modeling Tool", "OWASP Threat Dragon", "CAIRIS Platform", "Threat Modeling As Code Tools", "Freemium Tools", "Threat Model Templates and Examples", and the IriusRisk, Threat Dragon and CAIRIS exercises.

**Time:** 1.5 hours plus labs. **Safety:** use fictional systems in any tool; do not upload a real architecture to a SaaS tool without approval.

> **DevOps analogy.** Choosing a threat modeling tool is like choosing between a GUI database admin tool and migration scripts: the GUI is great for exploring and workshops, the scripts are what you can review, repeat and run in a pipeline. Most teams need both.

## 1. The landscape

| Tool | Type | Strengths | Limits | Status (Nov 2026, verify) |
|---|---|---|---|---|
| **Microsoft Threat Modeling Tool** | Free Windows desktop app, DFD + STRIDE rule templates | Auto-generates threats per element and flow; good for learning STRIDE; Azure templates | Windows only; binary-ish `.tm7` files hard to diff; updates are infrequent | Free download from Microsoft |
| **OWASP Threat Dragon** | Open source, desktop and web, DFD + threats | Free, simple, JSON models you can keep in git; STRIDE, LINDDUN, CIA and other rule types (verify) | Rule engine is basic; diagram editing is graphical | OWASP project, version 2.x |
| **CAIRIS** | Open source platform (web) | Links usability (personas, tasks), requirements and security (assets, attackers, threats, vulnerabilities, risks) per environment; rich model | Steep learning curve; check maintenance activity | Open source; Docker image documented |
| **IriusRisk** | Commercial platform with a free **Community Edition** | Component libraries, questionnaires, rules engine, countermeasure tracking, Jira/ADO integration, compliance mapping | Cost for full editions; model lives in the product (API export) | Freemium; verify CE limits |
| **OWASP pytm** | Threat model **with code** (Python) | Reports, DFD, sequence diagrams from code | Python needed | OWASP project |
| **Threagile** | Threat model **as code** (YAML) | Built-in risk rules, risk tracking in YAML, JSON output | YAML gets long; check activity | Open source |
| **ThreatSpec** | Annotations in code | Model next to the code | Little development since about 2020 | Legacy |
| **STRIDE GPT, ThreatCompass, vendor AI assistants** | LLM-assisted drafting | Fast first draft, attack trees | Hallucinations, data leakage | [Lesson 04](04-ai-assisted-threat-modeling.md) |
| **Whiteboard, draw.io, Miro, Excalidraw** | Free-form | Fastest for a first session | Not machine-readable | Always useful |

Commercial platforms also include ThreatModeler (VAST), Devici and others; check current vendors before naming them in a report.

## 2. Microsoft Threat Modeling Tool

- Draw a DFD with stencils (process, external interactor, data store, data flow, trust boundary).
- Switch to **Analysis view**: the tool generates threats from its template (STRIDE per interaction), with a state (Not Started, Needs Investigation, Not Applicable, Mitigated) and justification.
- Templates: the default SDL template and an Azure template; you can write your own template (`.tb7`).
- Export an HTML report.
- Best for: learning STRIDE per interaction, Windows-centric teams. Weak for CI.

Walkthrough: [real-tools/microsoft-threat-modeling-tool.md](real-tools/microsoft-threat-modeling-tool.md).

## 3. OWASP Threat Dragon

- Version 2 runs as a **desktop app** (Windows, macOS, Linux) or a **web app** with GitHub/GitLab/Bitbucket integration for storing models (verify current options).
- Draw actors, processes, stores, flows and trust boundaries; select an element and add threats (type, status, severity, mitigation); mark elements **out of scope** with a reason.
- Models are **JSON**: keep them in the application repository and validate them in CI (the [Threat Dragon lab](labs/threat-dragon-and-cairis-models/README.md) shows how).
- Generates a PDF/print report.

Walkthrough: [real-tools/owasp-threat-dragon.md](real-tools/owasp-threat-dragon.md).

## 4. IriusRisk: multi-tier and multi-cloud

IriusRisk works like every rules-based platform:

1. Create a **project** and a **diagram** from a component library (web server, API, database, queue, AWS S3, Azure Blob Storage, and so on) placed in **trust zones**.
2. Answer **questionnaires** per component and per project (authentication, data sensitivity, internet exposure).
3. The **rules engine** adds **threats** and **countermeasures** from libraries (including cloud provider libraries and compliance standards).
4. Set countermeasure **states** (Required, Recommended, Implemented, Not applicable, Rejected) and see **inherent, current and projected risk** (terminology varies; verify).
5. Sync countermeasures to Jira or Azure DevOps; **report**.

**Multi-tier application:** model the web tier, application/API tier, data tier and async components (queues) as separate components in separate zones; the most important threats sit on the flows **between** tiers (authentication between services, injection into the data tier, message spoofing).

**Multi-cloud:** use each provider's components (AWS, Azure, Google Cloud), put each cloud in its own trust zone, and model the **cross-cloud links** explicitly (identity federation, data copies, shared secrets). One generic threat ("public object storage") maps to different provider controls. Shared responsibility differs per provider and per service.

The offline [rules-engine lab](labs/rules-engine-multitier-multicloud/README.md) reproduces this flow; the hedged walkthrough is [real-tools/iriusrisk-multi-tier-and-multi-cloud.md](real-tools/iriusrisk-multi-tier-and-multi-cloud.md). Multi-cloud controls in depth: [enterprise architecture multi-cloud control matrix](../../09-enterprise-architecture/05-multi-cloud-control-matrix-and-shared-responsibility.md).

## 5. CAIRIS platform

**CAIRIS** (Computer Aided Integration of Requirements and Information Security, Shamal Faily) treats security, usability and requirements as one model:

- **Environments** (for example "Day" and "Night", or "Production" and "Disaster recovery"): the same asset can have different risks in each.
- **Assets, attackers (with capabilities and motives), threats, vulnerabilities, risks** (a threat exploiting a vulnerability in an environment), **countermeasures**.
- **Personas and tasks** (usability): which real users do what, so security does not break their work.
- Generates many diagram types (risk analysis, asset, goal, task models) and documentation.

**Exploring a completed model:** start from the risk analysis view, sort risks by score, follow attacker → threat → asset, find assets with risks but no requirement or countermeasure, and check which persona tasks touch high-risk assets. The [lab](labs/threat-dragon-and-cairis-models/README.md) practises these questions on a simplified XML model. Walkthrough: [real-tools/cairis.md](real-tools/cairis.md).

## 6. Threat modeling as code tools

Covered in [chapter 05](../05-agile-threat-modeling-as-code/README.md): OWASP pytm (with code), Threagile (as code, YAML), ThreatSpec-style annotations (inside the code), Threat Dragon JSON (alongside the code). Choose them when the team lives in git and wants CI checks.

## 7. Freemium tools

"Freemium" = free tier with limits, paid tiers for scale. Typical examples: **IriusRisk Community Edition**, free tiers of some SaaS threat modeling and diagram tools. Before using one:

- What are the limits (projects, users, libraries, integrations)?
- **Where is the model stored** and who can see it? Architecture diagrams are sensitive.
- Can you **export** in an open format if you leave?
- Is the free tier allowed for commercial use?

## 8. Threat model templates and examples

- **Document template:** this chapter's [threat model template](templates/threat-model-template.md) (scope, DFD, assets, assumptions, threats, decisions, accepted risks, review).
- **Tool templates:** Microsoft TMT `.tb7` templates (SDL, Azure), Threat Dragon example models, pytm's sample `tm.py` and report template, Threagile's example YAML, IriusRisk libraries.
- **Examples to study:** the OWASP Threat Model Cookbook (verify), the Kubernetes and AWS S3 threat models in [chapter 07](../07-secure-design-principles-and-case-studies/README.md), CAIRIS example models, and the AI system examples in [CAISP chapter 5](../../caisp-course/ch5-threat-modeling-ai-systems/README.md).

## 9. Scenario: picking a tool for a bank

A bank's AppSec team needed threat models for 60 applications. They used Microsoft TMT for training workshops (free, teaches STRIDE), Threat Dragon JSON in each repository for teams that wanted something visual but versioned, pytm for the platform team, and evaluated IriusRisk Community Edition for the compliance mapping. The deciding questions were not features but: where does the model live, can CI read it, and can the security team see all 60 in one place?

## 10. Common mistakes

- Buying a platform before anyone has run a whiteboard session.
- Accepting every auto-generated threat as real (or ignoring all of them).
- Uploading real architectures to a free SaaS tier without approval.
- Models that cannot be exported or diffed.

## 11. Checklist

- [ ] I can compare Microsoft TMT, Threat Dragon, CAIRIS, IriusRisk, pytm and Threagile.
- [ ] I can explain the IriusRisk flow and how multi-cloud models differ.
- [ ] I can explore a completed CAIRIS model with five questions.
- [ ] I can list four questions to ask before using a freemium tool.

## References

- Microsoft Threat Modeling Tool documentation (learn.microsoft.com); OWASP Threat Dragon (owasp.org, GitHub); CAIRIS (cairis.org, documentation); IriusRisk (iriusrisk.com); OWASP pytm; Threagile.
- Shamal Faily, *Designing Usable and Secure Software with IRIS and CAIRIS* (Springer, 2018).
- Real-tool guides in [real-tools/](real-tools/microsoft-threat-modeling-tool.md).
