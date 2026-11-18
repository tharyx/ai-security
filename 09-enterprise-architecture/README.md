# Module 09: Enterprise AI Security Architecture

> **Weeks:** 25–28 (Month 7) · **Time:** ~40 hours · **Phase gate:** Phase 7 (multi-cloud control equivalence)

## What and why

Modules 02–06 taught you to secure one LLM app, one RAG pipeline, one MCP server, one agent and one pipeline. An enterprise runs **dozens** of these, on **more than one cloud**, for **many tenants**. This module teaches you to design the **platform** they all share, and to prove it is secure on AWS, Azure and Google Cloud.

You will learn to think like an architect:

1. Start from **security outcomes** ("no path to a model skips the gateway"), not from product names.
2. Map each outcome to **each cloud's services**, and write down where they differ.
3. Describe the platform **as code**, review it **automatically**, and record decisions as **ADRs** (architecture decision records).

Most real AI incidents so far (leaked keys, public databases, broken tenant isolation, unauthenticated AI compute) were platform mistakes. This is where an AI security architect earns their title.

## Learning path

| # | Lesson | Weeks | You will be able to… |
|---|---|---|---|
| 01 | [Enterprise AI reference architecture](01-enterprise-ai-reference-architecture.md) | 25–28 (read first) | Draw the platform, name the control in each block, state eight security invariants |
| 02 | [AWS AI security: Bedrock and SageMaker](02-aws-ai-security.md) | 25 | Secure Bedrock with IAM, PrivateLink, KMS, CloudTrail, Bedrock Guardrails |
| 03 | [Azure AI security: AI Foundry and Azure OpenAI](03-azure-ai-security.md) | 26 | Secure Azure OpenAI with Entra ID, Private Endpoints, Key Vault, Azure Monitor, Prompt Shields |
| 04 | [Google Cloud AI security: Vertex AI](04-gcp-ai-security.md) | 27 | Secure Vertex AI with service accounts, VPC-SC, PSC, CMEK, audit logs, Model Armor |
| 05 | [Multi-cloud control matrix, shared responsibility and ADRs](05-multi-cloud-control-matrix-and-shared-responsibility.md) | 28 | Prove control equivalence, explain shared responsibility, write ADRs, run a design review |
| Lab | [`lab/`](lab/): architecture-as-code reviewer | 25–28 | Review YAML designs against a 21-control matrix; find gaps with severity and per-cloud fixes |

## Module architecture

![Enterprise AI reference architecture](../images/09-enterprise-ai-reference-architecture.svg)

![Module 09 map](../images/09-module-overview.svg)

## Key concepts (glossary)

| Term | Meaning |
|---|---|
| **AI gateway** | The single front door for model, RAG and agent traffic: authentication, quotas, routing, guardrails, logging |
| **PDP / PEP** | Policy decision point (answers "allowed?") / policy enforcement points (gateway, RAG, broker) that ask and enforce |
| **Control plane / data plane** | Changing the platform (deploy, configure) vs using it (prompts, retrieval, tool calls) |
| **Data zone** | A group of stores with the same classification, keys and access rules |
| **CMK / CMEK** | Customer-managed (encryption) key: a key you control in KMS / Key Vault / Cloud KMS |
| **Private endpoint** | A private IP in your network for a cloud service (PrivateLink, Private Link, Private Service Connect) |
| **VPC Service Controls** | Google Cloud's API-level perimeter that blocks data use from outside, even with valid credentials |
| **Workload identity** | Temporary credentials for code (IAM roles, managed identities, service accounts) instead of stored keys |
| **Landing zone** | A pre-built multi-account / subscription / project structure with central guardrails and logging |
| **SCP / Azure Policy / Org Policy** | Organization-wide preventive rules on AWS / Azure / Google Cloud |
| **Control equivalence** | Proof that different services on different clouds deliver the same security outcome, with gaps recorded |
| **Shared responsibility** | The split of security duties between provider and customer; for AI, data, identity, config and usage stay yours |
| **ADR** | Architecture decision record: context, options, decision, consequences, residual risk, owner, review date |
| **Architecture-as-code** | A machine-readable description of components, identities and data flows that tools can check |
| **Time-bound exception** | A risk acceptance with approver and expiry date; never for critical controls |
| **Drift** | When the running system no longer matches the approved design |

## How the lessons connect

- **Lesson 01** gives the cloud-neutral blueprint and the invariants. Every later lesson implements the same blueprint.
- **Lessons 02–04** implement it on each cloud. Use the **same** control IDs from the matrix in all three, so your notes line up.
- **Lesson 05** joins them: the matrix proves equivalence, the shared-responsibility map says who owns each control, ADRs record choices, and the checklist ends in a gate decision.
- The **lab** runs through all five lessons: one reviewer, one matrix, five fixtures (vulnerable, three secure clouds, one drifted design with exceptions).
- **Next:** [Module 10 (capstone)](../10-capstone-project/) uses this platform as the base for the secure AI operations assistant.

## Lab at a glance

```text
lab/
├── control_matrix.yaml        # 21 controls x (AWS, Azure, GCP) with evidence and OWASP/CIS mappings
├── reviewer.py                # strict schema, attribute checks, graph checks, exceptions, CLI + CSV
├── architectures/
│   ├── vulnerable_aws.yaml    # the hackathon build: 17 VULN comments
│   ├── secure_aws.yaml        # reference design per cloud
│   ├── secure_azure.yaml
│   ├── secure_gcp.yaml
│   └── drifted_gcp.yaml       # six months later: drift + valid / expired / rejected exceptions
├── demo.py                    # scorecard: every control x every design
├── test_control_matrix.py     # the matrix maps every control to all three clouds
└── test_reviewer.py           # attack-style tests + mutation tests (break one control, catch exactly it)
```

```powershell
python 09-enterprise-architecture/lab/demo.py
python -m pytest 09-enterprise-architecture
```

![Architecture-as-code review pipeline](../images/09-architecture-as-code-review.svg)

## Module mini-project: "One assistant, three clouds"

Build a portfolio-ready architecture pack for the ops assistant (it becomes the base of your capstone):

1. **Three architecture files** (`my_aws.yaml`, `my_azure.yaml`, `my_gcp.yaml`) that pass the reviewer, each with the real setting behind every value written as a YAML comment.
   Also record, per cloud: data region and retention, the deployment (CI) identity, which controls are provider-managed vs customer-managed, and the main cost and operational trade-offs.
2. **One diagram per cloud** (copy the style of the lesson diagrams) and the cloud-neutral reference diagram.
3. **Control matrix extension:** add two controls of your own (for example "ingestion sanitizes untrusted documents" and "approved model allowlist"), with checks, matrix rows for all clouds, and mutation tests.
4. **Five ADRs:** provider choice, tenant isolation model, logging of prompt content, key ownership, and one exception you would accept.
5. **A design-review record** for one design, using the checklist in lesson 05, ending in a gate decision.

**Done when:** `python -m pytest 09-enterprise-architecture` passes with your new controls, and a peer can follow your pack without asking you questions.

## Interview questions (cross-cutting, system design)

<details><summary><b>Q1. Design a secure multi-tenant AI platform that 30 internal teams will use on two clouds.</b></summary>

One logical platform with the same blocks on both clouds: an AI gateway per cloud (SSO, tenant from claims, quotas, routing to approved models, guardrails, redacted logging), a central PDP with policies as code, RAG with filter-then-rank retrieval and per-tenant indexes for sensitive tenants, a tool gateway with a registry and approvals, agent runtimes with limits and kill switches, private endpoints and deny-by-default egress, CMKs per data zone, and all logs to one SIEM with correlation IDs. Platform templates make these defaults; a control matrix and CI reviewer prove equivalence; ADRs record differences. Teams onboard through a request that adds them to the AI inventory and gives them a tenant, quotas and an identity.
</details>

<details><summary><b>Q2. How do you prove to an auditor that the same control holds on AWS, Azure and Google Cloud?</b></summary>

With an outcome-based control matrix: one row per outcome, the mechanism and evidence per cloud, and the equivalence level. Then automated evidence: policy exports, architecture-review reports from CI, test results (for example cross-tenant tests with canaries), and logs showing the control working. Differences are documented in ADRs with compensating controls.
</details>

<details><summary><b>Q3. Where do you enforce tenant isolation in an AI platform, end to end?</b></summary>

Identity (tenant claim from the IdP, never from the body), gateway (per-tenant quotas, routing), retrieval (server-side filters or per-tenant indexes), tools (resource ownership checks in the broker), memory and caches (keyed by tenant), logs (tenant field, access by tenant), and keys (per-tenant CMKs for high-sensitivity tenants). And tests: canary documents and resources per tenant in CI.
</details>

<details><summary><b>Q4. A stolen workload credential is used from outside your network. Compare what happens on each cloud.</b></summary>

On Google Cloud with VPC-SC, calls to protected services from outside the perimeter are denied and logged. On AWS, it depends on policies: SCPs or resource/endpoint policies using `aws:SourceVpce` or network conditions can deny it; otherwise the credential works until it expires. On Azure, `publicNetworkAccess: Disabled` stops network access to the resource; Entra Conditional Access for workload identities may also help (check features). In all cases short-lived credentials limit the window, and detections on unusual source IPs matter.
</details>

<details><summary><b>Q5. How would you roll out architecture-as-code review in a company that has none?</b></summary>

Start with the highest-value checks (gateway bypass, public endpoints, static keys, tenant isolation) in report-only mode on existing designs; fix or except findings; then make critical/high blocking in CI for new changes; add exceptions with expiry; generate the architecture file from IaC over time to avoid drift; and add mutation tests so the checks themselves are proven.
</details>

<details><summary><b>Q6. What are the hardest AI-specific parts of shared responsibility to explain to a business?</b></summary>

That the provider's safety features (content filters, guardrails) are tools we must configure and that are not security boundaries; that our prompts, RAG data, tools and agents are entirely our responsibility; that provider data-retention settings (abuse monitoring, caching) need a decision from us; and that legal accountability for what our AI says stays with us.
</details>

<details><summary><b>Q7. Your AI gateway is down. What should happen?</b></summary>

Fail closed for anything with data access or tools: no direct fallback to the model that skips authentication, quotas and logging. Offer degraded service (a status message, cached static answers) and fail over to a second gateway instance or region. The design must not include a "bypass for emergencies" path; if business needs require one, it is an ADR with an owner, logging and a kill switch.
</details>

<details><summary><b>Q8. How do you keep an approved architecture from drifting?</b></summary>

Preventive policy in each cloud (SCPs, Azure Policy deny, Org Policy), IaC as the only change path with review, the architecture reviewer in CI on every change, scheduled comparison between the declared architecture and the observed inventory, dated exceptions, and quarterly drift reviews like lesson 04.
</details>

<details><summary><b>Q9. Which logs would you require from every AI workload on the platform, and why?</b></summary>

Gateway logs (user, tenant, model, tokens, decision, correlation ID), guardrail verdicts, retrieval logs (document IDs, ACL-filtered counts), tool broker logs (proposed call, decision, approval, result), control-plane audit logs, and identity sign-in logs. Content (prompts/outputs) only redacted and restricted. They are what you need to answer: who did what, with which data, and was it allowed.
</details>

<details><summary><b>Q10. Explain to a CTO why the platform team should own AI security controls instead of each product team.</b></summary>

Because the hard parts (identity, tenant isolation, egress, tool approval, logging) are the same for every AI feature and are easy to get subtly wrong. Building them once in the platform makes them consistent, testable and auditable, lets product teams move faster, and gives us one place to react when a new attack appears. Product teams still own their prompts, data and use-case risks.
</details>

## References

- OWASP Top 10 for LLM Applications 2025, https://genai.owasp.org/llm-top-10/
- NIST AI 600-1, *Generative AI Profile*, https://doi.org/10.6028/NIST.AI.600-1
- Google Secure AI Framework (SAIF), https://saif.google/
- AWS Generative AI Security Scoping Matrix, https://aws.amazon.com/ai/generative-ai/security/scoping-matrix/
- Microsoft AI shared responsibility model, https://learn.microsoft.com/azure/security/fundamentals/shared-responsibility-ai
- Google Cloud shared responsibility and shared fate, https://cloud.google.com/architecture/framework/security/shared-responsibility-shared-fate
- MITRE ATLAS, https://atlas.mitre.org/
- Program files: [assessment rubric](../00-program/assessment-rubric.md) · [portfolio and interview guide](../00-program/portfolio-and-interview-guide.md) · [templates](../00-program/templates/)

---

**Courses for this module (KodeKloud / Udemy):** see [00-program/learning-resources.md](../00-program/learning-resources.md).
