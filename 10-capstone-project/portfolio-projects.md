# Portfolio Projects: Six Repositories That Prove Your Skills

> **Module:** 10 · Capstone Project · **Weeks:** build alongside the modules, polish in week 36 · **Time:** 6–12 hours per project (on top of the labs)
> **You will:** turn the repo's labs into six portfolio repositories that match the roadmap's portfolio list, each with a clear scope, a live demo, a README that reviewers can follow, and an interview story.

The roadmap asks for six portfolio projects. Each one below **reuses a lab you already passed**, then extends it into something you own. Rules for all six:

- Everything runs **offline** with synthetic data and canaries (`aisec_lab.make_canary`), one command to demo, tests in CI.
- Every claim in the README links to **evidence**: a test, a scorecard, a CI run.
- Each repo has a "**what I would do differently**" and a "**limitations**" section. Panels trust honest limits.
- Never use employer data, real credentials or real company names.

| # | Project | Builds on | Best for roles |
|---|---|---|---|
| 1 | LLM Security Testing Lab | [Module 02](../02-llm-security/) | LLM Security Engineer, AI Red Team Engineer |
| 2 | Secure Enterprise RAG (HR assistant) | [Module 03](../03-rag-security/), [09 DATA controls](../09-enterprise-architecture/) | GenAI Security Engineer, AI Security Engineer |
| 3 | MCP Security Gateway | [Module 04](../04-mcp-security/), [09 gateway lab](../09-enterprise-architecture/lab/gateway/) | Agentic AI Security Engineer, AI Security Architect |
| 4 | Secure Cloud AI Agent | [Module 05](../05-agent-security/), this capstone's broker, [09 AWS lesson](../09-enterprise-architecture/02-aws-ai-security.md) | Agentic AI Security Engineer, AI Security Engineer |
| 5 | AI Governance and Compliance Framework | [Module 07](../07-ai-governance/), [Module 08](../08-ai-compliance/) | AI Governance and Risk Consultant |
| 6 | AI DevSecOps Pipeline | [Module 06](../06-ai-devsecops/) | AI Security DevSecOps Engineer |
| ★ | Capstone: Secure AI Operations Assistant | all modules | AI Security Architect (the centerpiece) |

---

## 1. LLM Security Testing Lab

**Goal:** a deliberately vulnerable chatbot, an automated attack suite (direct and indirect injection, jailbreak, system-prompt and hidden-context extraction, insecure output handling), mitigations, and a retest that shows the difference.

| | |
|---|---|
| **Scope in** | One chatbot with a system prompt holding a canary, one RAG document source, one markdown renderer; attack suite with N runs per payload; secure version with layered defenses |
| **Scope out** | Attacks on real third-party models' safety systems; real secrets |
| **Builds on** | [`02-llm-security/prompt-injection/lab`](../02-llm-security/prompt-injection/lab/), [`jailbreak/lab`](../02-llm-security/jailbreak/lab/), [`data-leakage/lab`](../02-llm-security/data-leakage/lab/), [`security-testing/lab`](../02-llm-security/security-testing/lab/) (harness, YAML suite) |
| **Extend it with** | An `--ollama` run that reports attack success rate (ASR) per category over 10 runs; a markdown-image exfiltration test; an OWASP LLM 2026 id on every test case |
| **Demo (3 minutes)** | Run the suite on the vulnerable bot (high ASR, canary leaks), switch on defenses, re-run (impact rate 0), then show one test that still "fails" at the soft layer but has no impact |
| **Interview story** | "Model-level defenses lower the odds; app-level controls remove the impact. My suite measures both, and it runs on every prompt change." Be ready for: *Why measure ASR over many runs? What is the difference between jailbreak and prompt injection?* |

## 2. Secure Enterprise RAG (HR document assistant)

**Goal:** an HR policy assistant for two tenants where employees, managers and HR see different documents, with tenant isolation, document-level authorization before ranking, encryption choices, deletion that propagates to embeddings, and an audit log.

| | |
|---|---|
| **Scope in** | Ingestion with sanitization and labels; per-tenant index or server-side filters; group ACLs; citation checks; deletion workflow; audit log |
| **Scope out** | Real employee data; fine-tuning |
| **Builds on** | [`03-rag-security/access-control/lab`](../03-rag-security/access-control/lab/), [`document-security/lab`](../03-rag-security/document-security/lab/), [`vector-db-security/lab`](../03-rag-security/vector-db-security/lab/); control DATA-03 in the [Module 09 matrix](../09-enterprise-architecture/lab/control_matrix.yaml) |
| **Extend it with** | The five roadmap scenarios as tests: user A never retrieves user B's docs; a malicious PDF cannot override the system prompt; an unauthorized user cannot get HR docs; deleting a source removes its chunks and embeddings; authorization happens before content reaches the model |
| **Demo** | Canary documents per tenant and group; run the five scenario tests; show a retrieval log with `acl_filtered` counts |
| **Interview story** | "Similarity is not authorization. I filter before ranking, by claims from the verified token, and I prove it with canaries in CI." Be ready for: *Per-tenant index or shared index with filters? How do you handle deletion requests (GDPR, DPDP)?* |

## 3. MCP Security Gateway

**Goal:** a gateway in front of MCP servers that validates server identity and pinned tool definitions, enforces per-tool authorization and scopes, protects secrets (no token passthrough), validates inputs and audits every call.

| | |
|---|---|
| **Scope in** | Server registry with owners and pinned description hashes; allowlist; typed schemas; audience-bound tokens; secret redaction in logs; audit trail |
| **Scope out** | Publicly exposed MCP servers; real cloud credentials |
| **Builds on** | [`04-mcp-security/mcp-server/lab`](../04-mcp-security/mcp-server/lab/), [`tool-security/lab`](../04-mcp-security/tool-security/lab/), [`authentication/lab`](../04-mcp-security/authentication/lab/); the [AI gateway lab](../09-enterprise-architecture/lab/gateway/) (audience checks, token fingerprints); controls TOOL-01, IAM-06 |
| **Extend it with** | The roadmap's MCP scenarios as tests: malicious server steals credentials, tool runs a shell command, agent gets excessive permissions, a resource injects instructions, tokens leak through logs, an untrusted server changes tool descriptions (rug pull) |
| **Demo** | Register a server, change its tool description, watch the gateway block it; show the audit trail with token fingerprints only |
| **Interview story** | Map each control to the OWASP MCP Top 10 (MCP01 tokens, MCP03 tool poisoning, MCP07 authN/authZ, MCP08 telemetry, MCP09 shadow servers). Be ready for: *Why is token passthrough forbidden? How do you find shadow MCP servers?* |

## 4. Secure Cloud AI Agent (AWS)

**Goal:** an agent that reads cloud information (instances, logs) and proposes remediation, behind approval gates, following the roadmap's AWS agent controls.

| | |
|---|---|
| **Scope in** | Simulated read tools (inventory, logs), propose-only write tools (restart, security-group change, Terraform plan); the seven roadmap controls: read-only by default, separate identity per agent, explicit authorization for sensitive actions, human approval for production, time-limited credentials, full audit trail, sandboxing and rollback |
| **Scope out** | Real AWS accounts (optional: a sandbox account with read-only roles and no write permissions at all) |
| **Builds on** | [`05-agent-security/permissions/lab`](../05-agent-security/permissions/lab/), [`agent-identity/lab`](../05-agent-security/agent-identity/lab/), [`sandboxing/lab`](../05-agent-security/sandboxing/lab/); this module's [`ops_assistant.py`](lab/ops_assistant.py) broker; [Module 09 AWS lesson](../09-enterprise-architecture/02-aws-ai-security.md) |
| **Extend it with** | An IAM policy document per agent role (as JSON) checked by a test for wildcards; approval with expiry; a dry-run Terraform plan as the only "write" |
| **Demo** | An injected log line asks the agent to open a security group; the broker denies it; an operator approves a restart with the exact arguments shown |
| **Interview story** | "The model proposes; the broker decides with its own scoped identity; production changes need a human who sees the exact action." Be ready for: *How do you stop goal hijacking? What does your kill switch do in under a minute?* |

## 5. AI Governance and Compliance Framework

**Goal:** an AI inventory, risk register, policy set, control mapping, evidence repository and a simple compliance dashboard for a fictional company.

| | |
|---|---|
| **Scope in** | Inventory with owners and risk tiers; risk register with treatment and acceptance; the seven roadmap policies (acceptable use, risk management, model approval, data governance, third-party AI risk, AI incident response, AI security standard); mapping to NIST AI RMF, ISO/IEC 42001, EU AI Act and India DPDP; evidence links |
| **Scope out** | Legal advice; real company data |
| **Builds on** | [`07-ai-governance/lab`](../07-ai-governance/lab/) (register, risk register), [`08-ai-compliance/lab`](../08-ai-compliance/lab/) (AI Act classifier, evidence checker, incident clock); the [Module 09 control matrix CSV export](../09-enterprise-architecture/05-multi-cloud-control-matrix-and-shared-responsibility.md) |
| **Extend it with** | A generated Markdown or HTML dashboard: systems by risk tier, open risks by owner, controls without evidence, exceptions near expiry |
| **Demo** | Add a new AI system; the checker shows missing evidence and the regulatory clock; the dashboard updates |
| **Interview story** | "Governance is evidence, not paperwork: every control row links to a test or an export." Remember the key distinction: NIST AI RMF and OWASP are frameworks, ISO/IEC 42001 is a certifiable management-system standard, and the EU AI Act, GDPR and DPDP are law (verify current application dates at the source). |

## 6. AI DevSecOps Pipeline

**Goal:** a CI/CD pipeline for an AI service that scans models and dependencies, detects secrets, runs LLM security tests, enforces policy gates and requires approval for deployment.

| | |
|---|---|
| **Scope in** | Model file scanning (pickle vs safetensors), dependency audit, secret scanning, Dockerfile and Kubernetes policy checks, Terraform policy checks, the LLM attack suite, the architecture reviewer, a release gate with approval |
| **Scope out** | Deploying to real production |
| **Builds on** | [`06-ai-devsecops/cicd/lab`](../06-ai-devsecops/cicd/lab/), [`docker/lab`](../06-ai-devsecops/docker/lab/), [`kubernetes/lab`](../06-ai-devsecops/kubernetes/lab/), [`terraform/lab`](../06-ai-devsecops/terraform/lab/); [reviewer](../09-enterprise-architecture/lab/reviewer.py) as a CI step |
| **Extend it with** | A job that re-runs the attack suite when only a prompt file or the model name changes; an SBOM/AI-BOM artifact |
| **Demo** | Open a pull request that adds a pickle model and a wildcard IAM permission; show the pipeline failing with clear messages; fix and pass |
| **Interview story** | "Every AI change goes through the same gates as code, including prompt and model changes, because behavior changes with them." Be ready for: *How do you prove model provenance? What blocks a release, and who can override it?* |

---

## README outline (use it for every project)

1. **Problem and intended use** (3–5 sentences, one user story).
2. **Architecture** (one diagram with trust zones; link to the repo's style).
3. **Threat model** (top five abuse cases with OWASP LLM 2026 / ASI / MCP ids).
4. **Controls** (table: control, hard or soft, which abuse case it stops).
5. **Results** (the vulnerable-vs-secure scorecard; test count; CI badge).
6. **How to run** (one command for the demo, one for the tests).
7. **Residual risks and limitations.**
8. **What I would do differently.**
9. **Cost and operational assumptions.**
10. **References** (standards and research only; no copied text).

## How to talk about a project in 2 minutes

Use the seven-step answer pattern from [lesson 04](04-architecture-defense-and-interview.md): clarify the system, name assets and boundaries, state the invariant, the hard controls, detection and recovery, the trade-offs, and the **test that proves it**. End with one honest limitation and what you would build next.
