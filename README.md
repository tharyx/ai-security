# AI Security Master Learning Program
**Advanced AI Security Engineer / Architect track | 9 months | 36 weeks | Multi-cloud**

This repository is a structured, hands-on curriculum for designing, building, attacking, defending, operating and governing enterprise AI systems across AWS, Microsoft Azure and Google Cloud.

> **Operating principle:** Learn → Model threats → Build → Attack in a controlled lab → Defend → Automate → Produce evidence.

## Target outcome
By the end of 36 weeks, you should be able to:
- Threat-model an AI-enabled system across data, model, application, tool, agent, infrastructure and organizational boundaries.
- Secure LLM applications, RAG pipelines, MCP integrations and agentic workflows.
- Design identity, authorization, isolation, secrets, network, supply-chain and runtime controls.
- Integrate AI security testing into CI/CD and cloud operations.
- Build an AI governance and compliance evidence pack.
- Present an enterprise reference architecture and defend its trade-offs.

## Time commitment
- 12 hours/week: 3 hours study, 4 hours build, 2 hours attack/defense testing, 1 hour documentation, 2 hours review/assessment.
- Each phase ends with a working artifact and a go/no-go assessment.
- Do not advance based on videos watched. Advance when the acceptance criteria are demonstrated.

## Repository map
| Path | Purpose |
|---|---|
| `00-program/` | Program guide, prerequisites, weekly plan and assessment rubric |
| `01-foundations/` | AI/ML/LLM architecture and threat-model fundamentals |
| `02-llm-security/` | LLM threat catalogue, labs and mitigations |
| `03-rag-security/` | Secure ingestion, retrieval, tenancy and vector-store controls |
| `04-mcp-security/` | MCP trust boundaries, tool authorization and server hardening |
| `05-agent-security/` | Agent identity, autonomy controls, memory and sandboxing |
| `06-ai-devsecops/` | Secure SDLC, model supply chain, CI/CD and runtime operations |
| `07-cloud-security/` | AWS, Azure and GCP control mapping |
| `08-governance-compliance/` | AI governance, risk, privacy and compliance |
| `09-capstone/` | Enterprise architecture project and acceptance tests |
| `10-templates/` | Reusable threat model, risk register, test case and incident templates |

## Recommended prerequisites
You already have a strong platform/security engineering foundation. Refresh:
- Python 3.11+, typing, virtual environments, pytest, FastAPI and HTTP fundamentals.
- OAuth 2.0/OIDC, JWT validation, RBAC/ABAC, TLS, DNS, network segmentation.
- Docker, Kubernetes, Terraform, GitHub Actions and secrets management.
- Basic SQL, vector similarity concepts and cloud IAM.
- Basic ML concepts: datasets, training, inference, embeddings, transformers and evaluation.

You do **not** need to become a machine-learning researcher. You do need to understand enough model behavior to reason about the attack surface and limitations of controls.

## Lab safety rules
1. Use synthetic data and accounts you own.
2. Run attacks only against intentionally vulnerable local applications or explicitly authorized test environments.
3. Never place production credentials, customer records or proprietary prompts in public model services or repositories.
4. Use low-cost quotas, request limits and budget alerts for cloud labs.
5. Do not expose local MCP servers or agent tools to the public internet.
6. Keep destructive tools disabled by default; require explicit human approval in labs.
7. Record test scope, expected impact, actual result, evidence and remediation.

## How to use the program
1. Start with `00-program/36-week-plan.md`.
2. Read the relevant module guide before each week.
3. Complete the lab and save code, tests, screenshots/log excerpts (sanitized), and a short design decision record.
4. Complete the phase gate in `00-program/assessment-rubric.md`.
5. Maintain the risk register and evidence index throughout the program.
6. Finish with the capstone in `09-capstone/`.

## Important technical stance
- Prompt instructions are not an authorization boundary.
- A model's output is untrusted input until validated by deterministic application code.
- Retrieved content, tool descriptions, memory and external data are untrusted.
- Enforce authorization outside the model, as close as possible to the data or action.
- Tool execution should use narrowly scoped identities, allowlists, schemas, timeouts and audit logs.
- Human approval is a control for high-impact actions, not a substitute for least privilege.
- Evaluate security continuously; a single red-team pass does not prove safety.

## Versioning and freshness
AI frameworks, model APIs, MCP specifications, cloud services and regulations change quickly. Before production use, check the current official documentation and record:
- source URL and access date;
- version/release;
- applicable product region and service tier;
- control owner;
- evidence of implementation and testing.

See `08-governance-compliance/official-references.md` for the starting reference set.
