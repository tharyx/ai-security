# Expanded AI Security Master Curriculum

**Track:** Advanced AI Security Engineer / Architect | **Duration:** 36 weeks | **Effort:** 10–12 hours/week | **Cloud:** AWS, Azure, Google Cloud

This is a study-and-build curriculum, not a list of topics. Each module contains architecture, concepts, threat scenarios, defensive patterns, practical labs, code, exercises and acceptance criteria. Use synthetic data and isolated environments only.

## Study method
For every topic: **Understand → Draw → Threat-model → Build → Attack → Defend → Automate → Document.** Do not move on because you watched a course. Move on when the lab passes its acceptance criteria and you can explain residual risk.

## 36-week sequence
| Weeks | Module | Required outcome |
|---|---|---|
| 1–4 | AI foundations and threat modeling | System map, data flows, trust boundaries, risk register |
| 5–8 | LLM security | Injection, disclosure, unsafe output and abuse test suite |
| 9–12 | RAG security | Multi-tenant retrieval with document-level authorization |
| 13–16 | MCP security | Approved server registry, scoped identity and tool broker |
| 17–20 | Agent security | Bounded agent with identity, approval and kill switch |
| 21–24 | AI DevSecOps | CI/CD security gates, provenance, container and runtime controls |
| 25–28 | Enterprise architecture (multi-cloud) — module 09 | AWS/Azure/GCP security outcome mapping |
| 29–32 | Governance (07) and compliance (08) | AI inventory, risk treatment and evidence pack |
| 33–36 | Capstone (10) | Secure AI operations assistant and architecture defense |

## Repository modules
| # | Module | Lessons |
|---|---|---|
| 01 | [AI Security Fundamentals](../01-ai-security-fundamentals/) | AI basics for security, architecture and trust boundaries, threat modeling, attack surface |
| 02 | [LLM Security](../02-llm-security/) | [prompt-injection](../02-llm-security/prompt-injection/), [jailbreak](../02-llm-security/jailbreak/), [data-leakage](../02-llm-security/data-leakage/), [security-testing](../02-llm-security/security-testing/), [model-threats](../02-llm-security/model-threats/) |
| 03 | [RAG Security](../03-rag-security/) | [document-security](../03-rag-security/document-security/), [vector-db-security](../03-rag-security/vector-db-security/), [access-control](../03-rag-security/access-control/), [retrieval-reranking](../03-rag-security/retrieval-reranking/), [response-security](../03-rag-security/response-security/), [secure-hr-assistant](../03-rag-security/secure-hr-assistant/) |
| 04 | [MCP Security](../04-mcp-security/) | [mcp-server](../04-mcp-security/mcp-server/), [authentication](../04-mcp-security/authentication/), [tool-security](../04-mcp-security/tool-security/), [secure-operations](../04-mcp-security/secure-operations/) |
| 05 | [Agent Security](../05-agent-security/) | [agent-identity](../05-agent-security/agent-identity/), [permissions](../05-agent-security/permissions/), [sandboxing](../05-agent-security/sandboxing/), [multi-agent-trust](../05-agent-security/multi-agent-trust/), [monitoring-and-response](../05-agent-security/monitoring-and-response/), [mini-project](../05-agent-security/mini-project/) |
| 06 | [AI DevSecOps](../06-ai-devsecops/) | [terraform](../06-ai-devsecops/terraform/), [docker](../06-ai-devsecops/docker/), [kubernetes](../06-ai-devsecops/kubernetes/), [cicd](../06-ai-devsecops/cicd/), [runtime-security](../06-ai-devsecops/runtime-security/) |
| 07 | [AI Governance](../07-ai-governance/) | inventory, operating model, risk management, ISO/IEC 42001 |
| 08 | [AI Compliance](../08-ai-compliance/) | EU AI Act, GDPR and India DPDP, control mapping and evidence, audit readiness |
| 09 | [Enterprise Architecture](../09-enterprise-architecture/) | reference architecture, AWS, Azure, GCP, multi-cloud control matrix |
| 10 | [Capstone Project](../10-capstone-project/) | brief, milestones, red-team exercise, architecture defense |

## Weekly timebox
- 3 hours: concepts and official documentation.
- 4 hours: implementation.
- 2 hours: controlled attack and regression tests.
- 1 hour: architecture decision record and risk updates.
- 1–2 hours: review, quiz and portfolio cleanup.

## Safety and engineering rules
- Use accounts and systems you own or are explicitly authorized to test.
- Use synthetic documents, fake tokens and mock cloud resources.
- Never place production credentials or customer data in prompts, labs or public repositories.
- Keep destructive actions disabled; use read-only roles and simulated approvals.
- Treat user input, retrieved content, model output, tool descriptions and agent memory as untrusted.
- Enforce identity, authorization and business policy in deterministic services—not in prompt text.
- Record model/provider/version, policy version and test evidence for reproducibility.

## Phase gates
A phase passes only when: (1) architecture is documented, (2) attack can be reproduced safely, (3) mitigation is implemented, (4) automated regression passes, (5) residual risk is documented, and (6) evidence is committed without secrets.

## Graduation standard
Score 0–4 in architecture, attack reproduction, defensive implementation, automation, cloud integration, monitoring, governance and communication. Target 3+ in every critical area and 80% overall. No unresolved critical findings; high findings require approved, time-bound exceptions.
