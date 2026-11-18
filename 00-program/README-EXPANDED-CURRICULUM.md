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
| 25–28 | Multi-cloud AI security | AWS/Azure/GCP security outcome mapping |
| 29–32 | Governance and compliance | AI inventory, risk treatment and evidence pack |
| 33–36 | Enterprise capstone | Secure AI operations assistant and architecture defense |

## Repository modules
1. `01-foundations/01-ai-system-foundations.md`
2. `02-llm-security/02-llm-security-deep-dive.md`
3. `03-rag-security/03-rag-security-deep-dive.md`
4. `04-mcp-security/04-mcp-security-deep-dive.md`
5. `05-agent-security/05-agent-security-deep-dive.md`
6. `06-ai-devsecops/06-ai-devsecops-deep-dive.md`
7. `07-cloud-security/07-multi-cloud-ai-security-deep-dive.md`
8. `08-governance-compliance/08-ai-governance-compliance-deep-dive.md`
9. `09-capstone/09-enterprise-capstone.md`

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
