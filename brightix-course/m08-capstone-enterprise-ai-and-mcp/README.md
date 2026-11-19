# Module 08: Capstone: End-to-End Enterprise AI & MCP Security (days 41–45)

Put it all together on one multi-agent RAG + MCP enterprise assistant: threat model it, attack it end to end, harden it, wire up detections and playbooks, then present readiness to leadership.

> **How this module works.** Most topics are already taught in depth elsewhere in this repo, so the table links to those lessons and labs instead of repeating them. Rows marked **Gap filled here** had little or no hands-on material before; the **NEW** labs in this module fill them.

> **Safety.** Every attack lab targets the repo's own toy code and mock models. Only test systems you own or have written permission to test.

## Syllabus coverage

| Syllabus item | Where to study | Lab | Status |
|---|---|---|---|
| [BX 8] Threat Modeling a Multi-Agent RAG & MCP Enterprise Application | [Capstone brief](../../10-capstone-project/01-capstone-brief-and-requirements.md); [MCP threat modeling exercises](../../cmcpse-course/ch3-threat-modeling-mcp-architectures/06-hands-on-exercises.md); [Agentic threat modeling](../../caase-course/ch7-threat-modeling-agents-and-communication-protocols/01-threat-modeling-fundamentals-for-agentic-ai.md) | **NEW** [enterprise-ai-mcp-capstone (threat model as code)](labs/enterprise-ai-mcp-capstone); [stride-mcp-architecture](../../cmcpse-course/ch3-threat-modeling-mcp-architectures/labs/stride-mcp-architecture) | Gap filled here |
| [BX 8] Executing Full-Scope Red Team Attacks (RAG poisoning & MCP tool abuse) | [Capstone red team](../../10-capstone-project/03-red-team-and-incident-exercise.md); [MCP attack primitives](../../cmcpse-course/ch2-understanding-and-attacking-mcp-servers/03-mcp-attack-primitives.md) | **NEW** [enterprise-ai-mcp-capstone (red-team suite)](labs/enterprise-ai-mcp-capstone); [capstone attacks](../../10-capstone-project/lab) | Gap filled here |
| [BX 8] Deploying Input/Output Guardrails & Hardening MCP Server Permissions | [Capstone brief (layers)](../../10-capstone-project/01-capstone-brief-and-requirements.md); [MCP security gateway mini-project](../../04-mcp-security/README.md) | **NEW** [enterprise-ai-mcp-capstone (hardening toggles)](labs/enterprise-ai-mcp-capstone); [least-privilege-tools](../../cmcpse-course/ch4-defending-and-hardening-mcp-servers/labs/least-privilege-tools) | Covered |
| [BX 8] Configuring AI Telemetry, SOC Detection Rules & Incident Playbooks | [Detection engineering and playbooks](../../10-capstone-project/03-red-team-and-incident-exercise.md); [AI SOC monitoring extension](../../10-capstone-project/05-ai-soc-monitoring-extension.md) | **NEW** [enterprise-ai-mcp-capstone (detections)](labs/enterprise-ai-mcp-capstone); **NEW** [ai-soar-playbooks](../m06-ai-security-monitoring-and-soc/labs/ai-soar-playbooks) | Covered |
| [BX 8] Final Architecture Review & Executive Security Readiness Presentation | [Architecture defense](../../10-capstone-project/04-architecture-defense-and-interview.md); **NEW** [executive readiness deck template](executive-readiness-deck-template.md) | **NEW** [enterprise-ai-mcp-capstone (review checklist)](labs/enterprise-ai-mcp-capstone); [architecture reviewer](../../09-enterprise-architecture/lab) | Gap filled here |

## Day-by-day plan

- Day 41: read the capstone brief; build the threat model as code for the multi-agent RAG + MCP assistant.
- Day 42: run the full red-team suite against the baseline; record the scorecard.
- Day 43: switch on guardrails and MCP hardening; re-run until every attack is contained.
- Day 44: telemetry, detection rules and the incident playbook; run a drill.
- Day 45: architecture review and the executive readiness presentation.

## Interview / exam questions

<details><summary><b>How do you show leadership that the AI assistant is 'ready'?</b></summary>

Business-language top risks, the controls in place with evidence (attack success before vs after), residual risks needing formal acceptance, operational metrics (detections, MTTR), and a dated roadmap.

</details>

<details><summary><b>Why test 'soft layers off, hard controls still hold'?</b></summary>

It proves the system doesn't rely on probabilistic guardrails alone: with rails disabled, authorization, tool allowlists, approvals and egress limits must still stop the impact.

</details>

<details><summary><b>Which capstone attack is most likely in real enterprises, and why?</b></summary>

Indirect prompt injection through shared content (documents, email, tickets) reaching an agent that has tools, because content is everywhere and tool access turns text into action.

</details>

---

Previous: [Module 07](../m07-mcp-security-fundamentals/README.md) · [Course home](../README.md)
