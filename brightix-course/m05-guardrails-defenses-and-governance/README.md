# Module 05: AI Guardrails, Defensive Controls & Governance (days 23–29)

Layered runtime defenses: input/output rails, injection classifiers and semantic firewalls, PII/DLP, AI gateways with quotas, least-privilege tools with human approval, and the governance frameworks that tie it together.

> **How this module works.** Most topics are already taught in depth elsewhere in this repo, so the table links to those lessons and labs instead of repeating them. Rows marked **Gap filled here** had little or no hands-on material before; the **NEW** labs in this module fill them.

> **Safety.** Every attack lab targets the repo's own toy code and mock models. Only test systems you own or have written permission to test.

## Syllabus coverage

| Syllabus item | Where to study | Lab | Status |
|---|---|---|---|
| [BX 5] Input/Output Guardrails Architecture (NeMo Guardrails, Llama Guard) | [Defending goals and reasoning](../../caase-course/ch2-agent-reasoning-goals-and-prompt-boundaries/04-defending-goals-and-reasoning.md); [AI firewalls at the gateway](../../cmcpse-course/ch5-devsecops-for-mcp-security/07-ai-firewalls-at-the-gateway.md); **NEW** [NeMo Guardrails and Llama Guard guide](real-tools/nemo-guardrails-and-llama-guard.md) | **NEW** [rails-and-safety-classifier](labs/rails-and-safety-classifier); [05-guardrail-model](../../caase-course/ch2-agent-reasoning-goals-and-prompt-boundaries/labs/05-guardrail-model); [guard-io](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/guard-io) | Gap filled here |
| [BX 5] Prompt Injection Classifiers & Semantic Firewall Filtering | [AI firewalls at the gateway](../../cmcpse-course/ch5-devsecops-for-mcp-security/07-ai-firewalls-at-the-gateway.md); [Prompt injection defenses](../../02-llm-security/prompt-injection/README.md) | **NEW** [rails-and-safety-classifier (semantic firewall)](labs/rails-and-safety-classifier); [mcp-ai-firewall](../../cmcpse-course/ch4-defending-and-hardening-mcp-servers/labs/mcp-ai-firewall) | Covered |
| [BX 5] PII Detection, Redaction & Data Loss Prevention (DLP) for LLMs | [Response security (DLP)](../../03-rag-security/response-security/README.md); [Secure LLM/AI gateway](../../09-enterprise-architecture/06-secure-llm-ai-gateway.md) | [response-security lab](../../03-rag-security/response-security/lab); [llm-guard-sanitize](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/llm-guard-sanitize) | Covered |
| [BX 5] AI Gateways, Rate Limiting, Token Quotas & Cost-DoS Defense | [Secure LLM/AI gateway](../../09-enterprise-architecture/06-secure-llm-ai-gateway.md); [Runtime security](../../06-ai-devsecops/runtime-security/README.md) | [gateway lab](../../09-enterprise-architecture/lab); [model-dos-context-exhaustion](../../caisp-course/ch3-llm-top-10-vulnerabilities/labs/model-dos-context-exhaustion) | Covered |
| [BX 5] Least-Privilege Tool Execution & Human-in-the-Loop Approvals | [Agent permissions](../../05-agent-security/permissions/README.md); [Defending computer-use and coding agents](../../caase-course/ch4-computer-use-browser-and-coding-agents/05-defending-computer-use-and-coding-agents.md) | [permissions lab](../../05-agent-security/permissions/lab); [hitl-approval-gate](../../caase-course/ch5-multi-agent-systems-and-agent-identity/labs/hitl-approval-gate) | Covered |
| [BX 5] AI Governance & Compliance (NIST AI RMF, EU AI Act, ISO/IEC 42001) | [AI risk management](../../07-ai-governance/03-ai-risk-management.md); [ISO/IEC 42001](../../07-ai-governance/04-iso-42001-ai-management-system.md); [EU AI Act](../../08-ai-compliance/01-eu-ai-act.md) | [governance lab](../../07-ai-governance/lab); [compliance lab](../../08-ai-compliance/lab) | Covered |

## Day-by-day plan

- Day 23: guardrail architecture: where rails sit, fail-open vs fail-closed.
- Day 24: NEW rails and safety-classifier lab (NeMo-style rails, Llama-Guard-style classifier).
- Day 25: injection classifiers and the semantic firewall; mcp-ai-firewall lab.
- Day 26: PII detection, redaction and DLP; response-security lab.
- Day 27: AI gateways, quotas and cost-DoS; gateway lab.
- Day 28: least privilege and human-in-the-loop approvals.
- Day 29: NIST AI RMF, EU AI Act, ISO/IEC 42001.

## Interview / exam questions

<details><summary><b>Why are guardrails called 'soft' controls?</b></summary>

They are probabilistic classifiers that can be bypassed (encodings, paraphrase, multi-turn). Pair them with hard controls (authorization, tool allowlists, egress limits, approvals) that hold even when a rail misses.

</details>

<details><summary><b>What does a Llama-Guard-style classifier return, and where do you run it?</b></summary>

A verdict (safe/unsafe) and violated category codes. Run it on the user prompt (input rail) and on the model response (output rail).

</details>

<details><summary><b>Name four cost-DoS defenses.</b></summary>

Per-user token and request quotas, max input/output tokens, timeouts and loop limits for agents, and budget alerts at the gateway.

</details>

---

Previous: [Module 04](../m04-ai-red-teaming-and-automated-testing/README.md) · [Course home](../README.md) · Next: [Module 06](../m06-ai-security-monitoring-and-soc/README.md)
