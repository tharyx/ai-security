# Module 03: LLM Security Vulnerabilities (OWASP Top 10) (days 10–15)

The OWASP Top 10 for LLM applications in practice: prompt injection, disclosure, jailbreaks and prompt leakage, output handling, excessive agency, and privacy attacks such as model inversion and membership inference.

> **How this module works.** Most topics are already taught in depth elsewhere in this repo, so the table links to those lessons and labs instead of repeating them. Rows marked **Gap filled here** had little or no hands-on material before; the **NEW** labs in this module fill them.

> **Safety.** Every attack lab targets the repo's own toy code and mock models. Only test systems you own or have written permission to test.

## Syllabus coverage

| Syllabus item | Where to study | Lab | Status |
|---|---|---|---|
| [BX 3] Prompt Injection (Direct & Indirect across untrusted data sources) | [Prompt injection module](../../02-llm-security/prompt-injection/README.md); [CAISP prompt injection](../../caisp-course/ch3-llm-top-10-vulnerabilities/01-prompt-injection.md); [Taxonomy for agents](../../caase-course/ch2-agent-reasoning-goals-and-prompt-boundaries/02-prompt-injection-taxonomy-for-agents.md) | [prompt-injection lab](../../02-llm-security/prompt-injection/lab); [prompt-injection-levels](../../caisp-course/ch3-llm-top-10-vulnerabilities/labs/prompt-injection-levels) | Covered |
| [BX 3] Sensitive Information Disclosure & training/context extraction | [Data leakage](../../02-llm-security/data-leakage/README.md); [CAISP disclosure](../../caisp-course/ch3-llm-top-10-vulnerabilities/06-sensitive-information-disclosure.md) | [data-leakage lab](../../02-llm-security/data-leakage/lab); [sensitive-info-extraction](../../caisp-course/ch3-llm-top-10-vulnerabilities/labs/sensitive-info-extraction) | Covered |
| [BX 3] Jailbreaks, Guardrail Bypasses & System Prompt Leakage | [Jailbreak module](../../02-llm-security/jailbreak/README.md); [Attacking the reasoning loop](../../caase-course/ch2-agent-reasoning-goals-and-prompt-boundaries/03-attacking-the-reasoning-loop.md) | [jailbreak lab](../../02-llm-security/jailbreak/lab); [03-prompt-leaking](../../caase-course/ch2-agent-reasoning-goals-and-prompt-boundaries/labs/03-prompt-leaking) | Covered |
| [BX 3] Insecure Output Handling (XSS, SSRF, SQLi via model output) | [CAISP output handling](../../caisp-course/ch3-llm-top-10-vulnerabilities/02-insecure-output-handling.md); [Tool security (SSRF)](../../04-mcp-security/tool-security/README.md) | [data-leakage lab (XSS, markdown image)](../../02-llm-security/data-leakage/lab); [tool-security lab](../../04-mcp-security/tool-security/lab) | Covered |
| [BX 3] Excessive Agency, Tool Abuse & autonomous action hijacking | [Agent permissions](../../05-agent-security/permissions/README.md); [CAISP excessive agency](../../caisp-course/ch3-llm-top-10-vulnerabilities/08-excessive-agency.md); [Attacking tool calling](../../caase-course/ch3-agent-memory-context-and-tool-use/03-attacking-tool-and-function-calling-interfaces.md) | [permissions lab](../../05-agent-security/permissions/lab); [04-tool-chain-escalation](../../caase-course/ch3-agent-memory-context-and-tool-use/labs/04-tool-chain-escalation) | Covered |
| [BX 3] Data Leakage, Model Inversion & Privacy Risks | [Model threats](../../02-llm-security/model-threats/README.md); [Privacy, GDPR and DPDP](../../08-ai-compliance/02-privacy-gdpr-and-india-dpdp.md) | **NEW** [model-inversion-membership-inference](labs/model-inversion-membership-inference); [vector-db lab (embedding inversion)](../../03-rag-security/vector-db-security/lab) | Gap filled here |

## Day-by-day plan

- Day 10: OWASP LLM Top 10 overview and the 2023→2026 name mapping.
- Day 11: direct and indirect prompt injection; both injection labs.
- Day 12: sensitive information disclosure and context extraction.
- Day 13: jailbreaks, guardrail bypass, system prompt leakage.
- Day 14: improper output handling (XSS/SSRF/SQLi) and excessive agency.
- Day 15: privacy attacks; NEW model inversion and membership inference lab.

## Interview / exam questions

<details><summary><b>Why is output handling an LLM risk and not just a web risk?</b></summary>

The model's output is attacker-influenced (via injection), so rendering it as HTML, passing it to SQL or fetching URLs from it turns prompt injection into XSS, SQLi or SSRF. Treat model output as untrusted input.

</details>

<details><summary><b>What is membership inference and why does an overfit model make it easier?</b></summary>

Deciding whether a record was in the training set. Overfit models are much more confident on training records than on unseen ones, so a confidence threshold separates them.

</details>

<details><summary><b>Three defenses against model inversion/membership inference?</b></summary>

Return labels only or rounded confidences, reduce overfitting (regularisation, more data, differential privacy), and monitor/limit query volume per client.

</details>

---

Previous: [Module 02](../m02-llm-application-and-rag-security/README.md) · [Course home](../README.md) · Next: [Module 04](../m04-ai-red-teaming-and-automated-testing/README.md)
