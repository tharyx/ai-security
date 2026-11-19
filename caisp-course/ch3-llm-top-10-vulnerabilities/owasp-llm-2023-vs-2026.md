# OWASP LLM Top 10: 2023 (v1.1) vs 2025 vs 2026

The course teaches the **2023 v1.1** names. The exam and your job may use newer lists. This page lets you move between them without panic.

> Verify the current list at https://genai.owasp.org/ before an exam or a report. OWASP revises it, and numbers move.

## 1. Three-way mapping

| 2023 v1.1 (course) | 2025 | 2026 | Repo lesson (where it lives now) |
|---|---|---|---|
| LLM01 Prompt Injection | LLM01 Prompt Injection | 01 Prompt Injection | [02 prompt-injection](../../02-llm-security/prompt-injection/README.md) |
| LLM02 Insecure Output Handling | LLM05 Improper Output Handling | 10 Improper Output Handling | [02 data-leakage](../../02-llm-security/data-leakage/README.md) (section 2.5) |
| LLM03 Training Data Poisoning | LLM04 Data and Model Poisoning | 05 Data and Model Poisoning | [02 model-threats](../../02-llm-security/model-threats/README.md) |
| LLM04 Model Denial of Service | LLM10 Unbounded Consumption | 06 Unbounded Consumption | [02 security-testing](../../02-llm-security/security-testing/README.md) (`limits.py`) plus [the new context lab](labs/model-dos-context-exhaustion/README.md) |
| LLM05 Supply Chain Vulnerabilities | LLM03 Supply Chain | 04 Supply Chain | [02 model-threats](../../02-llm-security/model-threats/README.md), [06 docker](../../06-ai-devsecops/docker/README.md), [06 cicd](../../06-ai-devsecops/cicd/README.md) |
| LLM06 Sensitive Information Disclosure | LLM02 Sensitive Information Disclosure | 02 Sensitive Information Disclosure | [02 data-leakage](../../02-llm-security/data-leakage/README.md) |
| LLM07 Insecure Plugin Design | (folded in) Excessive Agency and Improper Output Handling | (folded in) 03 Excessive Agency and 10 Improper Output Handling | [04 MCP tool-security](../../04-mcp-security/tool-security/README.md) |
| LLM08 Excessive Agency | LLM06 Excessive Agency | 03 Excessive Agency | [05 permissions](../../05-agent-security/permissions/README.md) |
| LLM09 Overreliance | LLM09 Misinformation | 07 Misinformation | [02 model-threats](../../02-llm-security/model-threats/README.md) (section 2.5) |
| LLM10 Model Theft | (no separate entry; extraction appears under Unbounded Consumption) | (no separate entry; covered by Unbounded Consumption and Sensitive Information Disclosure) | [02 model-threats](../../02-llm-security/model-threats/README.md) (section 2.3) |
| (not in 2023) | LLM07 System Prompt Leakage | 08 Hidden Context Exposure | [02 data-leakage](../../02-llm-security/data-leakage/README.md) (section 2.3) |
| (not in 2023) | LLM08 Vector and Embedding Weaknesses | 09 Vector and Embedding Weaknesses | [03 rag-security](../../03-rag-security/README.md) |

How to read the table:

- **Renamed, same idea:** Prompt Injection, Sensitive Information Disclosure, Supply Chain, Excessive Agency.
- **Renamed, wider idea:** Insecure Output Handling became Improper Output Handling (it now also covers unsafe AI-generated code in places). Training Data Poisoning became Data and Model Poisoning (the model file and weights can be poisoned too). Model DoS became Unbounded Consumption (cost, "denial of wallet" and extraction through heavy API use, not only a crash).
- **Merged away:** Insecure Plugin Design (plugins faded from the market and tools or MCP servers replaced them; the weaknesses show up as Excessive Agency and Improper Output Handling). Model Theft (it stopped being its own entry; extraction is treated as part of resource abuse).
- **Replaced by a new idea:** Overreliance became Misinformation. The 2023 entry was about people trusting model output too much. The newer entry describes the model producing false or misleading content as a risk in itself.
- **New after 2023:** System Prompt Leakage (called Hidden Context Exposure in 2026) and Vector and Embedding Weaknesses, driven by RAG and agents.

## 2. What changed, and why

| Change | Reason (short) |
|---|---|
| Names became more general | Real incidents did not fit narrow names. "Unbounded Consumption" covers cost attacks, not just outages |
| Plugins dropped | The first plugin ecosystems (2023) were replaced by tool calling, agents and MCP. The security problem moved, it did not disappear |
| RAG and embeddings added | Retrieval-augmented systems became the common enterprise pattern, with their own failure modes |
| System prompt leakage added | Teams kept putting secrets and rules in system prompts. The lesson: a system prompt is not a secret |
| Agency moved up | Agents that act (not only talk) raise the impact of every other bug. Excessive Agency rose to third place in 2026 |
| Overreliance became Misinformation | The problem is both human trust and model fabrication; the list names the harm that results |

## 3. How to answer exam questions that use the 2023 names

1. **Answer in the question's framing.** If it says "LLM07 Insecure Plugin Design", describe plugin weaknesses: free-text inputs without validation, weak authorization, chained plugins, broad permissions.
2. **Add the modern link in one sentence.** For example: "Today this is covered under Excessive Agency and tool or MCP security."
3. **Do not mix numbers.** LLM02 in 2023 is Insecure Output Handling, but LLM02 in 2025 is Sensitive Information Disclosure. Always say the year when you give a number.
4. **If a question gives a number without a year, look at the name.** The name tells you the version.
5. **For "which control" questions the controls are the same across versions.** Validate input and output, least privilege, human approval for risky actions, rate and cost limits, trusted sources, monitoring.

Quick translation table for speaking: Insecure Output Handling = Improper Output Handling. Training Data Poisoning = Data and Model Poisoning. Model DoS = Unbounded Consumption. Overreliance = Misinformation (plus the human side). Insecure Plugin Design = tool and MCP security. Model Theft = model extraction.

## 4. Where each risk lives in this repo

| Risk (course name) | Course lesson in this chapter | Existing deep lesson | Lab |
|---|---|---|---|
| Prompt Injection | [01](01-prompt-injection.md) | [prompt-injection](../../02-llm-security/prompt-injection/README.md), [jailbreak](../../02-llm-security/jailbreak/README.md) | [prompt-injection-levels](labs/prompt-injection-levels/README.md), [system-vs-user-prompts](labs/system-vs-user-prompts/README.md) |
| Insecure Output Handling | [02](02-insecure-output-handling.md) | [data-leakage](../../02-llm-security/data-leakage/README.md) | [data-leakage lab](../../02-llm-security/data-leakage/lab/), [guard-io (chapter 4)](../ch4-ai-attacks-and-defenses-devops/labs/guard-io/README.md) |
| Training Data Poisoning | [03](03-training-data-poisoning.md) | [model-threats](../../02-llm-security/model-threats/README.md) | [model-threats lab](../../02-llm-security/model-threats/lab/) |
| Model Denial of Service | [04](04-model-denial-of-service.md) | [security-testing](../../02-llm-security/security-testing/README.md) | [model-dos-context-exhaustion](labs/model-dos-context-exhaustion/README.md) |
| Supply Chain Vulnerabilities | [05](05-supply-chain-vulnerabilities.md) | [model-threats](../../02-llm-security/model-threats/README.md), [docker](../../06-ai-devsecops/docker/README.md) | [model-threats lab](../../02-llm-security/model-threats/lab/), [pickle_scan](../../06-ai-devsecops/docker/lab/pickle_scan.py) |
| Sensitive Information Disclosure | [06](06-sensitive-information-disclosure.md) | [data-leakage](../../02-llm-security/data-leakage/README.md) | [sensitive-info-extraction](labs/sensitive-info-extraction/README.md) |
| Insecure Plugin Design | [07](07-insecure-plugin-design.md) | [MCP tool-security](../../04-mcp-security/tool-security/README.md) | [tool-security lab](../../04-mcp-security/tool-security/lab/) |
| Excessive Agency | [08](08-excessive-agency.md) | [agent permissions](../../05-agent-security/permissions/README.md) | [permissions lab](../../05-agent-security/permissions/lab/) |
| Overreliance | [09](09-overreliance.md) | [model-threats](../../02-llm-security/model-threats/README.md) | [hallucination-lab](labs/hallucination-lab/README.md) |
| Model Theft | [10](10-model-theft.md) | [model-threats](../../02-llm-security/model-threats/README.md) | [model-threats lab](../../02-llm-security/model-threats/lab/) (extraction) |
