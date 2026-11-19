# Module 01: LLM Security Fundamentals (days 1–4)

How LLMs work, what tokens, prompts and context windows are, how system and user prompts differ, the API parameters you will meet, and where the trust boundaries sit in an LLM application.

> **How this module works.** Most topics are already taught in depth elsewhere in this repo, so the table links to those lessons and labs instead of repeating them. Rows marked **Gap filled here** had little or no hands-on material before; the **NEW** labs in this module fill them.

> **Safety.** Every attack lab targets the repo's own toy code and mock models. Only test systems you own or have written permission to test.

## Syllabus coverage

| Syllabus item | Where to study | Lab | Status |
|---|---|---|---|
| [BX 1] How LLMs work & Transformer inference basics | [Inside the LLM](../../01-ai-security-fundamentals/01b-inside-the-llm-transformers-inference-and-training.md); [CAISP ch2 lesson 01](../../caisp-course/ch2-understanding-and-attacking-llms/01-llm-intro-gpt-bert-training-and-use-cases.md) | [tiny_llm lab](../../01-ai-security-fundamentals/lab) | Covered |
| [BX 1] Tokens, Prompts & Context Window mechanics | [AI/ML/LLM basics](../../01-ai-security-fundamentals/01-ai-ml-llm-basics-for-security.md); [Inside the LLM](../../01-ai-security-fundamentals/01b-inside-the-llm-transformers-inference-and-training.md); [Context windows](../../caisp-course/ch3-llm-top-10-vulnerabilities/04-model-denial-of-service.md) | [tokenizers](../../caisp-course/ch2-understanding-and-attacking-llms/labs/02-tokenizers); [fundamentals lab](../../01-ai-security-fundamentals/lab) | Covered |
| [BX 1] System Prompts vs. User Prompts & instruction hierarchy | [Prompt injection lesson](../../caisp-course/ch3-llm-top-10-vulnerabilities/01-prompt-injection.md); [Input and output boundaries](../../caase-course/ch2-agent-reasoning-goals-and-prompt-boundaries/01-input-and-output-boundaries.md) | [system-vs-user-prompts](../../caisp-course/ch3-llm-top-10-vulnerabilities/labs/system-vs-user-prompts) | Covered |
| [BX 1] LLM APIs & Model Parameters (temperature, top-p, max tokens) | [Inside the LLM (sampling)](../../01-ai-security-fundamentals/01b-inside-the-llm-transformers-inference-and-training.md); [Agent vs LLM call](../../caase-course/ch1-agents-harnesses-and-the-agentic-ecosystem/01-agent-vs-llm-call.md) | [fundamentals lab (top_p)](../../01-ai-security-fundamentals/lab); [tool-calling-determinism](../../caase-course/ch1-agents-harnesses-and-the-agentic-ecosystem/labs/tool-calling-determinism) | Covered |
| [BX 1] LLM Application Components & trust boundaries | [Architecture and trust boundaries](../../01-ai-security-fundamentals/02-ai-system-architecture-and-trust-boundaries.md) | [threat_model lab](../../01-ai-security-fundamentals/lab) | Covered |
| [BX 1] Security Challenges in Enterprise LLM Applications | [Attack surface and requirements](../../01-ai-security-fundamentals/04-ai-attack-surface-and-security-requirements.md); [Enterprise reference architecture](../../09-enterprise-architecture/01-enterprise-ai-reference-architecture.md) | [architecture reviewer](../../09-enterprise-architecture/lab) | Covered |

## Day-by-day plan

- Day 1: how LLMs work, transformer inference; run the tiny_llm lab.
- Day 2: tokens, context windows, sampling parameters (temperature, top-p, max tokens); tokenizers lab.
- Day 3: system vs user prompts and the instruction hierarchy; system-vs-user-prompts lab.
- Day 4: components, trust boundaries and enterprise challenges; draw the trust boundaries of an app you know.

## Interview / exam questions

<details><summary><b>Why can't a system prompt be treated as a security boundary?</b></summary>

The model sees system and user text as one token stream; the instruction hierarchy is learned behaviour, not enforcement. Anything that must hold (authorization, data access, tool limits) belongs in code outside the model.

</details>

<details><summary><b>What does temperature change, and does setting it to 0 make an app safe?</b></summary>

It changes how sharply the model picks likely tokens. Temperature 0 makes output more repeatable, not safer: injection and leakage still work, they just work every time.

</details>

<details><summary><b>Name the trust boundaries in a typical RAG chatbot.</b></summary>

User → app, app → model provider, app → retriever/vector DB, documents → index (ingestion), model output → downstream renderers and tools.

</details>

---

[Course home](../README.md) · Next: [Module 02](../m02-llm-application-and-rag-security/README.md)
