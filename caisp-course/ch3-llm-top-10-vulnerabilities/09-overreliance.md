# 09. Overreliance (LLM09 in 2023)

> **Maps to:** 2023 LLM09 Overreliance | 2025 LLM09 Misinformation | 2026 07 Misinformation.
> **Time:** 1.5 hours. **Existing coverage:** [02-llm-security/model-threats](../../02-llm-security/model-threats/README.md), section 2.5 (misinformation and overreliance) and the AI-generated code gate. This page adds the course material: what hallucination is, examples, and a lab with a detector.

## Why this matters

LLMs write fluent, confident text whether or not it is true. People (and downstream systems) trust fluent text. If nobody checks it, wrong output becomes a wrong decision, a legal problem or a vulnerability in production code. Overreliance is a **people-and-process** risk as much as a model risk.

## Understanding hallucinations

A **hallucination** is output that sounds plausible but is false, made up or unsupported. Why it happens, in simple words:

- The model predicts likely next words. It has no built-in fact checker or sense of "I do not know".
- It was trained to be helpful and fluent, so it fills gaps instead of refusing.
- Rare, recent or niche facts are weakly represented in training data.
- Long prompts, unclear questions or leading questions raise the error rate.
- Retrieved context helps (RAG) but does not remove the problem: the model can still ignore, mix or extend the context.

Types:

| Type | Example |
|---|---|
| Fabricated facts | Invented statistics or dates |
| Fabricated sources | Citations, case law, DOIs that do not exist |
| Fabricated entities | Package names, API functions, people, products |
| Wrong reasoning | Correct pieces, wrong conclusion |
| Unfaithful summary | Adds or drops points compared with the source |
| Insecure code | Plausible code with SQL injection, hardcoded keys, old crypto |

## Overreliance examples

Only documented cases:

| Case | What happened | Lesson |
|---|---|---|
| **Mata v. Avianca (US, 2023)** | Lawyers filed a brief containing court cases that ChatGPT had invented. The court sanctioned the lawyers. | Verify every citation against a trusted source. The professional is responsible. |
| **Air Canada chatbot (Canada, 2024)** | A tribunal held the airline responsible for wrong refund-policy information that its website chatbot gave a customer. | You own what your chatbot says. Ground answers in policy and test them. |
| **Invented package names** | Security researchers have shown that LLMs suggest packages that do not exist, and that an attacker could register such a name and wait ("slopsquatting"). | Check suggested dependencies against an approved index. See the lab. |
| **AI-generated code** | Studies have found that code suggestions can contain security flaws; developers can accept them too fast. | Treat AI code like code from an unknown contributor: tests, SAST, review. |

## Mitigating overreliance

| Control | Detail | Type |
|---|---|---|
| Ground answers | RAG with trusted sources; answer only from retrieved text; show the sources | Soft/Hard |
| Verify automatically | Check citations, package names, numbers, links against trusted data (see the lab) | Hard |
| Human review | Required for legal, medical, financial and security decisions | Hard (process) |
| Calibrate trust in the UI | Show confidence limits and "AI-generated" labels; make "I do not know" acceptable | Soft |
| Constrain output | Structured answers, allowed values, refuse out-of-scope questions | Hard |
| Test and monitor | Evaluation sets with known answers; track error and complaint rates | Process |
| Secure code gates | SAST, dependency checks, tests and code owner review for AI-written code | Hard |
| Training and policy | Teach people what the tool can and cannot do; assign accountability | Process |

## Hands-on

[labs/hallucination-lab](labs/hallucination-lab/README.md): detect fabricated citations, invented packages and ungrounded numbers, then wrap a model so checks decide. Also see the chapter 4 [ai-code-weaknesses](../ch4-ai-attacks-and-defenses-devops/labs/ai-code-weaknesses/README.md) lab for scanning AI-written code.

## Interview Q&A

<details><summary><b>Q1. What is a hallucination and can it be eliminated?</b></summary>
It is fluent output that is false or unsupported. It can be reduced (grounding, retrieval, constrained output, better models, evaluation) but not fully eliminated, so design for verification: checks in code and humans on high-impact decisions.
</details>

<details><summary><b>Q2. What is "slopsquatting" and how do you defend against it?</b></summary>
An attacker registers a package name that a model tends to invent. A developer who trusts the suggestion installs it. Defend with an approved package index or mirror, lock files with hashes, and automatic checks that flag unknown names.
</details>

<details><summary><b>Q3. How does overreliance differ from the 2025/2026 "Misinformation" entry?</b></summary>
Overreliance (2023) stressed human trust in model output. Misinformation (2025 and 2026) names the model producing false or misleading content as the risk, including its effects on people and systems. In practice you defend both: reduce false output and verify before acting.
</details>

## References

- OWASP LLM Top 10 (overreliance 2023; misinformation 2025/2026): https://genai.owasp.org/
- Court record: Mata v. Avianca, Inc. (S.D.N.Y., 2023); Moffatt v. Air Canada (BC Civil Resolution Tribunal, 2024)
- Repo: [model-threats](../../02-llm-security/model-threats/README.md), [03-rag-security](../../03-rag-security/README.md)
