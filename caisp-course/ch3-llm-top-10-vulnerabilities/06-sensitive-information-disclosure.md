# 06. Sensitive Information Disclosure (LLM06 in 2023)

> **Maps to:** 2023 LLM06 Sensitive Information Disclosure | 2025 LLM02 | 2026 02 Sensitive Information Disclosure.
> **Time:** 1 hour. **Deep lesson in this repo:** [02-llm-security/data-leakage](../../02-llm-security/data-leakage/README.md). This page keeps the course sub-topics and the two incidents the course uses.

## Why this matters

LLM applications sit next to valuable data: customer records, source code, contracts, prompts with secrets. Data can leave in many ways: a user pastes it into a public chatbot, the model repeats it in an answer, a bug mixes users' sessions, or an attacker tricks the model into sending it out.

## Exploring data leaks in various incidents

Only incidents that are well documented:

| Incident | What happened | Lesson |
|---|---|---|
| **Samsung, 2023** | After the company allowed employees to use ChatGPT, news reports said staff pasted internal source code and meeting notes into it. Samsung then restricted use of such tools. | The leak was a **human and policy** problem: data left the company because a user pasted it into an external service. Fix with policy, approved tools, DLP and training, not only technical filters. |
| **ChatGPT, March 2023** | A bug in an open-source Redis client library used by the service let some users see titles from other users' chat history. OpenAI also reported that payment-related details of a small share of ChatGPT Plus subscribers could have been exposed during a limited window. The service was taken offline briefly and fixed. | A **classic software bug** in a dependency caused cross-user disclosure. Isolation between users and a careful supply chain matter as much as model behavior. |

Do not confuse these with model "memorization" research (extracting training examples from a model). That is a third, separate path.

Leak paths to remember:

| Path | Example |
|---|---|
| User to provider | Pasting secrets into a public chatbot |
| Context to output | System prompt, retrieved documents or memory shown to the wrong user |
| Cross-user | Shared cache, shared memory, session mixup (the Redis bug is of this type) |
| Output to outside | Markdown image or link carrying data to an attacker's server |
| Training data to output | A model repeating memorized text |
| Logs and telemetry | Prompts and answers stored without controls |
| Tools | A tool returning more data than the user may see |

## Mitigating sensitive information disclosure

| Control | Detail | Type |
|---|---|---|
| Data minimization | Do not put secrets or other users' data in the prompt at all | Hard |
| Authorization before retrieval | Fetch only what this user may see; the user ID comes from the session, not from text | Hard |
| Tenant isolation | Separate caches, memory, indexes and keys per user or tenant | Hard |
| Output controls | Strip links and images, scan for PII and secrets, redact | Hard/Soft |
| Sanitize training and fine-tuning data | Remove personal data and secrets before training | Process |
| Approved tools and DLP | Provide a sanctioned AI tool; block or monitor pasting to unapproved ones | Process |
| Contracts and settings | Check provider data retention and training-use terms | Process |
| Logging with care | Redact prompts in logs; limit retention and access | Hard |
| Canary tokens | Plant fake secrets to prove a leak | Detection |

## Hands-on

- New step-by-step exercise: [sensitive-info-extraction](labs/sensitive-info-extraction/README.md) (six extraction techniques, then the fixes).
- Existing lab with exfiltration and cross-user memory: [data-leakage](../../02-llm-security/data-leakage/lab/).
- Input and output scanners: chapter 4 [llm-guard-sanitize](../ch4-ai-attacks-and-defenses-devops/labs/llm-guard-sanitize/README.md) and [guard-io](../ch4-ai-attacks-and-defenses-devops/labs/guard-io/README.md).

## Interview Q&A

<details><summary><b>Q1. What was the root cause of the March 2023 ChatGPT incident?</b></summary>
A bug in an open-source Redis client library caused some users to see other users' chat titles, and a small number of subscribers' payment details may have been visible. It was a software bug in a dependency, not model memorization or a prompt attack. The lesson is isolation between users and supply chain care.
</details>

<details><summary><b>Q2. The Samsung case was not a hack. What control would have helped?</b></summary>
A clear policy, an approved internal AI tool with suitable data terms, data loss prevention for pasted source code, and training. The data left because users sent it to an external service.
</details>

<details><summary><b>Q3. How do you stop a RAG chatbot from leaking another user's document?</b></summary>
Enforce the user's permissions in the retrieval step (filter by authorization before the model sees anything), keep per-tenant indexes or filters, and keep identity out of the prompt text. Do not rely on telling the model "only answer for this user".
</details>

## References

- OpenAI, "March 20 ChatGPT outage: Here's what happened" (March 2023)
- News coverage of the Samsung employee incident (April 2023); verify details at the sources
- OWASP LLM Top 10 (sensitive information disclosure): https://genai.owasp.org/
- Repo: [data-leakage](../../02-llm-security/data-leakage/README.md)
