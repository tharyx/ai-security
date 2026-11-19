# 01. Prompt Injection (LLM01 in 2023)

> **Maps to:** 2023 LLM01 Prompt Injection | 2025 LLM01 | 2026 01 Prompt Injection.
> **Time:** 1.5 hours + lab. **Deep lesson in this repo:** [02-llm-security/prompt-injection](../../02-llm-security/prompt-injection/README.md). This page adds the course sub-topics and keeps the rest short.

## Why this matters

- In 2022, Simon Willison named "prompt injection" by analogy to SQL injection.
- In February 2023, a researcher got the Bing Chat assistant to reveal its hidden instructions with a simple "ignore previous instructions" style request.
- In 2023, Greshake and colleagues showed *indirect* prompt injection: instructions hidden in web pages or emails that an LLM-integrated app reads and then obeys.
- OWASP ranks it first in all three editions of the list.

## System prompts versus user prompts

| | System prompt | User prompt |
|---|---|---|
| Written by | the developer | the person using the app (or an attacker) |
| Purpose | role, rules, format, tool descriptions | the task or question |
| Trust | meant to be higher, but it is still just text the model reads | untrusted |
| Where it sits | first message, role `system` | later messages, role `user` |

Two facts to remember. First, a model trained with an "instruction hierarchy" *tends* to put the system prompt above user text, but this is a learned habit, not a lock. Second, **a system prompt is not a secret**. Users can often make the model repeat it. Put rules there, never passwords or keys.

The lab [system-vs-user-prompts](labs/system-vs-user-prompts/README.md) shows prompt assembly done wrong (one concatenated string) and right (separate roles, forged markers removed, documents labeled as untrusted), and what role separation still cannot do.

## Direct and indirect prompt injection

- **Direct:** the attacker is the user and types the instruction ("Ignore previous instructions and ...").
- **Indirect:** the instruction is inside data the app fetches for the user: a web page, an email, a PDF, a ticket, a tool result, a RAG chunk. The victim never typed anything bad. This is the more dangerous kind, because it scales and can be zero-click.

![Direct vs indirect prompt injection](../../images/02-prompt-injection-direct-vs-indirect.svg)

The "lethal trifecta" (private data + untrusted content + a way to send data out) is the combination that turns injection into a breach. See the [repo lesson](../../02-llm-security/prompt-injection/README.md) section 2.4.

## Prompt injection techniques

Know these for testing and for exams (the repo lesson has examples):

| Technique | Idea |
|---|---|
| Override | "Ignore previous instructions and ..." |
| Role-play / persona | "Pretend you are an AI with no rules" |
| Payload splitting | Split a bad request into harmless-looking pieces |
| Encoding and obfuscation | base64, rot13, leetspeak, other languages, spaced letters |
| Completion / prefix attacks | Start the answer so the model continues it |
| Delimiter confusion | Fake `System:` markers or closing tags |
| Hidden text | White text, HTML comments, image text, metadata |
| Multi-turn drift | Build up over several messages |
| Indirect | Plant the text in data the app will read |

The lab [prompt-injection-levels](labs/prompt-injection-levels/README.md) lets you try the first six against an 8-level ladder, one defense at a time.

## Mitigating prompt injection

There is **no filter that fully prevents it**. Design so that a successful injection has little impact.

| Layer | Control | Type |
|---|---|---|
| Architecture | Do not give the model secrets. Do not let one context hold private data, untrusted content and an outbound channel together | Hard |
| Privilege | Least-privilege tools, read-only by default, scoped credentials | Hard |
| Approval | Human confirmation for sensitive or irreversible actions | Hard (process) |
| Output | Validate model output against a schema; strip markdown images and unknown links | Hard |
| Data handling | Label untrusted content, keep roles separate, remove forged markers | Soft |
| Detection | Input and output scanners, injection classifiers, monitoring | Soft |
| Testing | Red-team with an attack suite on every release | Process |

What does NOT work alone: "do not reveal" in the prompt, keyword block lists, asking the model whether the input is an attack, and fine-tuning for refusal. Level 1 to 7 of the ladder lab show why.

## Interview Q&A

<details><summary><b>Q1. What is the difference between direct and indirect prompt injection?</b></summary>
Direct: the user supplies the malicious instruction. Indirect: the instruction is hidden in external content the application passes to the model (web page, email, document, tool output). Indirect is worse because the victim is a different person and no one has to type anything.
</details>

<details><summary><b>Q2. Why can't we just filter prompt injection like SQL injection?</b></summary>
SQL has a strict separation between code and data (parameterized queries). An LLM has none: instructions and data are both natural language in one context window, and there are endless ways to phrase or encode an instruction. So filters are soft layers. The reliable fix is to limit what a hijacked model can do.
</details>

<details><summary><b>Q3. Is the system prompt a safe place for an API key?</b></summary>
No. Anything in the context can be extracted by some prompt. Keep keys in a vault or in tool code the model cannot read. The ladder lab level 8 shows the pattern: the app verifies the code, the model never sees it.
</details>

## References

- OWASP Top 10 for LLM Applications (prompt injection entry): https://genai.owasp.org/
- Greshake et al., "Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection" (2023)
- Repo: [prompt-injection](../../02-llm-security/prompt-injection/README.md), [jailbreak](../../02-llm-security/jailbreak/README.md)
