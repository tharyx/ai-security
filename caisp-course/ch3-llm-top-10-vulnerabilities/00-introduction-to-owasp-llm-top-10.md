# 00. Introduction to the OWASP Top 10 LLM Attacks

> **Syllabus:** Chapter 3, "Introduction to the OWASP Top 10 LLM attacks". **Time:** 30 minutes.
> **You will:** know what the list is, how to use it, and how the ten risks fit one picture.

## Why this matters

An LLM application is a normal application plus a model that reads text and decides things. It inherits web risks (injection, access control, supply chain) and adds new ones (the model can be talked into acting). The OWASP Top 10 for LLM Applications is the shared vocabulary for these risks. Auditors, exam questions and job interviews use it.

## Understand it

### What OWASP is and what the list is

OWASP is a non-profit community that publishes free security guidance (the web Top 10 is its best-known work). The **OWASP GenAI Security Project** publishes the *Top 10 for LLM Applications*. It is an awareness list, ranked by the community's view of risk. It is **not** a standard you can pass, and not a complete list.

Versions: 2023 (v1.1, used in this course), 2025 and 2026. See [owasp-llm-2023-vs-2026.md](owasp-llm-2023-vs-2026.md) for the mapping.

### The ten risks in one picture

Think of one request moving through an LLM application:

```text
user / documents / web ──> [1 Prompt Injection] ──> LLM ──> [2 Insecure Output Handling] ──> app, browser, shell, database
                                  ^                  |   \
        [3 Training Data Poisoning]   [4 Model DoS]  |    \──> [8 Excessive Agency] ──> tools [7 Insecure Plugin Design]
        [5 Supply Chain]  (data, models, libraries)  |
                                  [6 Sensitive Information Disclosure]   [9 Overreliance]   [10 Model Theft]
```

| Group | Risks | Question it asks |
|---|---|---|
| What goes in | 01 Prompt Injection, 03 Training Data Poisoning, 05 Supply Chain | Can an attacker control what the model reads or learns? |
| What comes out | 02 Insecure Output Handling, 06 Sensitive Information Disclosure, 09 Overreliance | Do we trust or leak what the model says? |
| What it can do | 07 Insecure Plugin Design, 08 Excessive Agency | What happens when the model calls tools? |
| What it costs | 04 Model Denial of Service, 10 Model Theft | Can someone exhaust it or copy it? |

### The root cause behind most of them

The model cannot reliably tell **instructions** from **data**. Everything in the context window is text. So untrusted text can steer the model. That one fact explains prompt injection, plugin abuse, excessive agency and many leaks. The consequence for design: never rely on the model to enforce security. Put hard controls in code around it.

## Defend it (the pattern that repeats in every lesson)

1. **Treat the model as an untrusted component.** Its output is untrusted input to your next system.
2. **Least privilege.** Give the app and its tools only what the task needs.
3. **Validate and encode** at every boundary (input, output, tool arguments).
4. **Keep secrets out of the context.** Anything in the prompt can be extracted.
5. **Limit cost** (size, rate, budget, steps).
6. **Verify the supply chain** (sources, hashes, signatures, scans).
7. **Human approval** for risky actions.
8. **Test with attacks, and monitor.**

## Hands-on

Run the labs in this chapter in this order (all offline): [prompt-injection-levels](labs/prompt-injection-levels/README.md), [system-vs-user-prompts](labs/system-vs-user-prompts/README.md), [sensitive-info-extraction](labs/sensitive-info-extraction/README.md), [hallucination-lab](labs/hallucination-lab/README.md), [model-dos-context-exhaustion](labs/model-dos-context-exhaustion/README.md). The chapter [README](README.md) has the lab index.

## Interview Q&A

<details><summary><b>Q1. Is the OWASP LLM Top 10 a standard?</b></summary>
No. It is a community awareness list. It gives names and priorities for common risks. It does not define pass/fail requirements. Frameworks such as NIST AI RMF or ISO 42001 are used for governance, and OWASP lists help with technical risk naming.
</details>

<details><summary><b>Q2. What is the one idea that connects most of the ten risks?</b></summary>
The model cannot separate instructions from data, so untrusted text can steer it. Hence the rule: treat model output and model "decisions" as untrusted, and enforce security in code outside the model.
</details>

## References

- OWASP GenAI Security Project: https://genai.owasp.org/ (Top 10 for LLM Applications, all versions)
- Repo module map: [02-llm-security](../../02-llm-security/README.md)
