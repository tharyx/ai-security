# 02. Insecure Output Handling (LLM02 in 2023)

> **Maps to:** 2023 LLM02 Insecure Output Handling | 2025 LLM05 Improper Output Handling | 2026 10 Improper Output Handling.
> **Time:** 45 minutes. **Deep lesson in this repo:** [02-llm-security/data-leakage](../../02-llm-security/data-leakage/README.md), section 2.5.

## Why this matters

The model's answer is not a "safe" string. It can contain script tags, SQL, shell commands, markdown images, links and file paths, because an attacker (or just a bad day) shaped it. If your application passes that answer to a browser, a database, a shell or an API without checking, **the attacker's text becomes code**. This is classic injection with a new source.

## Consequences of insecure output handling

| Where the output goes | What can happen |
|---|---|
| Web page (innerHTML, a rendered chat) | Cross-site scripting (XSS); markdown images that leak data when fetched |
| SQL | SQL injection through "generate a query" features |
| Shell, `eval`, `exec` | Remote code execution |
| HTTP client | Server-side request forgery (SSRF) to internal addresses |
| File paths | Path traversal and overwriting files |
| Templates / email / docs | Content injection, phishing text in your brand's voice |
| Another LLM or agent | Prompt injection chained across systems |
| Generated code merged without review | Vulnerable or backdoored code reaches production |

Example chain (hypothetical): a support bot summarizes a ticket. The ticket contains hidden text telling the model to include an image tag with the customer's data in the URL. The chat window renders the image, the browser requests the URL, and the data leaves with no click. The repo lab [data-leakage](../../02-llm-security/data-leakage/README.md) reproduces this with canaries.

## Mitigating insecure output handling

Treat model output as **untrusted user input**, always.

| Control | Detail | Type |
|---|---|---|
| Encode for the destination | HTML-escape for pages, parameterize SQL, never build commands from strings | Hard |
| Never `eval`/`exec` model output | Parse into a schema, then call an allowlisted function with checked arguments | Hard |
| Strip or allowlist links and images | Remove markdown images; allow only known domains | Hard |
| Validate structure | JSON schema, enums, length limits; reject on failure | Hard |
| Least-privilege downstream | The database account the model's SQL runs under is read-only and scoped | Hard |
| Content Security Policy | Blocks inline script and unknown image hosts in the browser | Hard |
| Scan code before merge | SAST, tests and review for AI-written code (see [the code gate in model-threats](../../02-llm-security/model-threats/README.md)) | Process |
| Output scanners | PII, URLs, relevance (soft; see the chapter 4 lab [guard-io](../ch4-ai-attacks-and-defenses-devops/labs/guard-io/README.md)) | Soft |

For a code-level view, the chapter 4 lab [ai-code-weaknesses](../ch4-ai-attacks-and-defenses-devops/labs/ai-code-weaknesses/README.md) has a scanner that flags "model output flows into `eval` or `subprocess`".

## Hands-on

- Run the repo [data-leakage lab](../../02-llm-security/data-leakage/lab/) (markdown-image exfiltration, output scrubbing).
- Run the chapter 4 [guard-io lab](../ch4-ai-attacks-and-defenses-devops/labs/guard-io/README.md) to see `LinkGuard` remove the exfiltration image.

## Interview Q&A

<details><summary><b>Q1. Why is output from your own model "untrusted"?</b></summary>
Because the model's output is shaped by inputs you do not control (the user's text, retrieved documents, tool results). An attacker can steer it, so its output has the same trust level as user input. Encode it, validate it and run it with least privilege.
</details>

<details><summary><b>Q2. How do you safely let an LLM trigger actions?</b></summary>
Have the model produce a structured request (JSON validated against a schema), map it to an allowlisted function, validate each argument in code, run it with the user's own permissions, and require approval for sensitive actions. Never execute free text.
</details>

## References

- OWASP LLM Top 10 (output handling entry): https://genai.owasp.org/
- OWASP Cheat Sheet Series on XSS prevention and injection prevention: https://cheatsheetseries.owasp.org/
- Repo: [data-leakage](../../02-llm-security/data-leakage/README.md)
