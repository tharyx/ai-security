# 10. Model Theft (LLM10 in 2023)

> **Maps to:** 2023 LLM10 Model Theft | 2025 and 2026: no separate entry; extraction is treated under Unbounded Consumption (and file or weights leaks under Sensitive Information Disclosure and supply chain controls).
> **Time:** 45 minutes. **Deep lesson in this repo:** [02-llm-security/model-threats](../../02-llm-security/model-threats/README.md), section 2.3 (extraction through the API, with a lab and a defense).

## Why this matters

A trained model is expensive intellectual property, and it may embed private training data. If it is copied, a competitor gets your investment, an attacker gets an offline copy to study for weaknesses, and private data may be exposed.

Facts to know:

- Tramer and colleagues (2016) showed that a model behind a prediction API can be copied by querying it.
- In March 2023, the weights of Meta's LLaMA model leaked online after being shared under a research-access arrangement. Weights, once out, cannot be recalled.
- Carlini and colleagues (2024) showed that part of a production language model's final layer can be recovered through its API.

## Stealing models

| Path | How it works | Needs |
|---|---|---|
| **Direct file theft** | Weights copied from storage, a container image, a laptop, a CI artifact, a backup | Access to the files: an insider, stolen credentials, a leaky bucket |
| **Model extraction through the API** | Send many queries, record outputs, train a copy ("student") | Query access; scales with allowed volume |
| **Distillation misuse** | Same idea, using a strong model's outputs to train another, possibly against terms of service | Many high-quality answers |
| **Side channels** | Timing, cache or memory behavior in shared hardware hints at the model | Co-located access; research-grade |
| **Prompt and config theft** | System prompts, adapters or fine-tuning data copied | Prompt extraction (see lesson 06), repository access |
| **Supply chain theft** | A compromised pipeline or plugin exfiltrates the weights | Pipeline access (see chapter 4) |

## Mitigating model theft

| Control | Detail | Type |
|---|---|---|
| Access control | Least privilege and MFA on weights, registries and training clusters | Hard |
| Encrypt and segment | Encryption at rest and in transit; separate production weights from dev | Hard |
| Audit and alert | Log all reads of model artifacts; alert on bulk copies | Process |
| Rate limits and quotas | Per key and per tenant; budgets stop mass querying | Hard |
| Limit output detail | Return labels not full probability vectors; cap length; no logprobs unless needed | Hard |
| Detect extraction | Watch for systematic, high-coverage query patterns | Soft |
| Watermarking and fingerprints | Embed signals to prove a copy later | Soft |
| Legal and contractual | Terms of service, licenses, NDAs | Process |
| Secure the pipeline | Pipeline hardening and secret hygiene (chapter 4) | Hard |
| Isolate serving | Dedicated tenants, hardened containers, no debug endpoints | Hard |

Be honest about limits: if a model gives useful answers to anyone, it can be partially imitated. Controls make theft slower, costlier and detectable.

## Hands-on

The [model-threats lab](../../02-llm-security/model-threats/lab/) copies a toy model through its API and then stops it with limits and output hardening. Combine it with the rate limiter in [security-testing `limits.py`](../../02-llm-security/security-testing/lab/limits.py).

## Interview Q&A

<details><summary><b>Q1. How can someone steal a model they cannot download?</b></summary>
By model extraction: query the API many times, collect input and output pairs, and train a copy. Defenses: rate limits, quotas, less detailed outputs, query pattern monitoring, authentication and contracts.
</details>

<details><summary><b>Q2. Where did Model Theft go in the newer OWASP lists?</b></summary>
It no longer has its own entry. Extraction through heavy API use is covered by Unbounded Consumption, and weights leaks are covered by access control, supply chain and sensitive information controls. The defenses are the same.
</details>

<details><summary><b>Q3. A competitor's model suddenly answers like yours. What do you do?</b></summary>
Preserve evidence (logs, query patterns, accounts), check whether fingerprints or watermarks match, review access logs for artifact reads, involve legal, and tighten rate limits, keys and output detail.
</details>

## References

- Tramer et al., "Stealing Machine Learning Models via Prediction APIs" (2016)
- Carlini et al., "Stealing Part of a Production Language Model" (2024)
- OWASP LLM Top 10 (model theft in 2023; later lists): https://genai.owasp.org/
- Repo: [model-threats](../../02-llm-security/model-threats/README.md)
