# 03. Training Data Poisoning (LLM03 in 2023)

> **Maps to:** 2023 LLM03 Training Data Poisoning | 2025 LLM04 Data and Model Poisoning | 2026 05 Data and Model Poisoning.
> **Time:** 1.5 hours. **Deep lesson in this repo:** [02-llm-security/model-threats](../../02-llm-security/model-threats/README.md), section 2.2 (a backdoor planted through training data, and the poisoning gate). This page adds the new depth: how an LLM learns, and where poisoning enters each stage.

## Why this matters

If an attacker controls part of what the model learns from, they control part of what it does, and the damage hides inside the weights. It survives restarts, passes normal tests and is hard to find.

- Microsoft's Tay chatbot (2016) learned from users in public and was pushed into offensive output within a day: online learning from untrusted input.
- Carlini and colleagues (2023) showed that some web-scale datasets can be poisoned cheaply, because they are built from URLs whose content can change after listing.
- Researchers (2025, reported by several labs together) reported that a small, fixed number of poisoned documents can plant a backdoor in models of very different sizes. Treat the details as "verify at source", but the lesson stands: poisoning does not need control of a large share of the data.
- Mithril Security's "PoisonGPT" demo (2023) showed a model edited to spread one false fact while behaving normally elsewhere (see ROME in the course chapter on supply chain).

## LLM's core learning approaches

An LLM is built in stages. Each stage reads data, so each stage can be poisoned.

| Stage | What happens | Data source | Where poisoning enters | Typical effect |
|---|---|---|---|---|
| **Pre-training** | Learn to predict the next token on huge text collections (web crawls, books, code) | Scraped and licensed corpora | Planted web pages, edited pages on a crawled site, expired domains that are re-registered, poisoned code repositories | Biases, false facts, hidden trigger-to-behavior pairs |
| **Fine-tuning** (supervised) | Train further on curated examples (instructions and answers) for a task or domain | Company documents, vendor datasets, crowd-written data | A poisoned example set, a malicious contractor, a compromised dataset repo | Backdoor: a trigger phrase causes a chosen output; degraded safety |
| **RLHF / preference tuning** | A reward signal from human (or AI) preferences shapes behavior | Human ratings, preference pairs | Biased or malicious raters, manipulated preference data, reward hacking | Model learns to please or to hide behavior; safety behavior erodes |
| **In-context learning** | No weight change: the model follows examples and facts placed in the prompt | Prompt, few-shot examples, retrieved documents (RAG) | Poisoned retrieved documents or examples; a "memory" that stores attacker text | Same effect as an instruction, but temporary and per request |
| **Embeddings / retrieval index** | Documents are turned into vectors for search | Knowledge base | Planting documents so they rank high for chosen queries | Attacker content is served as trusted context |

Key points for the exam:

- **Poisoning vs prompt injection.** Poisoning changes the **model or its data** (persistent). Injection changes **the input at run time** (per request). RAG and memory poisoning sit in between.
- **Backdoor vs availability attack.** A backdoor keeps normal accuracy and fires on a trigger. An availability poison degrades the whole model.
- Fine-tuning on a small clean-looking dataset can also *remove* safety behavior by accident.

The lab [model-threats](../../02-llm-security/model-threats/lab/) shows a trigger-word backdoor in a toy model and the data gate that stops it.

## Mitigating training data poisoning

| Control | Detail | Type |
|---|---|---|
| Know your data | A data inventory and AI-BOM: source, owner, license, hash, version for every dataset | Process |
| Pin and verify | Fixed dataset versions and hashes; no silently changing URLs | Hard |
| Gate untrusted data | Provenance checks, deduplication, outlier and trigger scans, quarantine before training | Hard/Soft |
| Separate trust levels | Do not train on raw user input or unreviewed feedback | Hard |
| Protect the pipeline | Access control and audit on dataset stores and training jobs | Hard |
| Evaluate after training | Backdoor probes, safety evals, comparison with the previous model (a "diff test") | Process |
| Sign what you ship | Hash and sign model artifacts so later tampering is detected | Hard |
| Defend the retrieval index | Authorization before retrieval and source allowlists for RAG | Hard |
| Monitor | Watch for behavior drift and for odd answers to rare inputs | Soft |

## Interview Q&A

<details><summary><b>Q1. Where can poisoning enter an LLM's life cycle?</b></summary>
In pre-training data (web crawls and code), in fine-tuning data, in preference and rating data used for RLHF, in the retrieval index and memory (in-context), and in the model file itself during storage or transfer.
</details>

<details><summary><b>Q2. How is a backdoor different from ordinary poor quality data?</b></summary>
A backdoor is deliberate and conditional. The model behaves normally on normal tests and misbehaves only on a trigger the attacker chose, so standard accuracy checks do not reveal it.
</details>

<details><summary><b>Q3. You fine-tune a model on customer tickets. What controls do you add?</b></summary>
Data inventory and provenance, remove personal data, filter out instructions and unusual patterns, restrict who can add data, keep the dataset versioned and hashed, run backdoor and safety evals on the result and compare with the base model, sign the output model.
</details>

## References

- OWASP LLM Top 10 (data and model poisoning entry): https://genai.owasp.org/
- Carlini et al., "Poisoning Web-Scale Training Datasets is Practical" (2023)
- MITRE ATLAS technique "Poison Training Data": https://atlas.mitre.org/
- Repo: [model-threats](../../02-llm-security/model-threats/README.md)
