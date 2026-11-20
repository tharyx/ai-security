# Cheat Sheets

One-page revision maps for interviews and quick recall. Each sheet starts from a popular infographic, is re-checked against current sources, and links every item to the lesson and the lab in this repo where it is taught. Where the repo had no hands-on practice for an item, a **NEW** lab was added here.

| Sheet | What it covers | New labs |
|---|---|---|
| [01 The six types of AI security](01-types-of-ai-security.md) | Data, model, LLM app, agent, supply chain and runtime security: what each protects, main attacks, controls, OWASP and ATLAS mapping, tools | [training-data-hygiene](labs/training-data-hygiene/), [evasion-and-adversarial-training](labs/evasion-and-adversarial-training/) |
| [02 LLM red teaming quick guide](02-llm-red-teaming-quick-guide.md) | What to test, methods, scoring (benchmarks, severity, ASR, coverage, false refusals), fixes, framework mapping | [red-team-scorecard](labs/red-team-scorecard/) |

**Run the labs:** `python -m pytest cheat-sheets`. They run offline, using only the Python standard library and the repo's `MockLLM`.

> **Safety.** The labs attack only their own toy models and apps, and harmful-content tests use placeholder prompts only. Only test systems you own or have written permission to test.

**Add your own.** When you find a useful infographic, add a sheet here in the same format: one table, every item linked to a repo lesson and lab, and a "Corrections" section for anything outdated.
