# Brightix 45-Day Program Companion: LLM, AI & MCP Security

This folder is a study companion for the **Brightix IT Solutions 45-day "LLM Security, AI Security & MCP Security" program** (8 modules, 47 syllabus topics, scenario-based, offensive + defensive + SOC).

Most of the program is already taught in depth in this repo, so this companion does not repeat it. Each module page instead gives you:
- a **coverage table** that maps every syllabus line to the best existing lessons and hands-on labs in the repo;
- **new labs and guides** where the repo was thin (marked **NEW**);
- a **day-by-day plan** that fits the 45 days.

The full line-by-line checklist is in [SYLLABUS-MAP.md](SYLLABUS-MAP.md).

> **Unofficial companion.** Your Brightix sessions and lab environment are the primary source. Tool versions and dates are hedged: **verify at the source**.

## The 45-day plan

| Days | Module | Focus | New in this companion |
|---|---|---|---|
| 1–4 | [01 LLM Security Fundamentals](m01-llm-security-fundamentals/README.md) | How LLMs work, tokens, context, prompt hierarchy, parameters, trust boundaries | n/a |
| 5–9 | [02 LLM Application & RAG Security](m02-llm-application-and-rag-security/README.md) | Orchestration, RAG, embeddings/vector DBs, ingestion, retrieval ACLs, poisoning | n/a |
| 10–15 | [03 LLM Vulnerabilities (OWASP Top 10)](m03-llm-vulnerabilities-owasp/README.md) | Injection, disclosure, jailbreaks, output handling, excessive agency, privacy | Model inversion and membership inference lab |
| 16–22 | [04 AI Red Teaming & Automated Testing](m04-ai-red-teaming-and-automated-testing/README.md) | ATLAS, multi-turn and encoding attacks, indirect injection, agent privesc, reporting | garak/PyRIT-style scanner lab and real-tool guide |
| 23–29 | [05 Guardrails, Defenses & Governance](m05-guardrails-defenses-and-governance/README.md) | Rails, injection classifiers, DLP, gateways and quotas, HITL, NIST AI RMF / EU AI Act / ISO 42001 | NeMo-style rails + Llama-Guard-style classifier + semantic firewall lab and guide |
| 30–35 | [06 AI Security Monitoring & SOC](m06-ai-security-monitoring-and-soc/README.md) | Telemetry, what to log, behaviour monitoring, risk scoring, SIEM/SOAR, AI incident response | AI SOAR playbooks lab and Sentinel KQL / Splunk SPL guide |
| 36–40 | [07 MCP Security Fundamentals](m07-mcp-security-fundamentals/README.md) | Architecture and transports, attack surface, OAuth, tool poisoning, rug pulls, shadow servers, hardening | n/a |
| 41–45 | [08 Capstone: Enterprise AI & MCP](m08-capstone-enterprise-ai-and-mcp/README.md) | Threat model, full red team, guardrails and MCP hardening, detections and playbooks, exec presentation | Multi-agent RAG + MCP capstone lab and executive readiness deck template |

**A study day** is about 2–3 hours: read the linked lesson sections (about 1 hour), run the lab and its tests (about 1 hour), then write 5 lines in your [journal](../journal/) on what you would check in your own company.

## Where the program's wording is out of date (Nov 2026)

| Program says | Current reality (verify at source) |
|---|---|
| "OWASP Top 10" for LLMs (no year) | The repo uses the **2026** list. The numbers moved between the 2023, 2025 and 2026 editions; see the [2023 ↔ 2026 mapping](../caisp-course/ch3-llm-top-10-vulnerabilities/owasp-llm-2023-vs-2026.md). Always say the year with an ID. |
| "Insecure Output Handling" | That is the 2023 name. Later editions call it **Improper Output Handling**. |
| Llama Guard | **Llama Guard 4** (Apr 2025, multimodal) is the latest; Llama Guard 3 is still common. Alternatives include ShieldGemma, IBM Granite Guardian and Prompt Guard. |
| PyRIT "orchestrators" | Newer PyRIT releases are moving to an "attack strategy / executor" vocabulary. Check the version you install. |
| MCP transports | **Streamable HTTP** replaced the deprecated HTTP+SSE transport. MCP is now governed by the Agentic AI Foundation (Linux Foundation, Dec 2025). |
| EU AI Act dates | The **Omnibus amendment (Regulation (EU) 2026/1744)** moved the high-risk dates to 2 Dec 2027 (stand-alone) and 2 Aug 2028 (embedded). |
| Incident response lifecycle | **NIST SP 800-61 Rev. 3** (2025) aligns IR to CSF 2.0; many SOCs still use the Rev. 2 phase names. |

## How the labs run

| Lab type | Where | Needs |
|---|---|---|
| Linked repo labs and **NEW** labs | Your laptop, offline | `python -m pytest brightix-course` for the new labs (each linked lab has its own tests). The Python standard library and the repo's `MockLLM` only: no GPU, API key or model download. |
| `real-tools/` guides | Your Brightix lab, or your laptop with Ollama or a cloud model | garak, PyRIT, NeMo Guardrails, Llama Guard, Sentinel or Splunk. Commands are hedged. |

> **Safety.** Every attack lab targets the repo's own toy apps and mock models. Only test systems you own or have written permission to test.

## How this connects to the rest of the repo

This program is close to the repo's own **AI security roadmap** (modules 01–10) plus three course companions: [CAISP](../caisp-course/) (LLM Top 10 and AI attacks), [CMCPSE](../cmcpse-course/) (MCP security) and [CAASE](../caase-course/) (agent security). Module 06 lines up with your SOC job and the [cybersecurity track](../cybersecurity-track/) (SIEM, Sentinel, Splunk).
