# CAASE: AI Agent Security Course Companion

A study companion for the **CAASE** agentic AI security course, organized exactly like its 7-chapter syllabus.
Every syllabus line points to a lesson that already exists in this repo or to new agent-specific material here. Check line by line in [SYLLABUS-MAP.md](SYLLABUS-MAP.md).

> Unofficial companion. Your course's videos, browser lab and 24×7 support are the primary source. Use this folder to go deeper, practice offline and prepare for interviews.

## Where the syllabus is out of date (Nov 2026)

The course syllabus uses some names and descriptions that have since changed. The lessons teach the syllabus terms, so you can pass the exam, **and** the current reality, so you're right in real work.

| Syllabus says | Current reality |
|---|---|
| **ACP**: Agent Communication Protocol | IBM's ACP **merged into A2A** (Linux Foundation) in August 2025, and its repository is archived. Today "ACP" often means a different thing: Zed's **Agent Client Protocol** (editor ↔ coding agent). |
| **UCP**: "Unified Context Protocol" for shared context | No standard by that name was found. The real **UCP** is Google's **Universal Commerce Protocol** (January 2026), for agentic shopping and checkout, used alongside AP2, MCP and A2A. The labs build the *shared context store* the syllabus describes and label it clearly. |
| **A2A** | Reached **v1.0** (2026) and now sits in the Linux Foundation's **Agentic AI Foundation**, alongside MCP. |
| **OpenClaw** | Renamed twice (Clawdbot → Moltbot → OpenClaw, January 2026). Real incidents: malicious ClawHub skills ("ClawHavoc"), CVE-2026-25253, and many internet-exposed gateways. NemoClaw, NanoClaw, SecureClaw and MiniClaw are hardening options and spin-offs. |
| **CISA / Five Eyes agentic guidance** | Published 1 May 2026 as "Careful Adoption of Agentic AI Services". |
| **NIST AI 100-2** | The current edition is **E2025** (March 2025). |
| **OWASP Top 10 for LLMs** | Now the **2026** list. Agentic risks have their own **OWASP Top 10 for Agentic Applications (ASI01–ASI10)**. |

## Chapters

| # | Chapter | Key labs |
|---|---|---|
| 1 | [Agents, harnesses and the agentic ecosystem](ch1-agents-harnesses-and-the-agentic-ecosystem/) | Minimal agent harness, model-sizing calculator, local/cloud routing proxy, tool-calling determinism, ATLAS threat model |
| 2 | [Agent reasoning, goals and prompt boundaries](ch2-agent-reasoning-goals-and-prompt-boundaries/) | Planning-loop injection, jailbreak, prompt/goal leaking, goal hijack, guardrail model, objective-drift detection |
| 3 | [Agent memory, context and tool use](ch3-agent-memory-context-and-tool-use/) | Memory poisoning, RAG poisoning, parameter abuse, tool-chain privilege escalation, Docker sandbox, MCP integrity audit, session forensics |
| 4 | [Computer-use, browser and coding agents](ch4-computer-use-browser-and-coding-agents/) | OpenClaw-style misconfiguration, README/commit injection, harness audit plugin, workspace escape, secure small-model harness, skill vetting, browser page injection, human approval |
| 5 | [Multi-agent systems and agent identity](ch5-multi-agent-systems-and-agent-identity/) | Delegator/worker, isolated subagents, A2A spoofing, confused deputy, delegated tokens, rogue agent termination, HITL gate |
| 6 | [Operationalizing agentic AI security](ch6-operationalizing-agentic-ai-security/) | Red-team release gate, trace dashboard, AIBOM, model provenance, signing, skill scanning, SecOps triage agent |
| 7 | [Threat modeling agents and communication protocols](ch7-threat-modeling-agents-and-communication-protocols/) | STRIDE + ATLAS multi-agent model, A2A exchange and spoofing, session abuse, shared-context poisoning, cross-protocol audit, mutual authentication, protocol threat model |

## How the labs run

| Lab type | Where | Needs |
|---|---|---|
| `labs/…` | Your laptop, offline | `python -m pytest caase-course` |
| `real-tools/` guides (LibreChat, Hermes Agent, OpenClaw, Docker, OpenRouter, cosign) | Your course lab, or your laptop with care | Docker/accounts as described. **Never expose agent gateways to the internet.** |

> Your laptop (16 GB RAM, no GPU) can run only small local models (1–4B, quantized) through Ollama. Route bigger tasks to the course lab or a cloud model, and keep company data out of cloud models unless you're allowed to send it there.

## How this connects to the rest of the repo

| Course chapter | Builds on |
|---|---|
| 1 | [05 agents](../05-agent-security/), [CAISP ch2 · ATLAS](../caisp-course/ch2-understanding-and-attacking-llms/), [CMCPSE ch1](../cmcpse-course/ch1-introduction-to-mcp-and-agentic-ecosystem/) |
| 2 | [02 · prompt-injection](../02-llm-security/prompt-injection/), [02 · jailbreak](../02-llm-security/jailbreak/), [05 · permissions](../05-agent-security/permissions/) |
| 3 | [03 RAG](../03-rag-security/), [05 · sandboxing](../05-agent-security/sandboxing/), [CMCPSE ch4](../cmcpse-course/ch4-defending-and-hardening-mcp-servers/) |
| 4 | [05 · sandboxing](../05-agent-security/sandboxing/), [CMCPSE ch6 · backdoored package](../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/) |
| 5 | [05 · agent-identity](../05-agent-security/agent-identity/), [05 · multi-agent-trust](../05-agent-security/multi-agent-trust/), [09 · AI IAM](../09-enterprise-architecture/07-centralized-ai-iam-and-zero-trust.md) |
| 6 | [02 · security-testing](../02-llm-security/security-testing/), [06](../06-ai-devsecops/), [10 · AI SOC](../10-capstone-project/05-ai-soc-monitoring-extension.md), [07](../07-ai-governance/) / [08](../08-ai-compliance/) |
| 7 | [CAISP ch5](../caisp-course/ch5-threat-modeling-ai-systems/), [CMCPSE ch3](../cmcpse-course/ch3-threat-modeling-mcp-architectures/) |
