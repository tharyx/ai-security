# Chapter 1: Agents, Harnesses and the Agentic Ecosystem

This chapter gives you the vocabulary and the map for the whole course: what makes an agent different from an LLM call, what a harness wraps around a model, where the attack surface is, which frameworks describe the risk, and which free and open tools you can use to practice. It ends with hands-on exercises. Every lab here runs offline with tests, and the real-tool exercises have hedged guides plus an offline twin.

## Syllabus coverage

Every syllabus line is listed in order. Sub-topics keep their own row. "n/a" means the line is administrative or covered by reading only.

| Syllabus item | Where to study | Lab |
|---|---|---|
| About the course, syllabus, and how to approach it | [00 How to approach this course](00-how-to-approach-this-course.md) | n/a |
| About the CAASE Certification and how to approach it | [00, section 3](00-how-to-approach-this-course.md#3-about-the-certification-generic-advice) (generic: check the course page for exam details) | n/a |
| Course Lab Environment | [00, section 4](00-how-to-approach-this-course.md#4-the-browser-based-lab-vs-this-repo) (browser lab vs this repo) | [labs index](#lab-index) |
| Lifetime course support 24 x 7 | [00, section 5](00-how-to-approach-this-course.md#5-lifetime-course-support-24-x-7-how-to-ask-good-questions) | n/a |
| What Makes an "Agent" Different from an LLM Call | [01 Agent vs LLM call](01-agent-vs-llm-call.md) | [minimal-agent-harness](labs/minimal-agent-harness/README.md) |
| The plan to act to observe (cognitive) loop | [01, section 2.2](01-agent-vs-llm-call.md#22-the-plan-act-observe-cognitive-loop) · [SVG](../../images/caase-ch1-cognitive-loop.svg) | [minimal-agent-harness](labs/minimal-agent-harness/README.md) |
| Agents vs. chatbots vs. copilots vs. autonomous agents | [01, section 2.3](01-agent-vs-llm-call.md#23-agents-vs-chatbots-vs-copilots-vs-autonomous-agents) | n/a |
| Planner-Executor-Verifier and other common agent design patterns | [01, section 2.4](01-agent-vs-llm-call.md#24-common-agent-design-patterns) (ReAct, plan-and-execute, planner-executor-verifier, reflection, router, supervisor) | [minimal-agent-harness](labs/minimal-agent-harness/README.md) |
| Single-agent vs. multi-agent systems | [01, section 2.5](01-agent-vs-llm-call.md#25-single-agent-vs-multi-agent-systems) · [multi-agent trust](../../05-agent-security/multi-agent-trust/README.md) | n/a |
| Anatomy of an Agent Harness | [02 Anatomy of an agent harness](02-anatomy-of-an-agent-harness.md) · [SVG](../../images/caase-ch1-harness-anatomy.svg) | [minimal-agent-harness](labs/minimal-agent-harness/README.md) |
| What a "harness" actually wraps around a model | [02, section 2.1](02-anatomy-of-an-agent-harness.md#21-what-a-harness-wraps-around-a-model) | [minimal-agent-harness](labs/minimal-agent-harness/README.md) |
| Real-world harnesses [Hermes, OpenClaw Ecosystem, and more] | [02, section 2.2](02-anatomy-of-an-agent-harness.md#22-real-world-harnesses) · [Hermes guide](real-tools/hermes-agent-local-and-openrouter.md) · [LibreChat guide](real-tools/librechat-mcp-local-ollama.md) | [real-tools](real-tools/README.md) (hedged, not tested) |
| Agent runtimes vs. MCP servers vs. the underlying LLM | [02, section 2.3](02-anatomy-of-an-agent-harness.md#23-agent-runtimes-vs-mcp-servers-vs-the-underlying-llm) · [CMCPSE chapter 1](../../cmcpse-course/ch1-introduction-to-mcp-and-agentic-ecosystem/README.md) | n/a |
| Building your own minimal agent harness | [02, section 2.4](02-anatomy-of-an-agent-harness.md#24-building-your-own-minimal-agent-harness) | [minimal-agent-harness](labs/minimal-agent-harness/README.md) |
| The Agentic AI Attack Surface | [03 Agentic attack surface](03-agentic-attack-surface.md) | [atlas-threat-model-agent](labs/atlas-threat-model-agent/README.md) |
| Mapping a complete agentic pipeline | [03, section 2.1](03-agentic-attack-surface.md#21-mapping-a-complete-agentic-pipeline) · [SVG](../../images/caase-ch1-attack-surface.svg) | [atlas-threat-model-agent](labs/atlas-threat-model-agent/README.md) |
| The agentic layer after the model and MCP tools | [03, section 2.2](03-agentic-attack-surface.md#22-the-agentic-layer-after-the-model-and-mcp-tools) | n/a |
| Trust boundaries in an agentic system | [03, section 2.3](03-agentic-attack-surface.md#23-trust-boundaries-in-an-agentic-system) | [minimal-agent-harness](labs/minimal-agent-harness/README.md) (boundary B1 and B2 in action) |
| Threat Modeling and Risk Frameworks for Agentic AI | [04 Frameworks](04-threat-modeling-and-risk-frameworks.md) · [CAISP chapter 5](../../caisp-course/ch5-threat-modeling-ai-systems/README.md) | [atlas-threat-model-agent](labs/atlas-threat-model-agent/README.md) |
| OWASP Top 10 for LLM Applications | [04, section 2.1](04-threat-modeling-and-risk-frameworks.md#21-owasp-top-10-for-llm-applications-2026-list) · [2023 vs 2026](../../caisp-course/ch3-llm-top-10-vulnerabilities/owasp-llm-2023-vs-2026.md) | n/a |
| OWASP Agentic Security Initiative | [04, section 2.2](04-threat-modeling-and-risk-frameworks.md#22-owasp-agentic-security-initiative-asi) · [05-agent-security ASI mapping](../../05-agent-security/README.md) | [atlas-threat-model-agent](labs/atlas-threat-model-agent/README.md) |
| MITRE ATLAS matrix for AI/ML systems | [04, section 2.3](04-threat-modeling-and-risk-frameworks.md#23-mitre-atlas-for-aiml-systems) · [ATT&CK vs ATLAS and the 14 tactics](../../caisp-course/ch2-understanding-and-attacking-llms/02-attck-vs-atlas-and-the-14-tactics.md) | [atlas-threat-model-agent](labs/atlas-threat-model-agent/README.md) |
| NIST AI Risk Management Framework (AI RMF) | [04, section 2.4](04-threat-modeling-and-risk-frameworks.md#24-nist-ai-risk-management-framework-ai-rmf) · [AI risk management](../../07-ai-governance/03-ai-risk-management.md) | n/a |
| NIST AI 100-2 adversarial ML taxonomy | [04, section 2.5](04-threat-modeling-and-risk-frameworks.md#25-nist-ai-100-2-adversarial-machine-learning-taxonomy) | n/a |
| Rating agentic-specific risks | [04, section 2.6](04-threat-modeling-and-risk-frameworks.md#26-rating-agentic-specific-risks) · [CAISP rating lesson](../../caisp-course/ch5-threat-modeling-ai-systems/05-rating-and-managing-risks.md) | [atlas-threat-model-agent](labs/atlas-threat-model-agent/README.md) |
| The Free/Open Agentic Toolchain | [05 Free and open agentic toolchain](05-free-open-agentic-toolchain.md) | [model-sizing-calculator](labs/model-sizing-calculator/README.md) |
| Local open-weight models sized to fit consumer-grade VRAM budgets | [05, section 2.1](05-free-open-agentic-toolchain.md#21-local-open-weight-models-sized-to-consumer-vram-budgets) | [model-sizing-calculator](labs/model-sizing-calculator/README.md) |
| Cloud/API-routed models for tasks that exceed local hardware capacity | [05, section 2.2](05-free-open-agentic-toolchain.md#22-cloud-and-api-routed-models-for-tasks-beyond-local-hardware) | [routing-proxy](labs/routing-proxy/README.md) |
| OpenRouter-style routing layers across free and paid models | [05, section 2.3](05-free-open-agentic-toolchain.md#23-openrouter-style-routing-layers-across-free-and-paid-models) · [LiteLLM guide](real-tools/litellm-proxy-cloud-routing.md) | [routing-proxy](labs/routing-proxy/README.md) |
| VSCode as an agent surface (extensions, integrated coding agents) | [05, section 2.4](05-free-open-agentic-toolchain.md#24-vs-code-as-an-agent-surface) | n/a |
| Hands-on Exercise: | See the rows below | |
| Learn how to use our browser-based lab environment | [00, section 4](00-how-to-approach-this-course.md#4-the-browser-based-lab-vs-this-repo) (use the course lab first; copy every command into your notes) | [labs index](#lab-index) (offline repetition) |
| Building a Minimal Agent Harness on Top of a Local Open-Weight Model | [02, section 2.4](02-anatomy-of-an-agent-harness.md#24-building-your-own-minimal-agent-harness) | [minimal-agent-harness](labs/minimal-agent-harness/README.md) (set `AISEC_LLM_BACKEND=ollama` for a real small model) |
| Setting Up LibreChat for MCP Tool-Calling with a Local Model | [LibreChat guide](real-tools/librechat-mcp-local-ollama.md) (hedged) | Twin: [minimal-agent-harness](labs/minimal-agent-harness/README.md) and [tool-calling-determinism](labs/tool-calling-determinism/README.md) |
| Standing Up Hermes Agent with a Local and a Cloud-Routed Model Side by Side | [Hermes guide](real-tools/hermes-agent-local-and-openrouter.md) (hedged) | Twin: [tool-calling-determinism](labs/tool-calling-determinism/README.md) and [routing-proxy](labs/routing-proxy/README.md) |
| Routing Agent Requests to a Large Cloud Model via a Proxy and Comparing It to a Local Model | [LiteLLM guide](real-tools/litellm-proxy-cloud-routing.md) (hedged) · [05, sections 2.2 and 2.3](05-free-open-agentic-toolchain.md#22-cloud-and-api-routed-models-for-tasks-beyond-local-hardware) | Twin: [routing-proxy](labs/routing-proxy/README.md) |
| Comparing Tool-Calling Determinism Across Two Local Models Running Concurrently | [02, section 2.4](02-anatomy-of-an-agent-harness.md#24-building-your-own-minimal-agent-harness) | [tool-calling-determinism](labs/tool-calling-determinism/README.md) |
| Threat Modeling an Agentic AI System Using MITRE ATLAS | [04](04-threat-modeling-and-risk-frameworks.md) · [03](03-agentic-attack-surface.md) | [atlas-threat-model-agent](labs/atlas-threat-model-agent/README.md) |

## Outdated in the syllabus → current

The learner was told the syllabus may contain old information. Learn the course's words for the exam, and the current facts for your work. Verify each at its source.

| Syllabus wording | Current state (as of late 2026, hedged) |
|---|---|
| "OWASP Top 10 for LLM Applications" (names from 2023, such as Insecure Output Handling, Insecure Plugin Design, Overreliance) | Current is the 2026 list: Prompt Injection, Sensitive Information Disclosure, Excessive Agency, Supply Chain, Data and Model Poisoning, Unbounded Consumption, Misinformation, Hidden Context Exposure, Vector and Embedding Weaknesses, Improper Output Handling. See [2023 vs 2026](../../caisp-course/ch3-llm-top-10-vulnerabilities/owasp-llm-2023-vs-2026.md). |
| "MITRE ATLAS matrix" with "ML Model Access" and "ML Attack Staging" | About 16 tactics in 2026; renamed "AI Model Access" and "AI Attack Staging" (a further rename to "AI Attack Adaptation" is reported but unconfirmed). Check atlas.mitre.org. |
| "OWASP Agentic Security Initiative" | Produced the OWASP Top 10 for Agentic Applications 2026 (ASI01 to ASI10) and "Agentic AI: Threats and Mitigations". An OWASP Agent Control Standard is mentioned in research notes (hedge). |
| "NIST AI 100-2 adversarial ML taxonomy" | The current edition is AI 100-2 E2025 (March 2025), with five dimensions and added coverage of generative AI attacks and agent security. NIST plans annual updates; no 2026 edition found. |
| "NIST AI Risk Management Framework (AI RMF)" | AI RMF 1.0 plus the Generative AI Profile (AI 600-1). NIST launched an AI Agent Standards Initiative in early 2026 (hedge). |
| "OpenClaw Ecosystem" (and earlier names) | Formerly Clawdbot and Moltbot; renamed OpenClaw on 30 Jan 2026; moved toward an independent foundation in Feb 2026; known security incidents (ClawHavoc skills, a patched token-theft CVE, many exposed instances); several hardening spin-offs. Hedge everything and verify. |
| "Hermes" | Hermes Agent by Nous Research, open source, launched Feb 2026 (hedge). Do not confuse with the older Hermes language models from the same lab. |
| "Local open-weight models sized to fit consumer-grade VRAM budgets" | The method (sizing formula) is stable; model names and sizes change quickly. Your laptop has no GPU: use 1B to 4B Q4 on CPU. |
| New in 2026 and worth knowing | Five Eyes joint guidance "Careful Adoption of Agentic AI Services" (1 May 2026, hedge). A2A v1.0 and the Agentic AI Foundation (Chapter 7). MCP spec revisions (see [CMCPSE](../../cmcpse-course/README.md)). |

## Lab index

| Lab | Course exercise it twins | Tests |
|---|---|---|
| [minimal-agent-harness](labs/minimal-agent-harness/README.md) | Building a Minimal Agent Harness...; LibreChat twin | 11 |
| [model-sizing-calculator](labs/model-sizing-calculator/README.md) | Local models sized to VRAM; local vs cloud choice | 10 |
| [routing-proxy](labs/routing-proxy/README.md) | Routing Agent Requests to a Large Cloud Model via a Proxy... | 10 |
| [tool-calling-determinism](labs/tool-calling-determinism/README.md) | Comparing Tool-Calling Determinism Across Two Local Models... | 8 |
| [atlas-threat-model-agent](labs/atlas-threat-model-agent/README.md) | Threat Modeling an Agentic AI System Using MITRE ATLAS | 11 |
| [real-tools](real-tools/README.md) | LibreChat, Hermes, LiteLLM guides (hedged, not tested) | n/a |

Run everything in this chapter:

```text
.venv/Scripts/python -m pytest caase-course/ch1-agents-harnesses-and-the-agentic-ecosystem -q
```

## Learning order

1. [00](00-how-to-approach-this-course.md): your routine and lab habits (20 minutes).
2. [01 Agent vs LLM call](01-agent-vs-llm-call.md), then run [minimal-agent-harness](labs/minimal-agent-harness/README.md).
3. [02 Anatomy of a harness](02-anatomy-of-an-agent-harness.md), then skim the [real-tools](real-tools/README.md) guides.
4. [03 Attack surface](03-agentic-attack-surface.md): draw the pipeline from memory.
5. [04 Frameworks](04-threat-modeling-and-risk-frameworks.md), then [atlas-threat-model-agent](labs/atlas-threat-model-agent/README.md).
6. [05 Free and open toolchain](05-free-open-agentic-toolchain.md), then the sizing, routing and determinism labs.
7. Do the course's browser-lab exercises, then the 15 questions below. Then read [05-agent-security](../../05-agent-security/README.md), which previews the defenses in later chapters.

## Exam tips for this chapter

- **Know the loop and the parts by heart:** plan, act, observe, update; and the eight harness parts (model client, prompt assembly, tool registry and MCP client, memory, policy and approval, loop control and budgets, logging, process and identity).
- **Say "the model proposes, the harness decides".** It is the one sentence behind most answers.
- **Learn ASI01 to ASI10 by name** and one example each; also learn the 2026 LLM list and what changed from 2023.
- **ATLAS:** the 14 tactics in order, plus the "outdated" note (renames, about 16 tactics).
- **NIST AI 100-2:** five dimensions; AI RMF: Govern, Map, Measure, Manage.
- **Sizing:** be able to compute a model's memory by hand: parameters x bytes per weight + KV cache + overhead.
- **Routing risks:** data leaves your boundary, provider logging, model substitution, key and cost abuse.
- **Do not memorize counts** (skills flagged, instances exposed, stars). Say "as reported, verify".
- Common mistakes: calling reflection a security control; thinking the model enforces permissions; trusting a caller's "public" label; saying a schema-valid call is a safe call.

## 15 exam and interview questions

<details><summary><b>Q1. What makes an agent different from an LLM call?</b></summary>
An LLM call turns one prompt into one reply. An agent runs the model in a loop with tools: it plans a step, acts through a tool, observes the result and repeats until a stop rule. It has side effects, state and autonomy, so a fooled model causes a wrong action, not just wrong text.
</details>

<details><summary><b>Q2. Describe the plan, act, observe loop and where each step can be attacked.</b></summary>
Plan: injected text changes the goal. Act: a valid tool is misused or called with harmful arguments. Observe: tool output carries hidden instructions. Update: poisoned notes persist. Stop: runaway loops and cost. Controls are code outside the model: schemas, allowlists, approval, provenance, budgets and loop detection.
</details>

<details><summary><b>Q3. Compare chatbots, copilots, agents and autonomous agents.</b></summary>
A chatbot answers; a copilot proposes and the human accepts each action; an agent pursues a goal with tools and acts within limits; an autonomous agent runs with little or no human in the loop. Higher autonomy means less time for a person to catch a mistake, so impact and the need for hard controls rise.
</details>

<details><summary><b>Q4. What is a planner-executor-verifier pattern, and what is its security pitfall?</b></summary>
A planner proposes steps, an executor runs them, a verifier checks results against the goal and rules. The pitfall is a verifier that is another LLM reading the same untrusted text, which can be fooled the same way. Use deterministic checks (schemas, policy, tests) and keep attacker text away from the verifier.
</details>

<details><summary><b>Q5. When would you choose a multi-agent system, and what risks do you add?</b></summary>
For separation of duties, specialist roles, parallel work or different models. It adds identities, message forgery, delegation chains, cascading failures and cost. Start with one agent or a fixed workflow. Authenticate and check every inter-agent message.
</details>

<details><summary><b>Q6. What does an agent harness wrap around a model?</b></summary>
Model client, prompt assembly, tool registry and MCP client, memory, policy and approval, loop control and budgets, logging, and the process and identity around it (OS user, secrets, network, config, updates). It is where permissions, approvals, limits and logs live.
</details>

<details><summary><b>Q7. Name some real-world harnesses and one security lesson from the OpenClaw ecosystem.</b></summary>
Hermes Agent (Nous Research), OpenClaw and its spin-offs, OpenCode, LibreChat, Claude Code and others (hedged, verify). OpenClaw lessons: a skill marketplace is a supply chain (ClawHavoc malicious skills), gateways must not be exposed with weak defaults, a token-theft CVE was patched so update promptly, and out-of-process sandboxing and policy enforcement are the hardening direction.
</details>

<details><summary><b>Q8. How do an agent runtime, an MCP server and the LLM differ?</b></summary>
The LLM proposes actions as text and is untrusted output. The runtime (the MCP host) is trusted code that decides, limits and holds secrets. An MCP server is a separate third-party program exposing tools. The model never calls a server directly; the runtime mediates.
</details>

<details><summary><b>Q9. What is the "agentic layer" after the model and MCP tools?</b></summary>
The layer that holds goals, memory, tool chaining, computer use, delegation, agent identity, scheduling and autonomy, and operations. It adds risks such as goal hijack, memory poisoning, rogue agents and cascades that model-only and tool-only controls do not cover.
</details>

<details><summary><b>Q10. Name five trust boundaries and the check at each.</b></summary>
User to agent (authentication); untrusted content to context (provenance, data not instruction); model proposal to action (schema, policy, approval); harness to third-party tools (sandbox, least privilege); agent to agent (signatures, freshness, policy); harness to provider (classification, DLP); memory read and write (write gate, per-user scope).
</details>

<details><summary><b>Q11. List ASI01 to ASI10.</b></summary>
Agent Goal Hijack; Tool Misuse and Exploitation; Identity and Privilege Abuse; Agentic Supply Chain Vulnerabilities; Unexpected Code Execution; Memory and Context Poisoning; Insecure Inter-Agent Communication; Cascading Failures; Human-Agent Trust Exploitation; Rogue Agents. (OWASP Top 10 for Agentic Applications 2026; verify current text.)
</details>

<details><summary><b>Q12. What are the five dimensions of NIST AI 100-2 E2025, and how do ATLAS and the AI RMF differ from it?</b></summary>
AI system type, lifecycle stage, attacker goals, attacker capabilities and access, attacker knowledge. AI 100-2 is a vocabulary for classifying attacks. ATLAS is a knowledge base of adversary tactics and techniques with case studies. The AI RMF (Govern, Map, Measure, Manage) is a voluntary program framework for managing AI risk.
</details>

<details><summary><b>Q13. How do you rate an agentic risk beyond likelihood times impact?</b></summary>
Score autonomy level, reversibility, blast radius, privileges and data sensitivity for impact; exposure to untrusted input and missing controls for likelihood. Report inherent and residual risk with a written reason. The rating is a decision aid, not a measurement.
</details>

<details><summary><b>Q14. How much memory does a 7B model need at 4-bit, and does it fit a 16 GB laptop with no GPU?</b></summary>
Weights about 7 x 0.58, roughly 4 GB, plus a KV cache of about 1 GB at 8k tokens plus about 0.5 GB overhead, so about 6 GB in total. With about 6 GB reserved for the OS and apps, a 10 GB budget fits it, at a slow but usable CPU speed (several tokens per second). A 70B model does not fit and needs cloud or a server.
</details>

<details><summary><b>Q15. What are the security risks of an OpenRouter-style routing layer, and how do you control them?</b></summary>
Data leaves your boundary, providers may log or retain prompts, silent fallback can substitute another model, leaked keys cause cost abuse, and free tiers change. Controls: classification and DLP so confidential data stays local, model pinning and checking the served model, scoped keys with spending caps, provider terms review, and an audit log.
</details>

## References

- OWASP GenAI Security Project: LLM Top 10 (2026), Top 10 for Agentic Applications 2026, "Agentic AI: Threats and Mitigations": <https://genai.owasp.org> (verify).
- MITRE ATLAS: <https://atlas.mitre.org> (verify the version).
- NIST AI RMF 1.0 (AI 100-1), Generative AI Profile (AI 600-1), AI 100-2 E2025: <https://www.nist.gov/itl/ai-risk-management-framework> and <https://csrc.nist.gov> (verify editions).
- CISA and partner agencies, "Careful Adoption of Agentic AI Services" (1 May 2026; verify title and details).
- Hermes Agent documentation: <https://hermes-agent.nousresearch.com> (verify). LibreChat: <https://www.librechat.ai/docs>. OpenRouter: <https://openrouter.ai/docs>. LiteLLM: <https://docs.litellm.ai>. Ollama and llama.cpp documentation.
- Yao et al., "ReAct" (2022); Anthropic, "Building effective agents" (2024).
- Repo: [05-agent-security](../../05-agent-security/README.md), [04-mcp-security](../../04-mcp-security/README.md), [CAISP companion](../../caisp-course/README.md), [CMCPSE companion](../../cmcpse-course/README.md).
