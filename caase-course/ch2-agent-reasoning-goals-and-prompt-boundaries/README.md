# Chapter 2: Agent Reasoning, Goals and Prompt Boundaries

This chapter teaches how an agent's reasoning loop is attacked and defended: where untrusted text enters, how prompt injection works against agents (including multi-hop and encoded forms), how jailbreaks, prompt leaks and goal hijacks work, and how to keep goals intact with constrained plans, structured output, guardrails and fail-safe design. Seven offline labs (six exercises plus one supporting demo) let you attack first and then defend.

> **Safety.** Every lab is a simulation: a deterministic gullible mock model, canary secrets, fake keys, `.example` domains, and a harmless `UNSAFE_CONTENT` marker instead of real harmful content. Nothing opens a network connection. Never test a system you do not own or have written permission to test.

## Syllabus coverage

Every line of the chapter syllabus appears below, in order. Topics are in bold; sub-topics and exercises follow them. The generic material that already existed in this repo is linked from the lessons.

| Syllabus item | Where to study | Lab |
|---|---|---|
| **Input and Output Boundary Enforcement** | [Lesson 01](01-input-and-output-boundaries.md); repo [prompt injection](../../02-llm-security/prompt-injection/README.md) | [01](labs/01-planning-loop-injection/README.md), [05](labs/05-guardrail-model/README.md) |
| Where untrusted input enters an agent's reasoning loop | [01, section 2.1](01-input-and-output-boundaries.md#21-where-untrusted-input-enters-an-agent-reasoning-loop), diagrams [loop and checkpoints](../../images/caase-ch2-agent-loop-boundaries.svg), [trust zones](../../images/caase-ch2-trust-zones.svg) | [01](labs/01-planning-loop-injection/README.md) |
| What an agent is allowed to emit, trigger, or act on | [01, section 2.2](01-input-and-output-boundaries.md#22-what-an-agent-may-emit-trigger-or-act-on) (the allowed-actions table) | [01](labs/01-planning-loop-injection/README.md) (`_gate`), [05](labs/05-guardrail-model/README.md) |
| **The Prompt Injection Taxonomy for Agents** | [Lesson 02](02-prompt-injection-taxonomy-for-agents.md); repo [prompt injection](../../02-llm-security/prompt-injection/README.md), CAISP [prompt-injection levels](../../caisp-course/ch3-llm-top-10-vulnerabilities/labs/prompt-injection-levels/README.md) | [01](labs/01-planning-loop-injection/README.md), [07](labs/07-encoding-and-refusal-suppression-demo/README.md) |
| Direct vs. indirect prompt injection | [02, section 2.1](02-prompt-injection-taxonomy-for-agents.md#21-direct-vs-indirect-prompt-injection) | [01](labs/01-planning-loop-injection/README.md) |
| Chained and multi-hop injection across tool outputs | [02, section 2.2](02-prompt-injection-taxonomy-for-agents.md#22-chained-and-multi-hop-injection-across-tool-outputs); repo [CMCPSE lab 05](../../cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/05-cross-server-privesc/README.md) | [01](labs/01-planning-loop-injection/README.md) (multi-hop chain) |
| Multi-language and encoding-based injection | [02, section 2.3](02-prompt-injection-taxonomy-for-agents.md#23-multi-language-and-encoding-based-injection) | [07](labs/07-encoding-and-refusal-suppression-demo/README.md) (base64, homoglyphs, zero-width, translation) |
| Refusal suppression and instruction-override techniques | [02, section 2.4](02-prompt-injection-taxonomy-for-agents.md#24-refusal-suppression-and-instruction-override-techniques) | [07](labs/07-encoding-and-refusal-suppression-demo/README.md) |
| **Attacking the Reasoning Loop** | [Lesson 03](03-attacking-the-reasoning-loop.md); repo [jailbreak](../../02-llm-security/jailbreak/README.md), [data leakage](../../02-llm-security/data-leakage/README.md) | [02](labs/02-jailbreak-local-agent/README.md), [03](labs/03-prompt-leaking/README.md), [04](labs/04-goal-hijack/README.md) |
| Jailbreaking an agent vs. jailbreaking a model | [03, section 2.1](03-attacking-the-reasoning-loop.md#21-jailbreaking-an-agent-vs-jailbreaking-a-model); CAISP [system vs user prompts](../../caisp-course/ch3-llm-top-10-vulnerabilities/labs/system-vs-user-prompts/README.md) | [02](labs/02-jailbreak-local-agent/README.md) |
| Prompt leaking of system instructions, goals, and hidden context | [03, section 2.2](03-attacking-the-reasoning-loop.md#22-prompt-leaking-of-system-instructions-goals-and-hidden-context) | [03](labs/03-prompt-leaking/README.md) |
| Goal hijacking and objective substitution | [03, section 2.3](03-attacking-the-reasoning-loop.md#23-goal-hijacking-and-objective-substitution); repo [permissions, refund agent](../../05-agent-security/permissions/README.md) | [04](labs/04-goal-hijack/README.md) |
| Agent hijacking: redirecting an autonomous task mid-execution | [03, section 2.4](03-attacking-the-reasoning-loop.md#24-agent-hijacking-redirecting-an-autonomous-task-mid-execution) | [04](labs/04-goal-hijack/README.md) (signed redirects) |
| **Defending Agent Goals and Reasoning** | [Lesson 04](04-defending-goals-and-reasoning.md); repo [05 agent security](../../05-agent-security/README.md) | [01](labs/01-planning-loop-injection/README.md), [04](labs/04-goal-hijack/README.md), [05](labs/05-guardrail-model/README.md), [06](labs/06-objective-drift-detection/README.md) |
| Secure agent development patterns | [04, section 2.1](04-defending-goals-and-reasoning.md#21-secure-agent-development-patterns) | [01](labs/01-planning-loop-injection/README.md), [04](labs/04-goal-hijack/README.md) |
| Constrained planning | [04, section 2.2](04-defending-goals-and-reasoning.md#22-constrained-planning) | [01](labs/01-planning-loop-injection/README.md) (`allowed_tools`) |
| Structured output enforcement | [04, section 2.3](04-defending-goals-and-reasoning.md#23-structured-output-enforcement) | [06](labs/06-objective-drift-detection/README.md) |
| Guardrail frameworks and policy layers around the reasoning loop | [04, section 2.4](04-defending-goals-and-reasoning.md#24-guardrail-frameworks-and-policy-layers-around-the-reasoning-loop); repo [CMCPSE AI firewall](../../cmcpse-course/ch4-defending-and-hardening-mcp-servers/labs/mcp-ai-firewall/README.md) | [05](labs/05-guardrail-model/README.md) |
| Goal-integrity checks and objective-drift detection | [04, section 2.5](04-defending-goals-and-reasoning.md#25-goal-integrity-checks-and-objective-drift-detection) | [06](labs/06-objective-drift-detection/README.md), [04](labs/04-goal-hijack/README.md) |
| Designing agents that fail safely when reasoning is compromised | [04, section 2.6](04-defending-goals-and-reasoning.md#26-designing-agents-that-fail-safely-when-reasoning-is-compromised), diagram [fail-safe states](../../images/caase-ch2-fail-safe-states.svg) | [06](labs/06-objective-drift-detection/README.md) (fail-safe tests), [05](labs/05-guardrail-model/README.md) (fail closed) |
| **Hands-on Exercises:** | [Lab index](#lab-index) | all labs |
| Prompt Injecting an Agent's Planning Loop via a Tool Response | [02, sections 2.1 and 2.2](02-prompt-injection-taxonomy-for-agents.md#22-chained-and-multi-hop-injection-across-tool-outputs) | [01-planning-loop-injection](labs/01-planning-loop-injection/README.md) |
| Jailbreaking a Local Agent's Underlying Model | [03, section 2.1](03-attacking-the-reasoning-loop.md#21-jailbreaking-an-agent-vs-jailbreaking-a-model) | [02-jailbreak-local-agent](labs/02-jailbreak-local-agent/README.md) |
| Leaking an Agent's System Prompt and Hidden Objectives | [03, section 2.2](03-attacking-the-reasoning-loop.md#22-prompt-leaking-of-system-instructions-goals-and-hidden-context) | [03-prompt-leaking](labs/03-prompt-leaking/README.md) |
| Hijacking an Agent's Goal Mid-Task | [03, sections 2.3 and 2.4](03-attacking-the-reasoning-loop.md#23-goal-hijacking-and-objective-substitution) | [04-goal-hijack](labs/04-goal-hijack/README.md) |
| Adding a Guardrail Model to Filter Agent Input/Output | [04, section 2.4](04-defending-goals-and-reasoning.md#24-guardrail-frameworks-and-policy-layers-around-the-reasoning-loop) | [05-guardrail-model](labs/05-guardrail-model/README.md) |
| Detecting Objective Drift Through Structured Output Validation | [04, sections 2.3, 2.5, 2.6](04-defending-goals-and-reasoning.md#25-goal-integrity-checks-and-objective-drift-detection) | [06-objective-drift-detection](labs/06-objective-drift-detection/README.md) |

## Outdated in the syllabus → current

> **Verify at source.** The AI security field renames and re-orders its lists every year. Use the current names in exams and reports, and quote the syllabus name only if the exam does.

| Syllabus wording or older idea | Current state (Nov 2026; verify at source) |
|---|---|
| "Prompt leaking" and "system prompt leakage" | OWASP LLM Top 10 **2025** called it LLM07 System Prompt Leakage; the **2026** list calls it **LLM08 Hidden Context Exposure** (it covers system prompts, goals and other hidden context). |
| Prompt injection as one model-level problem | OWASP **Top 10 for Agentic Applications 2026** puts **ASI01 Agent Goal Hijack** first and adds ASI02 Tool Misuse, ASI06 Memory and Context Poisoning, ASI09 Human-Agent Trust Exploitation, ASI10 Rogue Agents. Map attacks to both lists. |
| Keyword filters as a safety layer | They are shown here only because they are easy to bypass. Current practice: instruction-hierarchy training in models, classifier guard models, and above all deterministic policy around tool calls. |
| "Guardrail frameworks" as a fixed list | The tooling changes quickly (NeMo Guardrails, Guardrails AI, LLM Guard, Llama Guard and Prompt Guard families, cloud prompt-shield services). Learn the **stages and the fail-closed contract**, then check the current tools. |
| Agent hijacking as a research term | NIST has evaluated agent hijacking, and the NIST AI Agent Standards Initiative (launched Feb 2026) and the Five Eyes guidance "Careful Adoption of Agentic AI Services" (1 May 2026) treat agent goal and privilege abuse as core risks. Hedge details. |
| Local models and "agents" on a laptop | Open-source harnesses such as **Hermes Agent** (Nous Research, 2026) and **OpenClaw** exist, with their own incidents (see Chapter 1 and Chapter 4). Small 1-4B models run on CPU for practice; their safety is thin. |
| MITRE ATLAS tactic names | ATLAS renamed "ML Model Access" and "ML Attack Staging" to **AI** Model Access and AI Attack Staging; check atlas.mitre.org for the current tactic list. |

## Lab index

Run everything: `.venv/Scripts/python -m pytest caase-course/ch2-agent-reasoning-goals-and-prompt-boundaries` (66 tests, about 1 second). Each lab has a `demo.py` with real output pasted in its README. Every lab is **self-contained** and shows a vulnerable and a defended version. The agent in each lab is a `MockLLM` subclass: deterministic and gullible on purpose.

| Lab | Exercise | Vulnerable behavior | Defended behavior | Tests |
|---|---|---|---|---|
| [01-planning-loop-injection](labs/01-planning-loop-injection/README.md) | Planning-loop injection via a tool response, single hop and multi-hop | A page steers the planner; a 4-step chain leaks private notes | Spotlight, taint gate, egress allowlist, constrained plan (each tested alone) | 9 |
| [02-jailbreak-local-agent](labs/02-jailbreak-local-agent/README.md) | Jailbreaking a local agent's model | Role-play, base64, homoglyph and zero-width bypass a keyword filter, and the agent publishes the result | Normalize, role-play-aware filter, output scan, publish gate | 11 |
| [03-prompt-leaking](labs/03-prompt-leaking/README.md) | Leaking the system prompt and hidden objectives (LLM08:2026) | Override, paraphrase and error-echo leak a canary and the hidden objective | No secrets in the prompt, overlap filter, generic errors | 9 |
| [04-goal-hijack](labs/04-goal-hijack/README.md) | Hijacking a goal mid-task | A report block replaces the goal and records are deleted | Objective lock, goal-to-tool allowlist, approval, signed redirect | 9 |
| [05-guardrail-model](labs/05-guardrail-model/README.md) | A guardrail model on input and output | No guard, or a guard that fails open | Guard at three stages, strict contract, fail closed | 10 |
| [06-objective-drift-detection](labs/06-objective-drift-detection/README.md) | Objective drift via structured output validation | A poisoned replan adds an e-mail step | Plan schema, goal-integrity checks, drift score, staged commit, fail-safe tests | 10 |
| [07-encoding-and-refusal-suppression-demo](labs/07-encoding-and-refusal-suppression-demo/README.md) | Supporting demo for lesson 02 (not a syllabus exercise) | English-only detector misses base64, homoglyph, zero-width, translation | Normalizing detector, translation table, refusal-suppression rule, honest gap | 8 |

Existing repo labs that go with this chapter: [prompt-injection lab](../../02-llm-security/prompt-injection/lab/), [jailbreak lab](../../02-llm-security/jailbreak/lab/), [data-leakage lab](../../02-llm-security/data-leakage/lab/), [permissions lab and refund agent](../../05-agent-security/permissions/lab/), [red-team harness](../../02-llm-security/security-testing/lab/), [CAISP prompt-injection levels](../../caisp-course/ch3-llm-top-10-vulnerabilities/labs/prompt-injection-levels/README.md), [CAISP system vs user prompts](../../caisp-course/ch3-llm-top-10-vulnerabilities/labs/system-vs-user-prompts/README.md), [CMCPSE tool-response injection](../../cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/03-tool-response-injection/README.md).

## Learning order

1. [Lesson 01](01-input-and-output-boundaries.md), then [lab 01](labs/01-planning-loop-injection/README.md) (about 4 hours). Fill in the allowed-actions table for an agent you use.
2. [Lesson 02](02-prompt-injection-taxonomy-for-agents.md) with [lab 07](labs/07-encoding-and-refusal-suppression-demo/README.md) (about 4 hours).
3. [Lesson 03](03-attacking-the-reasoning-loop.md) with labs [02](labs/02-jailbreak-local-agent/README.md), [03](labs/03-prompt-leaking/README.md), [04](labs/04-goal-hijack/README.md) (about 8 hours).
4. [Lesson 04](04-defending-goals-and-reasoning.md) with labs [05](labs/05-guardrail-model/README.md) and [06](labs/06-objective-drift-detection/README.md) (about 6 hours).
5. Read the repo [05 agent security](../../05-agent-security/README.md) module in parallel, then go to [Chapter 3](../ch3-agent-memory-context-and-tool-use/README.md).

## Mapping to OWASP (verify at source)

| ID | Name | Where in this chapter |
|---|---|---|
| LLM01:2026 | Prompt Injection | Lesson 02; labs 01, 07 |
| LLM02:2026 | Sensitive Information Disclosure | Lesson 03; lab 03 |
| LLM03:2026 | Excessive Agency | Lesson 01 (allowed actions), lesson 04; labs 01, 04 |
| LLM06:2026 | Unbounded Consumption | Lesson 04 (budgets); lab 01 (step limit) |
| LLM08:2026 | Hidden Context Exposure | Lesson 03; lab 03 |
| LLM10:2026 | Improper Output Handling | Lesson 01 (output boundary); lab 05 |
| ASI01 | Agent Goal Hijack | Lesson 03; labs 04, 06 |
| ASI02 | Tool Misuse and Exploitation | Lesson 01; lab 01 |
| ASI09 | Human-Agent Trust Exploitation | Lesson 04 (approval); lab 04 |
| ASI10 | Rogue Agents | Lesson 04 (fail-safe, kill switch); lab 06 |

## Exam tips

- **The model proposes, code disposes.** Any answer that depends on the model "behaving" is weak. Name the deterministic control.
- **Direct vs indirect:** direct uses the attacker's own rights; indirect borrows the victim's. The second is the agent problem.
- **Multi-hop:** no single piece looks like an attack. Defend the whole run: constrained plan, taint gate, egress list, budgets.
- **Detectors are tripwires.** Say what each cannot see (other languages, new encodings, images).
- **Leaks:** "put no secrets in the prompt" is the strongest answer; filters and canaries are secondary.
- **Goal lock is not enough:** it protects the field, not the world. Pair it with a goal-to-tool allowlist and approvals.
- **Fail closed, fail safe:** error in a validator or guard means stop and discard staged effects. Test the failure path.
- **Names:** use the 2026 OWASP names; mention the 2025 or syllabus name once.

## 15 exam-style questions

<details>
<summary>1. Where does untrusted input enter an agent's reasoning loop? Give six places.</summary>

The user turn, tool results, tool descriptions and schemas, retrieved documents, long-term memory, messages from other agents, multimodal input, and the environment (file names, command output). Only the system configuration and the authenticated user channel carry authority.
</details>

<details>
<summary>2. What are the four checkpoints around an agent loop?</summary>

Before the model (label, normalize, spotlight, guard), around the plan (constrained plan, budgets), around each tool call (schema, allowed actions, taint, egress, approval), after the model (secret and canary scan, link and image handling, encoding for the next system).
</details>

<details>
<summary>3. Compare direct and indirect prompt injection for an agent.</summary>

Direct: the user's own input, the attacker's own rights, aims at jailbreaks and leaks. Indirect: third-party content in tool results, documents, memory, mail; it uses the victim's authority and the victim does not see it. Controls for indirect: taint, approval, egress allowlist, least privilege.
</details>

<details>
<summary>4. Describe a multi-hop injection and which controls stop it.</summary>

Page 1 only redirects, page 2 carries the instruction, the final step uses a legitimate tool (read notes, send e-mail). Stopped by a constrained task plan (no read or send tools), a taint gate (no side effect after untrusted content without approval), an egress allowlist, and a hop or step budget.
</details>

<details>
<summary>5. Name four ways to hide an instruction and one defense for each.</summary>

Base64 (decode spans before scanning), homoglyphs (NFKC and confusables fold), zero-width characters (strip), translation (multilingual rules or, better, do not give text authority). Images and metadata: scan after extraction.
</details>

<details>
<summary>6. What is refusal suppression and why does it matter more for agents?</summary>

Text that tells the model not to refuse, apologize or warn. For an agent it removes the last model-side hesitation before an action, so the gates must live outside the model. It is also a useful detection signal.
</details>

<details>
<summary>7. How does jailbreaking an agent differ from jailbreaking a model?</summary>

A model jailbreak yields unsafe text; an agent jailbreak yields unsafe actions and can be delivered through unfiltered channels such as tool results or memory. Fix in the harness: tool gates, publish gates, output scans, approvals.
</details>

<details>
<summary>8. How would you stop an agent leaking its system prompt?</summary>

Keep secrets and enforceable rules out of the prompt (server-side tools decide). Then add output overlap filters, canaries, generic error messages and monitoring. Assume the prompt will leak and make that boring.
</details>

<details>
<summary>9. Which OWASP 2026 entry covers prompt leakage, and what was it called before?</summary>

LLM08:2026 Hidden Context Exposure; it was LLM07:2025 System Prompt Leakage. (Verify at genai.owasp.org.)
</details>

<details>
<summary>10. What is objective substitution and how do you prevent it?</summary>

The goal sits in the same text stream as data, and a "new goal" in data replaces it. Prevent it with an objective lock (goal in code), a goal-to-tool allowlist tied to the user's goal, approvals for destructive tools, and signed redirects from the user channel.
</details>

<details>
<summary>11. How should an agent accept a legitimate mid-task redirect?</summary>

Only through an authenticated, signed or session-bound message from the user interface. Tool output cannot change the goal. Log every redirect and re-validate the plan after it.
</details>

<details>
<summary>12. What is constrained planning, and which lab shows it?</summary>

Limiting a plan before it runs: per-task tool set, plan schema, step and cost budgets, plan approval, no self-expansion. Lab 01's `allowed_tools` stops the multi-hop chain by itself.
</details>

<details>
<summary>13. What does "fail closed" mean for a guardrail model, and what are the costs?</summary>

If the guard errors, times out or breaks its output contract, block. Cost: availability (benign requests blocked during an outage) and latency. Fail open turns an outage or an attack on the guard into a bypass.
</details>

<details>
<summary>14. How do you detect objective drift with structured output?</summary>

Fix the objective (id, digest, allowed tools, bounds). Require a strict schema for plans and replans. Check each step against the objective, compute a drift score, stage side effects, halt above a threshold. Add fail-safe tests for validator crashes and unparseable output.
</details>

<details>
<summary>15. A guard model catches 98% of your test injections. What do you still need?</summary>

Deterministic controls (tool allowlist per task, taint and approval, egress allowlist, argument validation, budgets), logging with canaries, a kill switch, and measurement of false positives and of attacks outside the test set. A classifier is one layer.
</details>

## References

- OWASP GenAI Security Project: LLM Top 10 (2026) and Top 10 for Agentic Applications 2026 (genai.owasp.org). Verify at source.
- MITRE ATLAS (atlas.mitre.org); NIST AI RMF 1.0 and the Generative AI Profile (AI 600-1); NIST AI 100-2 E2025.
- CISA and partner agencies, "Careful Adoption of Agentic AI Services" (1 May 2026; hedge exact title and details).
- Greshake et al., "Not what you've signed up for" (2023); "Design Patterns for Securing LLM Agents against Prompt Injections" (2025).
- Repo: [02 LLM security](../../02-llm-security/README.md), [05 agent security](../../05-agent-security/README.md), [CAISP chapter 3](../../caisp-course/ch3-llm-top-10-vulnerabilities/README.md), [CMCPSE chapter 4](../../cmcpse-course/ch4-defending-and-hardening-mcp-servers/README.md).
