# Chapter 3: Agent Memory, Context and Tool Use

This chapter teaches how an agent's memory, context and tool interfaces are attacked and defended: how long-term memory and RAG sources are poisoned, how context bleeds between sessions and users, how function-calling parameters and tool chains are abused, why a downloaded open-weight model is a tool-use risk, and how to sandbox tools, verify MCP integrity, scope privileges and investigate a compromised session. Eight offline labs (seven exercises plus one supporting demo) run without Docker, a network or a key.

> **Safety.** Every lab is a simulation: a deterministic gullible mock model, canary secrets, fake tokens and keys, `.example` domains, a toy backdoor with a harmless payload, and a Docker policy generator that never starts Docker. Real-tool guides (LibreChat, Docker, Hermes Agent) are hedged and optional. Never test a system you do not own or have written permission to test.

## Syllabus coverage

Every line of the chapter syllabus appears below, in order. Topics are in bold; sub-topics and exercises follow them.

| Syllabus item | Where to study | Lab |
|---|---|---|
| **Agent Memory and Context Stores** | [Lesson 01](01-agent-memory-and-context-stores.md); repo [permissions, memory section](../../05-agent-security/permissions/README.md), [RAG security](../../03-rag-security/README.md) | [01](labs/01-memory-poisoning/README.md), [02](labs/02-rag-source-poisoning/README.md) |
| Short-term memory vs. long-term/persistent memory | [01, section 2.1](01-agent-memory-and-context-stores.md#21-short-term-memory-vs-long-term-and-persistent-memory), diagram [memory and context map](../../images/caase-ch3-memory-context-map.svg) | [01](labs/01-memory-poisoning/README.md) |
| Context window management and context injection points | [01, section 2.2](01-agent-memory-and-context-stores.md#22-context-window-management-and-context-injection-points); CAISP [context exhaustion lab](../../caisp-course/ch3-llm-top-10-vulnerabilities/labs/model-dos-context-exhaustion/README.md) | [01](labs/01-memory-poisoning/README.md) (`Agent.say` prompt assembly) |
| RAG pipelines as an agent memory source | [01, section 2.3](01-agent-memory-and-context-stores.md#23-rag-pipelines-as-an-agent-memory-source); repo [RAG security](../../03-rag-security/README.md) | [02](labs/02-rag-source-poisoning/README.md) |
| **Attacking Memory and Context** | [Lesson 02](02-attacking-memory-and-context.md); repo [03 document security](../../03-rag-security/document-security/README.md), [access control](../../03-rag-security/access-control/README.md) | [01](labs/01-memory-poisoning/README.md), [02](labs/02-rag-source-poisoning/README.md) |
| Memory poisoning and long-term malicious persistence | [02, section 2.1](02-attacking-memory-and-context.md#21-memory-poisoning-and-long-term-malicious-persistence), diagram [persistence](../../images/caase-ch3-poisoning-persistence.svg) | [01](labs/01-memory-poisoning/README.md) |
| Cross-session and cross-user context bleed | [02, section 2.2](02-attacking-memory-and-context.md#22-cross-session-and-cross-user-context-bleed) | [01](labs/01-memory-poisoning/README.md) (`GlobalCache` vs `ScopedCache`) |
| Poisoning retrieval sources to influence future agent behavior | [02, section 2.3](02-attacking-memory-and-context.md#23-poisoning-retrieval-sources-to-influence-future-agent-behavior) | [02](labs/02-rag-source-poisoning/README.md) |
| **Attacking Tool and Function-Calling Interfaces** | [Lesson 03](03-attacking-tool-and-function-calling-interfaces.md); repo [MCP tool security](../../04-mcp-security/tool-security/README.md), [CMCPSE chapter 2](../../cmcpse-course/ch2-understanding-and-attacking-mcp-servers/README.md) | [03](labs/03-function-call-parameter-abuse/README.md), [04](labs/04-tool-chain-escalation/README.md), [08](labs/08-backdoored-tool-model-demo/README.md) |
| Function-calling abuse and parameter injection | [03, section 2.1](03-attacking-tool-and-function-calling-interfaces.md#21-function-calling-abuse-and-parameter-injection) | [03](labs/03-function-call-parameter-abuse/README.md) |
| Chaining tool calls to escalate privileges | [03, section 2.2](03-attacking-tool-and-function-calling-interfaces.md#22-chaining-tool-calls-to-escalate-privileges), diagram [closure](../../images/caase-ch3-tool-chain-closure.svg); repo [CMCPSE lab 05](../../cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/05-cross-server-privesc/README.md) | [04](labs/04-tool-chain-escalation/README.md) |
| Malicious open-weight models as a tool-use risk | [03, section 2.3](03-attacking-tool-and-function-calling-interfaces.md#23-malicious-open-weight-models-as-a-tool-use-risk); repo [model threats](../../02-llm-security/model-threats/README.md), [CAISP chapter 6](../../caisp-course/ch6-supply-chain-attacks-in-ai/README.md) | [08](labs/08-backdoored-tool-model-demo/README.md) |
| **Defending Memory, Context, and Tool Use** | [Lesson 04](04-defending-memory-context-and-tool-use.md); repo [05 sandboxing](../../05-agent-security/sandboxing/README.md), [monitoring and response](../../05-agent-security/monitoring-and-response/README.md) | [05](labs/05-docker-tool-sandbox/README.md), [06](labs/06-mcp-integrity-audit/README.md), [07](labs/07-session-reconstruction/README.md) |
| Tool-execution sandboxing and output validation | [04, section 2.1](04-defending-memory-context-and-tool-use.md#21-tool-execution-sandboxing-and-output-validation), diagram [sandbox layers](../../images/caase-ch3-sandbox-layers.svg) | [05](labs/05-docker-tool-sandbox/README.md) |
| MCP-level data integrity checks | [04, section 2.2](04-defending-memory-context-and-tool-use.md#22-mcp-level-data-integrity-checks); repo [CMCPSE defend-rug-pull](../../cmcpse-course/ch4-defending-and-hardening-mcp-servers/labs/defend-rug-pull/README.md) | [06](labs/06-mcp-integrity-audit/README.md) |
| Least-privilege tool scoping and allow-listing | [04, section 2.3](04-defending-memory-context-and-tool-use.md#23-least-privilege-tool-scoping-and-allow-listing); repo [CMCPSE least-privilege-tools](../../cmcpse-course/ch4-defending-and-hardening-mcp-servers/labs/least-privilege-tools/README.md) | [04](labs/04-tool-chain-escalation/README.md), [03](labs/03-function-call-parameter-abuse/README.md), [06](labs/06-mcp-integrity-audit/README.md) |
| Detecting a compromised agent after the fact | [04, section 2.4](04-defending-memory-context-and-tool-use.md#24-detecting-a-compromised-agent-after-the-fact), diagram [reconstruction](../../images/caase-ch3-session-reconstruction.svg); repo [CMCPSE tool-invocation-logging](../../cmcpse-course/ch4-defending-and-hardening-mcp-servers/labs/tool-invocation-logging/README.md) | [07](labs/07-session-reconstruction/README.md) |
| **Hands-on Exercises:** | [Lab index](#lab-index) | all labs |
| Poisoning an Agent's Long-Term Memory Store | [02, section 2.1](02-attacking-memory-and-context.md#21-memory-poisoning-and-long-term-malicious-persistence) | [01-memory-poisoning](labs/01-memory-poisoning/README.md) |
| Poisoning a RAG Source to Influence Future Agent Responses | [02, section 2.3](02-attacking-memory-and-context.md#23-poisoning-retrieval-sources-to-influence-future-agent-behavior) | [02-rag-source-poisoning](labs/02-rag-source-poisoning/README.md) |
| Abusing Function-Calling Parameters via LibreChat's MCP Tools | [03, section 2.1](03-attacking-tool-and-function-calling-interfaces.md#21-function-calling-abuse-and-parameter-injection) | [03-function-call-parameter-abuse](labs/03-function-call-parameter-abuse/README.md) (offline twin plus hedged LibreChat guide) |
| Chaining Tool Calls to Escalate an Agent's Effective Privilege | [03, section 2.2](03-attacking-tool-and-function-calling-interfaces.md#22-chaining-tool-calls-to-escalate-privileges) | [04-tool-chain-escalation](labs/04-tool-chain-escalation/README.md) |
| Sandboxing Tool Execution Using Docker | [04, section 2.1](04-defending-memory-context-and-tool-use.md#21-tool-execution-sandboxing-and-output-validation) | [05-docker-tool-sandbox](labs/05-docker-tool-sandbox/README.md) (policy generator, Dockerfile, hedged real run) |
| Auditing Hermes Agent's MCP Server Connections for Data Integrity | [04, section 2.2](04-defending-memory-context-and-tool-use.md#22-mcp-level-data-integrity-checks) | [06-mcp-integrity-audit](labs/06-mcp-integrity-audit/README.md) (offline twin plus hedged Hermes guide) |
| Reconstructing a Compromised Agent Session from Memory Artifacts | [04, section 2.4](04-defending-memory-context-and-tool-use.md#24-detecting-a-compromised-agent-after-the-fact) | [07-session-reconstruction](labs/07-session-reconstruction/README.md) |

## Outdated in the syllabus → current

> **Verify at source.** The field renames lists and tools often. Use current names in exams and reports.

| Syllabus wording or older idea | Current state (Nov 2026; verify at source) |
|---|---|
| "Memory poisoning" as a research curiosity | OWASP **Top 10 for Agentic Applications 2026** lists it as **ASI06 Memory and Context Poisoning**. OWASP LLM 2026 lists **LLM04 Data and Model Poisoning** and **LLM09 Vector and Embedding Weaknesses** (the 2025 list had these as LLM04 and LLM08). |
| "Function calling" and "plugins" | The tool layer is now mostly **MCP** (Model Context Protocol, in the Linux Foundation's Agentic AI Foundation since Dec 2025). The old "insecure plugin design" idea lives on as tool and MCP security, covered by OWASP LLM03 Excessive Agency, ASI02 and the OWASP MCP Top 10 (2025, beta). |
| MCP transports (if the course says "SSE") | Standard transports are **stdio** and **Streamable HTTP**; the old HTTP+SSE transport is deprecated. A 2026-07-28 spec revision appears to be the latest; check modelcontextprotocol.io. |
| LibreChat and Hermes as "labs" | Both are real and fast-moving. LibreChat: self-hosted chat UI with native MCP support, agents and RAG. Hermes Agent (Nous Research, launched Feb 2026, MIT): MCP client over stdio and HTTP with per-server tool filtering and `hermes mcp` commands. Read the current docs before following any guide. |
| "Malicious models" = a pickle file | Still true for pickle-based formats, but also: backdoored weights and adapters that emit malicious **tool calls** on a trigger, tampered conversions, and poisoned chat templates. Prefer safe formats (safetensors, GGUF), pinned hashes and signatures (OpenSSF model signing v1.0, 2025), and runtime gates. |
| "Docker sandbox" as the answer | Containers share the host kernel. For untrusted code and computer-use agents, add seccomp profiles, a user-space kernel (gVisor-style) or a **microVM**. The OpenClaw ecosystem added sandboxing layers such as NVIDIA's NemoClaw (kernel-level sandbox plus policy enforcement; hedge details). |
| "Detecting compromise" with model-side signals | Practice has moved to **tool-log, provenance and canary** forensics plus the agent kill switch and IR runbooks. NIST is working on agent standards (AI Agent Standards Initiative, Feb 2026; hedge). |

## Lab index

Run everything: `.venv/Scripts/python -m pytest caase-course/ch3-agent-memory-context-and-tool-use` (103 tests, about 3 seconds). Each lab has a `demo.py` with real output pasted in its README. Every lab is **self-contained**, shows a vulnerable and a defended version, and runs without Docker, a network or an API key.

| Lab | Exercise | Vulnerable behavior | Defended behavior | Tests |
|---|---|---|---|---|
| [01-memory-poisoning](labs/01-memory-poisoning/README.md) | Poisoning long-term memory (plus context bleed) | A page writes a false payment account; a later session pays it | Provenance-tagged memory: quarantine, MAC, TTL, purge, scoped caches | 11 |
| [02-rag-source-poisoning](labs/02-rag-source-poisoning/README.md) | Poisoning a RAG source | Keyword-stuffed upload ranks first and rewrites every later answer | Quarantine at ingest, trust-weighted ranking, min trust, citations | 11 |
| [03-function-call-parameter-abuse](labs/03-function-call-parameter-abuse/README.md) | Function-calling parameter abuse (LibreChat MCP twin) | SQL injection, foreign id, path traversal, extra parameters | Schema, bound parameters, session binding, path confinement | 12 |
| [04-tool-chain-escalation](labs/04-tool-chain-escalation/README.md) | Chaining tool calls to escalate privilege | Read `.env`, use the token, make an attacker admin | Closure analysis, path allowlist, redaction, identity authz, chain gate | 10 |
| [05-docker-tool-sandbox](labs/05-docker-tool-sandbox/README.md) | Sandboxing tool execution with Docker | Tool runs with the agent's rights, network and environment | `docker run` policy generator with refusal of unsafe policies; subprocess twin | 24 |
| [06-mcp-integrity-audit](labs/06-mcp-integrity-audit/README.md) | Auditing Hermes MCP connections | Unpinned, plain HTTP, no auth, literal key, wildcard tools | Config audit, definition pinning, signed results, replay check, hash chain | 17 |
| [07-session-reconstruction](labs/07-session-reconstruction/README.md) | Reconstructing a compromised session | A transcript that says "nothing unusual" | Timeline, chain verification, injection point, blast-radius score | 9 |
| [08-backdoored-tool-model-demo](labs/08-backdoored-tool-model-demo/README.md) | Supporting demo for malicious open-weight models | A trigger makes the model call an exfil tool | Artifact checks, per-task tool and egress allowlists, probing (and its limit) | 9 |

Existing repo labs that go with this chapter: [permissions lab](../../05-agent-security/permissions/lab/), [sandboxing lab](../../05-agent-security/sandboxing/lab/), [monitoring lab](../../05-agent-security/monitoring-and-response/lab/), [RAG document security lab](../../03-rag-security/document-security/lab/), [RAG access control lab](../../03-rag-security/access-control/lab/), [MCP tool-security lab](../../04-mcp-security/tool-security/lab/), [model-threats lab](../../02-llm-security/model-threats/lab/), [CMCPSE tool-invocation logging](../../cmcpse-course/ch4-defending-and-hardening-mcp-servers/labs/tool-invocation-logging/README.md), [CMCPSE AI firewall](../../cmcpse-course/ch4-defending-and-hardening-mcp-servers/labs/mcp-ai-firewall/README.md).

## Learning order

1. [Lesson 01](01-agent-memory-and-context-stores.md) (about 3 hours). List the memory stores of an agent you use.
2. [Lesson 02](02-attacking-memory-and-context.md) with labs [01](labs/01-memory-poisoning/README.md) and [02](labs/02-rag-source-poisoning/README.md) (about 7 hours).
3. [Lesson 03](03-attacking-tool-and-function-calling-interfaces.md) with labs [03](labs/03-function-call-parameter-abuse/README.md), [04](labs/04-tool-chain-escalation/README.md), [08](labs/08-backdoored-tool-model-demo/README.md) (about 9 hours).
4. [Lesson 04](04-defending-memory-context-and-tool-use.md) with labs [05](labs/05-docker-tool-sandbox/README.md), [06](labs/06-mcp-integrity-audit/README.md), [07](labs/07-session-reconstruction/README.md) (about 10 hours).
5. Optional real-tool guides: LibreChat (lab 03), Docker (lab 05), Hermes Agent (lab 06). Check disk space on D: first; the laptop has no GPU, so use cloud models for anything large.
6. Go to [Chapter 4](../ch4-computer-use-browser-and-coding-agents/README.md).

## Mapping to OWASP (verify at source)

| ID | Name | Where in this chapter |
|---|---|---|
| LLM03:2026 | Excessive Agency | Lessons 03 and 04 (scoping); labs 03, 04 |
| LLM04:2026 | Data and Model Poisoning | Lesson 02; labs 01, 02, 08 |
| LLM05:2026 or the supply-chain entry | Supply Chain | Lesson 03 (open-weight models); lab 08, lab 06 |
| LLM09:2026 | Vector and Embedding Weaknesses | Lessons 01 and 02; lab 02 |
| ASI02 | Tool Misuse and Exploitation | Lesson 03; lab 03 |
| ASI03 | Identity and Privilege Abuse | Lesson 03 (chains); lab 04 |
| ASI04 | Agentic Supply Chain Vulnerabilities | Lessons 03 and 04; labs 06, 08 |
| ASI05 | Unexpected Code Execution | Lesson 04 (sandboxing); lab 05 |
| ASI06 | Memory and Context Poisoning | Lessons 01 and 02; labs 01, 02 |
| ASI08 | Cascading Failures | Lesson 04 (blast radius); lab 07 |
| MCP03, MCP04, MCP08 (OWASP MCP Top 10, 2025 beta) | Tool Poisoning, Supply Chain, Lack of Audit and Telemetry | Lesson 04; labs 06, 07 |

## Exam tips

- **Memory:** the defense is **provenance** (source, trust, time, session, MAC) plus quarantine, scoping, expiry and purge. Say "persistence" when you explain why it is worse than one-shot injection.
- **RAG poisoning:** name the three ingest controls (source approval, quarantine, stuffing and injection checks) and the three query controls (trust weighting, min trust, citations). Add corroboration for a compromised trusted source.
- **Parameters:** schema validation is necessary and not sufficient. Authorization comes from the session, not from an argument.
- **Chaining:** effective privilege is the **closure**. Review it against a ceiling. A stolen token fails if authorization is identity-based.
- **Open-weight models:** provenance, safe formats, pinned hash and signature, sandbox, and runtime gates. Probing only finds triggers you guess.
- **Docker flags:** memorize `--network none --read-only --user <non-root> --cap-drop ALL --security-opt no-new-privileges` plus memory, CPU and PID limits, and say that a container is not a microVM.
- **Integrity:** pin versions and definition hashes; sign or hash results at a gateway; keep a hash-chained log. A plain hash cannot attribute; a signature can.
- **Forensics:** timeline, integrity check, injection point, first anomaly, blast radius, containment, learning. You cannot reconstruct what you did not log.

## 15 exam-style questions

<details>
<summary>1. Compare short-term and long-term agent memory from a security view.</summary>

Short-term is the context window of one session: in-session injection, overflow, leakage into outputs. Long-term survives sessions: persistence of poison, cross-user bleed, stale facts, privacy. Controls shift to provenance, scoping, expiry and integrity for long-term memory.
</details>

<details>
<summary>2. List five context injection points.</summary>

System prompt, memory recall, retrieved documents, tool results, conversation history, project and rules files, and compaction summaries that launder untrusted text.
</details>

<details>
<summary>3. Why is memory poisoning worse than a one-shot prompt injection?</summary>

The write persists. Later sessions read it as the agent's own knowledge, the attacker is absent, and cause and effect are far apart in time and logs. It can also spread through shared memory.
</details>

<details>
<summary>4. Design a poisoning-resistant memory store.</summary>

Provenance on every entry, quarantine for untrusted sources, sensitive keys only from the authenticated user channel or after approval, per-user scoping, an integrity MAC, TTL, purge-by-source, review UI and logs of reads and writes.
</details>

<details>
<summary>5. Give three causes of cross-user context bleed.</summary>

Loose cache keys, a shared vector index without an enforced filter, global memory, predictable session ids, shared workspaces. Fixes: key by tenant and user, enforce filters in the retrieval layer, per-user stores.
</details>

<details>
<summary>6. How does a poisoned RAG source change future agent answers, and how do you stop it?</summary>

A low-trust source adds a keyword-stuffed or instruction-carrying document that outranks the real one. Stop it with source approval, quarantine at ingest, trust-weighted ranking with capped term counts, a minimum trust for policy answers, and citations. For a compromised approved source add corroboration and review.
</details>

<details>
<summary>7. List five parameter-level bug classes in tool calls and a fix for each.</summary>

SQL injection (bound parameters), object-level authorization bypass (session-derived identity), path traversal (resolve and confine), command injection (argv arrays), SSRF (URL allowlist and IP checks), extra parameters (`additionalProperties: false`), type confusion (strict types).
</details>

<details>
<summary>8. Why is schema validation not enough for tool parameters?</summary>

A valid-looking value can still be wrong: customer id "2" matches the pattern but belongs to someone else; a valid filename can still point to a secret. You need authorization from the session, safe execution and confinement as well.
</details>

<details>
<summary>9. What is effective privilege in an agent and how do you compute it?</summary>

Everything reachable by chaining the granted tools. Model each tool's needed and yielded capabilities and compute the fixpoint (closure); compare with a ceiling in review or CI.
</details>

<details>
<summary>10. Why does identity-based authorization defeat a stolen-token chain?</summary>

The server decides from the authenticated caller and its role, not from a token passed as an argument, so a string found in a file does not make the caller an admin.
</details>

<details>
<summary>11. What is the specific risk of a backdoored open-weight model in an agent?</summary>

On a rare trigger (in the prompt or in retrieved text) it can emit malicious tool calls, so the backdoor can exfiltrate data or act. Defend with provenance, safe formats, pinned hashes, sandboxing, per-task tool and egress allowlists, and differential tests that you know are incomplete.
</details>

<details>
<summary>12. List the Docker flags for a hardened agent tool and what each prevents.</summary>

`--network none` (exfiltration), `--read-only` (persistence), non-root `--user` (privilege), `--cap-drop ALL` (kernel capabilities), `no-new-privileges` (setuid escalation), memory, CPU and PID limits (resource abuse), `noexec` tmpfs (running dropped files), read-only mounts from allowed roots (host access, never the Docker socket).
</details>

<details>
<summary>13. What do you check when auditing an agent's MCP server connections?</summary>

Exact versions and package integrity hashes, tool-definition hashes, HTTPS and authentication for remote servers, secrets by reference, tool allowlists, bind addresses, deprecated transports, definition drift on every connect and `list_changed`, and signed or hashed results with replay protection.
</details>

<details>
<summary>14. What is the difference between a signed and a hashed MCP result?</summary>

A signature proves origin and integrity with a key; a plain hash only detects later change of a stored copy and can be recomputed by anyone who can alter the result.
</details>

<details>
<summary>15. Outline how to reconstruct a compromised agent session.</summary>

Collect and preserve transcript, tool log and memory; verify the hash chain; merge a timeline; find the injection point (first untrusted result with instruction-like text followed by an off-policy action) and the first anomaly; score the blast radius (secrets exposed and sent, tainted memory, off-policy calls); contain (kill switch, rotate secrets, purge memory and source); add a regression test and a detection rule.
</details>

## References

- OWASP GenAI Security Project: LLM Top 10 (2026), Top 10 for Agentic Applications 2026 (ASI01 to ASI10), OWASP MCP Top 10 (2025, beta). Verify at source.
- Model Context Protocol specification (modelcontextprotocol.io/specification); the 2026-07-28 revision appears to be the latest.
- LibreChat documentation (librechat.ai); Hermes Agent documentation (hermes-agent.nousresearch.com); Docker `run` reference.
- Rehberger, J., agent memory attack write-ups (2024 to 2025); Zou et al., "PoisonedRAG" (2024); Hubinger et al., "Sleeper Agents" (2024).
- OpenSSF Model Signing (v1.0, 2025); CISA and partners, "Careful Adoption of Agentic AI Services" (1 May 2026; hedge details).
- Repo: [05 agent security](../../05-agent-security/README.md), [03 RAG security](../../03-rag-security/README.md), [04 MCP security](../../04-mcp-security/README.md), [CMCPSE chapter 4](../../cmcpse-course/ch4-defending-and-hardening-mcp-servers/README.md), [CAISP chapter 6](../../caisp-course/ch6-supply-chain-attacks-in-ai/README.md).
