# Chapter 1: Introduction to MCP and Agentic Ecosystem

This chapter gives you the vocabulary for the whole course: what MCP is, how hosts, clients and servers talk, where agents fit, and why this is a high-value target. It ends with hands-on labs where you build, connect to and observe an MCP server. All labs run offline, with tests.

## Syllabus coverage

Every syllabus line is listed in order. Sub-topics keep their own row.

| Syllabus item | Where to study | Lab |
|---|---|---|
| About the course, syllabus, and how to approach it | [00 How to approach this course](00-how-to-approach-this-course.md) | n/a |
| About the CMCPSE Certification and how to approach it | [00, section 3](00-how-to-approach-this-course.md#3-about-the-certification-generic-advice) (generic: check the course page for exam details) | n/a |
| Course Lab Environment | [00, section 4](00-how-to-approach-this-course.md#4-the-browser-based-lab-vs-this-repo) (browser lab vs this repo) | [real-sdk](real-sdk/README.md) |
| Lifetime course support (Mattermost) | [00, section 5](00-how-to-approach-this-course.md#5-course-support-on-mattermost-how-to-ask-good-questions) | n/a |
| An overview of MCP Security | [01 What is MCP](01-what-is-mcp.md), [04 MCP security, a first look](04-mcp-security-first-look.md) | n/a |
| What is MCP? | [01, section "What is MCP?"](01-what-is-mcp.md#what-is-mcp) | [lab 01](labs/01-install-configure-server/README.md) |
| The origin and history of MCP | [01, section "The origin and history of MCP"](01-what-is-mcp.md#the-origin-and-history-of-mcp) | n/a |
| The problem MCP was designed to solve | [01, section "The problem MCP was designed to solve: N x M"](01-what-is-mcp.md#the-problem-mcp-was-designed-to-solve-n-x-m) | n/a |
| MCP vs REST APIs vs function calling vs other integration patterns | [01, comparison table](01-what-is-mcp.md#mcp-vs-rest-vs-function-calling-vs-other-patterns) | n/a |
| The MCP ecosystem today: adoption, registries, and tooling | [01, section "The MCP ecosystem today"](01-what-is-mcp.md#the-mcp-ecosystem-today-adoption-registries-and-tooling), repo: [04-mcp-security/mcp-server](../../04-mcp-security/mcp-server/README.md) | [real-sdk](real-sdk/README.md) (SDK and Inspector) |
| MCP Architecture Deep Dive | [02 MCP architecture deep dive](02-mcp-architecture-deep-dive.md) | [labs 01 to 04](labs/01-install-configure-server/README.md) |
| The three-tier model: Hosts, Clients, and Servers | [02, section "The three-tier model"](02-mcp-architecture-deep-dive.md#the-three-tier-model-hosts-clients-and-servers) (SVG) | [lab 02](labs/02-connect-local-server/README.md) |
| The three primitives: Tools, Resources, and Prompts | [02, section "The three primitives"](02-mcp-architecture-deep-dive.md#the-three-primitives-tools-resources-and-prompts) (plus client features: sampling, roots, elicitation) | [lab 04](labs/04-build-server-tools-resources/README.md) |
| Transport mechanisms: stdio, SSE, and HTTP with SSE | [02, section "Transport mechanisms"](02-mcp-architecture-deep-dive.md#transport-mechanisms-stdio-sse-and-http-with-sse) (SSE is deprecated and historic; Streamable HTTP is current) | [lab 01](labs/01-install-configure-server/README.md) (stdio) |
| The JSON-RPC 2.0 protocol layer | [02, section "The JSON-RPC 2.0 protocol layer"](02-mcp-architecture-deep-dive.md#the-json-rpc-20-protocol-layer) (real message examples) | [lab 01](labs/01-install-configure-server/README.md), [lab 03](labs/03-observe-protocol/README.md) |
| MCP lifecycle: initialization, capability negotiation, and message exchange | [02, section "MCP lifecycle"](02-mcp-architecture-deep-dive.md#mcp-lifecycle-initialization-capability-negotiation-and-message-exchange) (sequence SVG) | [lab 02](labs/02-connect-local-server/README.md) |
| Agentic AI Ecosystem | [03 The agentic AI ecosystem](03-agentic-ecosystem.md), repo: [05-agent-security](../../05-agent-security/README.md) | n/a |
| What are AI agents? | [03, section "What are AI agents?"](03-agentic-ecosystem.md#what-are-ai-agents) | n/a |
| Single-agent vs multi-agent systems | [03, section "Single-agent vs multi-agent systems"](03-agentic-ecosystem.md#single-agent-vs-multi-agent-systems), repo: [multi-agent trust](../../05-agent-security/multi-agent-trust/README.md) | n/a |
| Agentic workflows and orchestration patterns | [03, section "Agentic workflows and orchestration patterns"](03-agentic-ecosystem.md#agentic-workflows-and-orchestration-patterns) (router, planner-executor, supervisor, swarm) | n/a |
| Where MCP fits in the agentic stack | [03, section "Where MCP fits in the agentic stack"](03-agentic-ecosystem.md#where-mcp-fits-in-the-agentic-stack) | n/a |
| Popular hosts and frameworks using MCP (Claude Desktop, Cursor, Continue, and others) | [03, section "Popular hosts and frameworks using MCP"](03-agentic-ecosystem.md#popular-hosts-and-frameworks-using-mcp) (hedged) | n/a |
| The rapid growth of third-party MCP server registries | [03, section "The rapid growth of third-party MCP server registries"](03-agentic-ecosystem.md#the-rapid-growth-of-third-party-mcp-server-registries), [01, ecosystem](01-what-is-mcp.md#the-mcp-ecosystem-today-adoption-registries-and-tooling) | n/a |
| MCP Security – A First Look | [04 MCP security, a first look](04-mcp-security-first-look.md) | [lab 03](labs/03-observe-protocol/README.md) |
| Why MCP is a high-value target for attackers | [04, section "Why MCP is a high-value target for attackers"](04-mcp-security-first-look.md#why-mcp-is-a-high-value-target-for-attackers) | n/a |
| The unique security challenges that agentic systems introduce | [04, section "The unique security challenges that agentic systems introduce"](04-mcp-security-first-look.md#the-unique-security-challenges-that-agentic-systems-introduce) | n/a |
| A high-level map of the MCP threat landscape | [04, section "A high-level map of the MCP threat landscape"](04-mcp-security-first-look.md#a-high-level-map-of-the-mcp-threat-landscape) (SVG), repo: [secure-operations (OWASP MCP Top 10)](../../04-mcp-security/secure-operations/README.md) | n/a |
| What this course will cover and how chapters connect | [04, section "What this course will cover and how chapters connect"](04-mcp-security-first-look.md#what-this-course-will-cover-and-how-chapters-connect) | n/a |
| Hands-on Exercise: | Labs 01 to 04 below | all four labs |
| Learn how to use our browser-based lab environment | [00, section 4](00-how-to-approach-this-course.md#4-the-browser-based-lab-vs-this-repo) (use the course's browser lab first, then this repo) | course lab (not reproduced here); [real-sdk](real-sdk/README.md) |
| Install and configure a Python-based MCP server from scratch | [02](02-mcp-architecture-deep-dive.md), [lab 01](labs/01-install-configure-server/README.md) | [lab 01](labs/01-install-configure-server/README.md) + [real-sdk server](real-sdk/server_fastmcp.py) |
| Connect to a local MCP server | [02, lifecycle](02-mcp-architecture-deep-dive.md#mcp-lifecycle-initialization-capability-negotiation-and-message-exchange) | [lab 02](labs/02-connect-local-server/README.md) + [real-sdk client](real-sdk/client_fastmcp.py) |
| Observing MCP protocol-level communication | [02, JSON-RPC layer](02-mcp-architecture-deep-dive.md#the-json-rpc-20-protocol-layer) | [lab 03](labs/03-observe-protocol/README.md) (proxy), MCP Inspector in [real-sdk](real-sdk/README.md#inspect-with-mcp-inspector-hedged) |
| Building an MCP server with tools and resources | [02, primitives](02-mcp-architecture-deep-dive.md#the-three-primitives-tools-resources-and-prompts) | [lab 04](labs/04-build-server-tools-resources/README.md) + [real-sdk server](real-sdk/server_fastmcp.py) |

## Lab index

All labs are offline, standard-library Python, with tests:

```text
.venv/Scripts/python -m pytest cmcpse-course/ch1-introduction-to-mcp-and-agentic-ecosystem
```

| Lab | Course exercise | Tests | Also see |
|---|---|---|---|
| [01 install-configure-server](labs/01-install-configure-server/README.md) | Install and configure a Python-based MCP server from scratch | 8 (spawns the server with `python -I`, exchanges `initialize` and `tools/list` over stdin/stdout) | [mcp-server lab](../../04-mcp-security/mcp-server/lab/servers.py) (in-process simulation) |
| [02 connect-local-server](labs/02-connect-local-server/README.md) | Connect to a local MCP server | 7 | [authentication](../../04-mcp-security/authentication/README.md) (remote servers) |
| [03 observe-protocol](labs/03-observe-protocol/README.md) | Observing MCP protocol-level communication | 7 | [secure-operations](../../04-mcp-security/secure-operations/README.md) (audit and redaction) |
| [04 build-server-tools-resources](labs/04-build-server-tools-resources/README.md) | Building an MCP server with tools and resources | 10 | [tool-security](../../04-mcp-security/tool-security/README.md) |
| [real-sdk](real-sdk/README.md) | Same exercises with the official Python SDK and MCP Inspector | 1 (skipped if `mcp` is not installed) | |

Diagrams: [host, client, server](../../images/cmcpse-ch1-host-client-server.svg), [lifecycle](../../images/cmcpse-ch1-lifecycle.svg), [threat landscape](../../images/cmcpse-ch1-threat-landscape.svg), [N x M](../../images/cmcpse-ch1-n-by-m.svg).

## Learning order

1. [00](00-how-to-approach-this-course.md): set up your routine and your lab habits (20 minutes).
2. [01 What is MCP](01-what-is-mcp.md): definition, history, N x M, comparison table.
3. [02 Architecture](02-mcp-architecture-deep-dive.md): draw the diagram from memory; then do labs 01, 02, 03 and 04 in order.
4. [03 Agentic ecosystem](03-agentic-ecosystem.md).
5. [04 Security first look](04-mcp-security-first-look.md): then open the OWASP MCP Top 10 in [secure-operations](../../04-mcp-security/secure-operations/README.md).
6. Optional: [real-sdk](real-sdk/README.md) and MCP Inspector (update it first: CVE-2025-49596).
7. The questions below. Then read the repo's [MCP server trust module](../../04-mcp-security/mcp-server/README.md), which previews Chapter 2.

## Exam tips for this chapter

- **Three-tier model:** host (AI app, trust anchor), client (one per server, inside the host), server (third-party code). The LLM is in the host.
- **Three primitives and their controllers:** tools = model, resources = application, prompts = user. Client features (sampling, roots, elicitation) are server-to-client requests.
- **Transports:** stdio (local child process, no network but full user rights), Streamable HTTP (current remote standard, needs real authentication), HTTP+SSE (the old remote transport, deprecated in spec 2025-03-26). Know the history **and** the current state, because the syllabus line names SSE.
- **JSON-RPC:** request (id + method), response (id + result or error), notification (method, no id). Know the standard error codes and the difference between a protocol error and `isError: true`.
- **Lifecycle order:** `initialize` → result with version and capabilities → `notifications/initialized` → operation → shutdown. Use only negotiated capabilities.
- **Dates:** announced 25 Nov 2024; donated to the Agentic AI Foundation (Linux Foundation) 9 Dec 2025; spec revisions 2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25, and a later one (verify the latest).
- **Comparisons:** function calling = how a model requests a call; MCP = how the host discovers and reaches tools; A2A = agent to agent. MCP often wraps REST.
- **Security one-liners:** "text is the control channel", "servers are untrusted third-party code", "the host is the trust anchor", "official registry means verified namespace, not audited code".
- **OWASP MCP Top 10 (beta):** know that it exists and a few ids (MCP03 Tool Poisoning, MCP04 Supply Chain, MCP05 Command Injection, MCP09 Shadow Servers). Say "verify the current list".
- **Exam format:** this README does not know it. Check the course page.

## 15 exam and interview questions

<details><summary><b>Q1. What is MCP, and what problem does it solve?</b></summary>
An open protocol (JSON-RPC 2.0) that lets AI applications discover and use tools, data and prompts from external servers in one standard way. It replaces N x M custom integrations with N + M implementations of a shared protocol.
</details>

<details><summary><b>Q2. When was MCP created, and who governs it now?</b></summary>
Anthropic open-sourced it on 25 November 2024. On 9 December 2025 Anthropic donated it to the Agentic AI Foundation, a Linux Foundation fund, alongside Block's goose and OpenAI's AGENTS.md. Check the specification site for the latest revision.
</details>

<details><summary><b>Q3. Compare MCP with REST, function calling and plugins.</b></summary>
REST is a general service API style with no model-aware discovery. Function calling is how a model requests a function call, and you supply the function list yourself. Plugins and OpenAPI tools describe web APIs for a model but have no live session. MCP adds runtime discovery, capability negotiation, resources, prompts and server-to-client features. MCP servers often wrap REST APIs. A2A is agent-to-agent (delegating tasks between agents), while MCP is agent-to-tool; many systems use both.
</details>

<details><summary><b>Q4. Describe the host, client and server roles and the trust relationships.</b></summary>
The host is the AI application with the model, UI and policy, and is the trust anchor. It runs one client per server connection. Servers offer tools, resources and prompts and are untrusted third-party code until reviewed. The model never talks to a server directly: the host puts server text in the model's context.
</details>

<details><summary><b>Q5. Who controls tools, resources and prompts? Why does it matter for security?</b></summary>
Tools are model-controlled (usually with user approval), resources are application-controlled, prompts are user-controlled. The more the model decides, the more prompt injection can trigger actions. All three carry text from a third party.
</details>

<details><summary><b>Q6. What are sampling, roots and elicitation?</b></summary>
Client features requested by or for a server. Sampling: the server asks the host's LLM to generate text. Roots: the host tells the server which folders or URIs to work in (a hint, not a sandbox). Elicitation: the server asks the user for input through the host (must not be used to collect secrets). Each needs limits, human oversight and logging.
</details>

<details><summary><b>Q7. Explain the MCP transports and their security trade-offs.</b></summary>
stdio: local child process, no network surface, but the server runs with the user's rights and often holds secrets in env vars. Streamable HTTP: the current remote transport, needs OAuth 2.1 style authorization, TLS, Origin validation and localhost binding for local servers. HTTP+SSE: the older two-endpoint remote transport, deprecated since spec 2025-03-26, with removal planned; migrate off it.
</details>

<details><summary><b>Q8. What are the three JSON-RPC message types? Give an example of each.</b></summary>
Request (`{"jsonrpc":"2.0","id":3,"method":"tools/call",...}`), response (same id with `result` or `error`), and notification (`{"jsonrpc":"2.0","method":"notifications/initialized"}`, no id, no reply).
</details>

<details><summary><b>Q9. What is the difference between a protocol error and a tool error?</b></summary>
A protocol error is an `error` object (for example `-32602` unknown tool or `-32601` method not found) and means the request itself was wrong. A tool error is a normal result with `isError: true` and a message the model can read and react to. Check the current spec for which cases belong to which.
</details>

<details><summary><b>Q10. Walk through the MCP lifecycle and the security checks at each step.</b></summary>
Initialize (client sends version and capabilities), capability negotiation (server replies with agreed version and capabilities, client must accept or disconnect), `notifications/initialized`, operation (only negotiated features), shutdown. Checks: pinned server identity before start, version policy, gate methods on capabilities, treat results as untrusted, re-approve when descriptions change, log every message.
</details>

<details><summary><b>Q11. What is an AI agent, and how does single-agent differ from multi-agent?</b></summary>
An agent pursues a goal in a loop of plan, act (tool call), observe and repeat, choosing steps itself. A single agent uses one model with tools. Multi-agent systems split roles across agents and add messages between them, which gives more injection points and requires trust checks between agents.
</details>

<details><summary><b>Q12. Name four orchestration patterns and a risk each.</b></summary>
Router (misrouting to a privileged path), planner-executor (the plan is built from untrusted input), supervisor with workers (trusting worker output), swarm or handoff (privilege leaks through handoffs).
</details>

<details><summary><b>Q13. Where does MCP sit in the agentic stack?</b></summary>
Between the agent or orchestration layer (inside the host) and the tools and data. It is the connection layer: not the model, not the agent, not the agent-to-agent protocol.
</details>

<details><summary><b>Q14. Why is MCP a high-value target?</b></summary>
It concentrates credentials and access to many systems, runs third-party code with user rights, feeds untrusted text to a model that can act, is adopted quickly with little review, and the protocol does not define authorization, audit or supply chain controls. Real examples: postmark-mcp (malicious package), CVE-2025-6514 (mcp-remote), CVE-2025-49596 (MCP Inspector).
</details>

<details><summary><b>Q15. What does the official MCP Registry guarantee, and what does it not?</b></summary>
It verifies that the publisher controls the namespace (for example a domain or GitHub account). It does not scan or certify the safety of the code. Scanning is left to package registries and aggregators, so you still need allowlists, pinning, review and signing. Verify the current registry status at source.
</details>

## References

- MCP specification (lifecycle, transports, authorization, security best practices): <https://modelcontextprotocol.io/specification>
- Anthropic, "Introducing the Model Context Protocol" (25 Nov 2024): <https://www.anthropic.com/news/model-context-protocol>
- Agentic AI Foundation (AAIF) announcement, Linux Foundation, 9 Dec 2025: search for it on <https://www.linuxfoundation.org/press> and verify the exact URL and wording.
- OWASP MCP Top 10 (beta): <https://owasp.org/www-project-mcp-top-10/>; repo mapping in [secure-operations](../../04-mcp-security/secure-operations/README.md).
- OWASP Top 10 for Agentic Applications 2026: <https://genai.owasp.org> (verify).
- MCP Python SDK docs: <https://py.sdk.modelcontextprotocol.io>; MCP Inspector: <https://github.com/modelcontextprotocol/inspector>.
- Repo deep dives: [04-mcp-security](../../04-mcp-security/README.md), [05-agent-security](../../05-agent-security/README.md), [CAISP companion](../../caisp-course/README.md).
