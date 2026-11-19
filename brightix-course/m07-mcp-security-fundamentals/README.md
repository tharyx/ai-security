# Module 07: MCP Security Fundamentals (days 36–40)

The Model Context Protocol: hosts, clients, servers and transports; the tools/resources/prompts attack surface; OAuth and fine-grained authorization; tool poisoning, rug pulls, credential theft and shadow servers; secure implementation and sandboxing.

> **How this module works.** Most topics are already taught in depth elsewhere in this repo, so the table links to those lessons and labs instead of repeating them. Rows marked **Gap filled here** had little or no hands-on material before; the **NEW** labs in this module fill them.

> **Safety.** Every attack lab targets the repo's own toy code and mock models. Only test systems you own or have written permission to test.

## Syllabus coverage

| Syllabus item | Where to study | Lab | Status |
|---|---|---|---|
| [BX 7] What is MCP & Why it Matters in Agentic Ecosystems | [What is MCP](../../cmcpse-course/ch1-introduction-to-mcp-and-agentic-ecosystem/01-what-is-mcp.md); [MCP security module](../../04-mcp-security/README.md) | [01-install-configure-server](../../cmcpse-course/ch1-introduction-to-mcp-and-agentic-ecosystem/labs/01-install-configure-server) | Covered |
| [BX 7] MCP Architecture Deep Dive (Host, Client, Server & Transports) | [MCP architecture deep dive](../../cmcpse-course/ch1-introduction-to-mcp-and-agentic-ecosystem/02-mcp-architecture-deep-dive.md); [MCP server](../../04-mcp-security/mcp-server/README.md) | [03-observe-protocol](../../cmcpse-course/ch1-introduction-to-mcp-and-agentic-ecosystem/labs/03-observe-protocol); [mcp-server lab](../../04-mcp-security/mcp-server/lab) | Covered |
| [BX 7] Tools, Resources & Prompts Attack Surfaces | [MCP attack surface](../../cmcpse-course/ch2-understanding-and-attacking-mcp-servers/01-mcp-attack-surface.md); [Tool security](../../04-mcp-security/tool-security/README.md) | [01-recon-enumeration](../../cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/01-recon-enumeration); [tool-security lab](../../04-mcp-security/tool-security/lab) | Covered |
| [BX 7] Authentication, OAuth & Fine-Grained Authorization in MCP | [MCP authentication](../../04-mcp-security/authentication/README.md); [AuthN and AuthZ](../../cmcpse-course/ch4-defending-and-hardening-mcp-servers/02-authentication-and-authorization.md) | [authentication lab](../../04-mcp-security/authentication/lab); [defend-oauth-scopes](../../cmcpse-course/ch4-defending-and-hardening-mcp-servers/labs/defend-oauth-scopes) | Covered |
| [BX 7] MCP Security Risks (tool poisoning, rug pulls, credential theft, shadow servers) | [MCP attack primitives](../../cmcpse-course/ch2-understanding-and-attacking-mcp-servers/03-mcp-attack-primitives.md); [Secure operations (shadow MCP)](../../04-mcp-security/secure-operations/README.md) | [02-tool-poisoning](../../cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/02-tool-poisoning); [04-rug-pull](../../cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/04-rug-pull); [secure-operations lab](../../04-mcp-security/secure-operations/lab) | Covered |
| [BX 7] Secure MCP Implementation, Sandboxing & Hardening Practices | [Secure MCP development](../../cmcpse-course/ch4-defending-and-hardening-mcp-servers/07-secure-mcp-development.md); [Secure tool and resource design](../../cmcpse-course/ch4-defending-and-hardening-mcp-servers/03-secure-tool-and-resource-design.md); [Sandboxing](../../05-agent-security/sandboxing/README.md) | [least-privilege-tools](../../cmcpse-course/ch4-defending-and-hardening-mcp-servers/labs/least-privilege-tools); [05-docker-tool-sandbox](../../caase-course/ch3-agent-memory-context-and-tool-use/labs/05-docker-tool-sandbox) | Covered |

## Day-by-day plan

- Day 36: what MCP is and why it matters; install and configure a server.
- Day 37: host/client/server and transports (stdio, Streamable HTTP); observe the protocol.
- Day 38: tools, resources and prompts attack surface; recon lab.
- Day 39: OAuth and fine-grained authorization; tool poisoning, rug pull and shadow servers labs.
- Day 40: secure implementation, sandboxing and hardening.

## Interview / exam questions

<details><summary><b>What is an MCP rug pull and how do you detect it?</b></summary>

A server changes a tool's description or behaviour after the user approved it. Pin a hash of each tool definition at approval time and alert or block on any change.

</details>

<details><summary><b>Why is token passthrough forbidden in MCP?</b></summary>

Forwarding the client's token to downstream APIs breaks audience binding: a token issued for the MCP server can be replayed elsewhere, and the server loses control and audit of what it accesses.

</details>

<details><summary><b>What is a shadow MCP server?</b></summary>

An MCP server an employee installs or connects without security review, often with broad local or SaaS credentials. Inventory, allowlists and egress controls find and stop them.

</details>

---

Previous: [Module 06](../m06-ai-security-monitoring-and-soc/README.md) · [Course home](../README.md) · Next: [Module 08](../m08-capstone-enterprise-ai-and-mcp/README.md)
