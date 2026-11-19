# Certified MCP Security Expert: Course Companion

A study companion for the **Certified MCP Security Expert (CMCPSE)** course, organized exactly like its 6-chapter syllabus.
Every syllabus line points either to a lesson that already exists in this repo or to a new MCP-specific lesson and lab here. Check line by line in [SYLLABUS-MAP.md](SYLLABUS-MAP.md).

> Unofficial companion. Your course's videos, browser-based lab environment and support community are the primary source. Use this folder to go deeper, practice offline and prepare for interviews.

## Chapters

| # | Chapter | What's new here | Key labs |
|---|---|---|---|
| 1 | [Introduction to MCP and the Agentic Ecosystem](ch1-introduction-to-mcp-and-agentic-ecosystem/) | MCP origin → Linux Foundation (AAIF), MCP vs REST vs function calling, architecture, transports (**SSE is deprecated**), JSON-RPC, lifecycle, agent patterns | Build/run a stdio MCP server, connect a client, watch the protocol, tools + resources (+ real SDK versions) |
| 2 | [Understanding and Attacking MCP Servers](ch2-understanding-and-attacking-mcp-servers/) | Attack surface, ATT&CK/ATLAS for MCP, every attack primitive, vulnerability classes, real incidents | Recon, tool poisoning, response injection, rug pull, cross-server privesc, confused deputy, MCP worm, code exec → compromise |
| 3 | [Threat Modeling MCP Architectures](ch3-threat-modeling-mcp-architectures/) | MCP assets, DFDs with trust boundaries (single and multi-server), STRIDE for MCP, MCP threat taxonomies | STRIDE an MCP architecture, risk rating, IriusRisk walkthrough, STRIDE GPT |
| 4 | [Defending and Hardening MCP Servers](ch4-defending-and-hardening-mcp-servers/) | AuthN/AuthZ, RBAC for tools, transport/TLS/pinning, secrets and Vault, logging and detection, secure development | OAuth scopes, least-privilege tools, Vault, invocation logging, defending rug pull / poisoning / tool confusion, MCP AI firewall |
| 5 | [DevSecOps for MCP Security](ch5-devsecops-for-mcp-security/) | MCP SDLC, SAST/secret scanning, DAST, fuzzing, pentest methodology, CI/CD gates, runtime protection | SAST a vulnerable MCP server, fuzz tools, MCP CI/CD pipeline, PPE on MCP deployment, AI firewall deploy |
| 6 | [Supply Chain Security and Governance of MCP](ch6-supply-chain-security-and-governance-of-mcp/) | MCP supply chain and registries, postmark-mcp, vetting, SBOM/provenance/signing, SLSA/SCVS/OpenSSF, governance and compliance for MCP, emerging threats | Backdoored MCP package, SBOM, sign and verify a build, provenance attestations |

## Two things the syllabus doesn't tell you

1. **Transports have changed.** The syllabus says "stdio, SSE, and HTTP with SSE". In the current specification the standard transports are **stdio** and **Streamable HTTP**; the old HTTP+SSE transport was deprecated in 2025. Learn both: the old one for the exam and legacy servers, the new one for real work.
2. **MCP now has a neutral home.** In December 2025 Anthropic donated MCP to the Linux Foundation's Agentic AI Foundation. Always check the latest specification revision at modelcontextprotocol.io.

## How the labs run

| Lab type | Where | Needs |
|---|---|---|
| `labs/…` | Your laptop, offline | `python -m pytest cmcpse-course` |
| `real-sdk/…` (where present) | Your laptop | `python -m pip install -e ".[mcp]"` (official MCP Python SDK; small, no GPU). In SDK 2.x `FastMCP` is called `MCPServer` (`mcp.server.mcpserver`), and the examples handle both. Course videos may show the older name. |
| Course lab | Your course's browser-based lab | A browser |

## How this connects to the rest of the repo

| Course chapter | Builds on |
|---|---|
| 1 | [04 · mcp-server](../04-mcp-security/mcp-server/), [05 agents](../05-agent-security/) |
| 2 | [04 · tool-security](../04-mcp-security/tool-security/), [04 · secure-operations](../04-mcp-security/secure-operations/) (OWASP MCP Top 10), [CAISP ch2 · ATLAS](../caisp-course/ch2-understanding-and-attacking-llms/) |
| 3 | [CAISP ch5 · threat modeling](../caisp-course/ch5-threat-modeling-ai-systems/) |
| 4 | [04 · authentication](../04-mcp-security/authentication/), [06 · runtime-security](../06-ai-devsecops/runtime-security/) |
| 5 | [CAISP ch4 · DevSecOps](../caisp-course/ch4-ai-attacks-and-defenses-devops/), [06 · cicd](../06-ai-devsecops/cicd/) |
| 6 | [CAISP ch6 · supply chain](../caisp-course/ch6-supply-chain-attacks-in-ai/), [CAISP ch7 · governance](../caisp-course/ch7-emerging-threats-governance-compliance/), [07](../07-ai-governance/), [08](../08-ai-compliance/) |
