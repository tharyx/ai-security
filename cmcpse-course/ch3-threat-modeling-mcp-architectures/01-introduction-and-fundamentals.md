# Lesson 01: Threat modeling MCP systems, introduction and fundamentals

> **Chapter 3** · **Time:** ~3 hours · **You will:** explain what threat modeling is, why MCP needs its own threat model, list the assets in an MCP deployment, separate weakness from vulnerability, and walk the risk management stages and STRIDE with MCP examples.

| | |
|---|---|
| **Syllabus lines** | Introduction to Threat Modeling (4 lines) · Threat Modeling Fundamentals (4 lines) |
| **Already in this repo** | General method: [CAISP ch5, lesson 01](../../caisp-course/ch5-threat-modeling-ai-systems/01-threat-modeling-foundations.md) and [Module 01, lesson 03](../../01-ai-security-fundamentals/03-ai-threat-modeling.md). MCP architecture basics: [Module 04, mcp-server](../../04-mcp-security/mcp-server/README.md) |
| **This lesson adds** | The MCP view: assets, trust, and the questions that are different for MCP |
| **Next** | [Lesson 02: diagramming MCP architectures](02-diagramming-mcp-architectures.md) |

---

## 1. What is threat modeling?

Threat modeling is a structured way to find what can go wrong in a design, decide which problems matter most, and decide what to do before you build or ship. Use the four questions:

1. What are we working on? (draw it)
2. What can go wrong? (STRIDE, libraries)
3. What are we going to do about it? (controls, risk treatment)
4. Did we do a good job? (tests, review, re-model)

Do it when you design, when the design changes (a new server, a new transport, a new OAuth scope), and when new threat information appears. The general method is the same as in [CAISP ch5 lesson 01](../../caisp-course/ch5-threat-modeling-ai-systems/01-threat-modeling-foundations.md). This chapter only adds what is different for MCP.

## 2. Why threat model MCP systems specifically?

* **The attack surface is assembled at run time.** A user adds a server to a config file and, in a minute, a new third-party program (local) or service (remote) can feed text into the model and receive tool calls. A scanner of your own code never sees it.
* **Tool descriptions are executable-ish.** The model reads names, descriptions and schemas as instructions. Text from a server is therefore part of your control plane (tool poisoning, rug pull).
* **Tool results are untrusted input that re-enters the prompt.** A result can carry instructions (indirect prompt injection).
* **Many trust boundaries meet in one process.** The host has the user, the model provider, several servers, a registry and an identity provider around it. Each pair is a boundary.
* **Local servers run with the user's privileges.** A stdio server is a child process, not a sandbox ([Module 04, secure-operations](../../04-mcp-security/secure-operations/README.md)).
* **Real incidents already happened** (secondary sources, verify details): a malicious `postmark-mcp` npm package that BCC'd email (Sept 2025); command execution through a crafted `authorization_endpoint` in `mcp-remote` (CVE-2025-6514); an unauthenticated MCP Inspector proxy (CVE-2025-49596); sandbox bypasses in the filesystem server (CVE-2025-53109/53110); and a tenant-isolation flaw in an experimental Asana MCP server (June 2025).

## 3. Threat modeling challenges in agentic AI environments

| Challenge | What it means for you |
|---|---|
| The system changes at run time | Model the *rules* (what may connect, what may call what), not only today's list of servers |
| Behaviour is not deterministic | You cannot enumerate every tool-call chain. Model the *capabilities* each chain could reach and bound them with policy |
| Data and instructions share one channel | Every flow into the model is a possible injection path, so draw them all |
| Many owners | Host vendor, server author, registry, IdP and model provider each own part. Record who owns each control |
| Fast-moving spec | The MCP spec changes (revisions 2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25, and a later one; verify at modelcontextprotocol.io). Re-check transports and auth text before each review |
| Humans in the loop are weak points | Approval fatigue and misleading prompts are threats too (ASI09) |
| Thin evidence | Few public incident reports. Mix libraries with your own red-team results |

## 4. Threat modeling benefits for MCP practitioners

* **Cheaper fixes.** Changing "which servers may run" is a policy edit at design time, and a rewrite after an incident.
* **A shared picture.** The DFD lets developers, security and the platform team argue about the same boundaries.
* **Better tests.** Every finding becomes a test (for example "a tool call without the `tickets:write` scope is rejected").
* **Better procurement.** You can ask a server vendor the same questions ("how do you bind tokens to an audience?").
* **Evidence for governance.** A threat model and a register are an easy answer to audit questions ([CAISP ch7](../../caisp-course/ch7-emerging-threats-governance-compliance/README.md)).

## 5. Threat modeling fundamentals

### 5.1 What are assets in an MCP context?

An **asset** is anything of value that an attacker could want or that you must keep working. Name assets first. Threats are "something bad happens to an asset".

| Asset | Where it lives | Why an attacker wants it | Typical controls |
|---|---|---|---|
| **Tokens and keys** (OAuth access and refresh tokens, API keys, session ids) | Token cache, server env, headers, logs | Act as the user; reach downstream APIs | Short lifetime, audience binding, vault, OS keychain, redaction |
| **Tool definitions** (names, descriptions, input schemas, annotations) | Server memory, host catalog | Steer the model; hide a rug pull | Pinning, scanning, review, signing |
| **Resources** (files, rows, documents exposed by URI) | Server and backing stores | Data theft, tampering | Resource scopes, least privilege, per-user filtering |
| **Conversation context** (prompts, tool results, system prompt, memory) | Host memory, model provider | Contains secrets and private data; is the injection target | Minimisation, redaction, isolation per user |
| **Host configuration** (mcp.json: launch commands, URLs, env) | User or project config file | A command line is code execution; a URL decides who you trust | File permissions, code review, integrity checks |
| **Server code and dependencies** | Package registry, disk | Supply chain compromise | Allowlist, pin, SBOM, signing |
| **Audit trail** | Logs | Proof of what happened | Structured logs, hash chain, write-once storage |
| **Availability and budget** | Quotas, model spend | Denial of service, denial of wallet | Rate limits, budgets |

Give each asset a value (the labs use 0 to 9). A value is a conversation starter, not a measurement.

### 5.2 Weaknesses vs vulnerabilities in MCP

* A **weakness** is a *kind* of mistake (a CWE category). Example: "OS command injection" (CWE-78).
* A **vulnerability** is a *specific, exploitable instance* in a product, often with a CVE. Example: CVE-2025-6514 in `mcp-remote`, where an untrusted `authorization_endpoint` value reached a command.
* A **threat** is what an attacker could do. A **risk** is how likely and how bad. A **control** reduces likelihood or impact.

MCP examples of weaknesses (and the usual CWE family, verify the ids): command injection (CWE-78), path traversal (CWE-22), missing authentication for a critical function (CWE-306), missing authorization (CWE-862), exposure of sensitive information in logs (CWE-532), SSRF (CWE-918), and improper input validation (CWE-20). *Design* weaknesses are not in CWE yet: "tool descriptions are trusted by the model" and "no way to tell data from instructions".

### 5.3 Risk management stages

```text
Identify assets -> Identify threats -> Rate risk -> Choose treatment -> Implement controls -> Monitor and review -> (repeat)
```

| Stage | MCP example |
|---|---|
| Identify assets | Tokens, tool definitions, CRM data |
| Identify threats | Tool poisoning, token passthrough, DNS rebinding (STRIDE per element) |
| Rate | Likelihood × impact, inherent and residual ([lesson 05](05-rating-and-managing-risks.md)) |
| Treat | Avoid (drop the server), mitigate (add pinning), transfer (vendor contract, insurance), accept (owner signs) |
| Implement | Scope checks, vault, gateway |
| Monitor | Tool-call logs and detections ([ch4 lesson 06](../ch4-defending-and-hardening-mcp-servers/06-logging-monitoring-detection.md)) |

### 5.4 The STRIDE methodology

| Letter | Threat | Property broken | MCP one-liner |
|---|---|---|---|
| S | Spoofing | Authentication | Fake server, stolen token, forged client id |
| T | Tampering | Integrity | Poisoned description, altered config, changed tool result |
| R | Repudiation | Non-repudiation | "The agent did it", with no log to prove who approved |
| I | Information disclosure | Confidentiality | Secrets in logs, over-sharing, cross-server leakage |
| D | Denial of service | Availability | Tool-call loops, huge outputs, registry outage |
| E | Elevation of privilege | Authorisation | Scope creep, token passthrough, server running as the user |

STRIDE-per-element says which letters to ask for which DFD symbol: external entity S and R; process S, T, R, I, D, E; data store T, R, I, D; data flow T, I, D. The full MCP application is in [lesson 03](03-stride-for-mcp.md).

## 6. Quick check

1. Name five MCP assets and one control for each.
2. Is "a tool description tells the model to read `~/.ssh/id_rsa`" a weakness, a vulnerability, or a threat? Explain.
3. Which STRIDE letters apply to a data store, and which to an external entity?
4. Why does adding a server to `mcp.json` justify a new review?

## 7. References

* OWASP Threat Modeling Cookbook and the Threat Modeling Manifesto (threatmodelingmanifesto.org).
* Adam Shostack, *Threat Modeling: Designing for Security* (the four questions and STRIDE per element).
* MCP specification and security best practices (modelcontextprotocol.io, verify the current revision).
* Incident sources: vendor write-ups from Koi Security, JFrog, Oligo and Asana (secondary; verify numbers).
