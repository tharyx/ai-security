# Lesson 03: Applying STRIDE to MCP

> **Chapter 3** · **Time:** ~3 hours · **You will:** apply STRIDE per MCP element and per boundary crossing, and read the output of the lab tool.

| | |
|---|---|
| **Syllabus lines** | Applying STRIDE to MCP |
| **Already in this repo** | STRIDE method: [CAISP ch5, lesson 03](../../caisp-course/ch5-threat-modeling-ai-systems/03-stride-for-llm-apps.md). Attack and defense labs for MCP: [Module 04](../../04-mcp-security/README.md) |
| **Lab** | [`labs/stride-mcp-architecture/`](labs/stride-mcp-architecture/) |
| **Prerequisite** | [Lesson 02](02-diagramming-mcp-architectures.md) |

---

## 1. The method

1. Take the DFD ([lesson 02](02-diagramming-mcp-architectures.md)).
2. For each **element** (entity, process, store) ask the STRIDE letters that apply to its type.
3. For each **data flow**, ask T, I and D. For flows that **cross a trust boundary**, ask harder and rate the likelihood higher.
4. For each threat write: element, STRIDE letter, scenario, what asset, which control exists, which is missing.
5. Map to a library (OWASP MCP Top 10, Agentic Top 10) so the finding has a common name ([lesson 04](04-mcp-threat-libraries.md)).

## 2. STRIDE per MCP element

### 2.1 MCP host and client (a process)

| STRIDE | Threat | Example | Controls |
|---|---|---|---|
| S | Connects to an impostor server or accepts a forged client identity | Typosquatted package; look-alike URL | Allowlist, TLS validation, registry namespace checks |
| T | Accepts poisoned or changed tool definitions | Tool poisoning; rug pull; `tools/list_changed` abuse | Scan, pin hashes, re-approve changes |
| R | No record of which user approved which call | Agent "did it", no log | Structured log with user, client, tool, decision; signed trail |
| I | Context leaks across servers or to the model provider | Data from server A sent through server B | Taint policy, minimisation, redaction |
| D | Runaway loops, huge outputs | A tool that returns 10 MB | Rate limits, size caps, circuit breaker |
| E | Excessive agency: side effects without approval | Auto-approve everything | Human approval for writes, least-privilege tool list |

### 2.2 MCP server (a process)

| STRIDE | Threat | Example | Controls |
|---|---|---|---|
| S | Serves a client it cannot identify; token replay | Any local program connects to 127.0.0.1 | Auth on every request, Origin and Host check |
| T | Command injection, path traversal; its own definition changes | `run_command` passes args to a shell | Schemas, no shell, root-bound paths, pinning |
| R | Cannot show who did what | No per-user identity downstream | Downstream identity, audit log |
| I | Secrets in env, logs, errors, descriptions | API key printed on error | Vault, redaction, safe errors |
| D | Resource exhaustion | Unbounded query | Timeouts, quotas |
| E | Runs with the user's full privileges; scope creep; confused deputy | Token for API A used on API B | Sandbox, scope checks, audience binding |

### 2.3 Data stores (host config, token cache, files, DB, logs)

| STRIDE | MCP threat | Control |
|---|---|---|
| T | Host config edited to launch a malicious command (the command line is code) | File permissions, review, integrity hash |
| R | Writes with no trace | Log changes |
| I | Tokens in plaintext; secrets in `mcp.json` env | OS keychain, vault, `${ENV}` references |
| D | Disk filled by logs or caches | Quotas, rotation |

### 2.4 External entities (user, LLM, registry, IdP)

| STRIDE | MCP threat | Control |
|---|---|---|
| S | Registry listing impersonates a publisher; user tricked into consent | Namespace-verified publishers, allowlist, clear consent text |
| R | User denies approving an action | Record approvals with the exact action text |

### 2.5 Data flows (the bulk of MCP findings)

| Flow | T | I | D |
|---|---|---|---|
| `tools/list` and results (server to host) | **Injection in results**; changed definitions | Over-sharing; data in descriptions | Oversized output |
| `tools/call` (host to server) | Argument tampering by an injected model | Secrets in arguments | Call floods |
| OAuth (host to IdP and server) | Redirect tampering; code interception | Token leakage in URLs or logs | - |
| Registry (host to registry) | Package or metadata swap | - | Outage blocks discovery |
| Context (host to LLM) | - | Private data to a third party | Token/cost exhaustion |

## 3. Per crossing

Every dashed arrow in the diagrams is a crossing. The lab raises the *threat agent* factor by 1 for a threat on a crossing flow, because more actors can reach it. In the sample architecture 13 of 18 flows cross a boundary. The injection-in-results finding (MT-T03) is only generated for crossings.

## 4. Walk-through with the lab

```bash
python cmcpse-course/ch3-threat-modeling-mcp-architectures/labs/stride-mcp-architecture/demo.py
python cmcpse-course/ch3-threat-modeling-mcp-architectures/labs/stride-mcp-architecture/stride_mcp.py --format csv > findings.csv
```

1. The tool reads `mcp_architecture.yaml` and checks DFD rules.
2. It applies the library `mcp_threat_library.yaml` (27 reusable threats) to each element and flow.
3. A finding is **mitigated** when at least one listed control is present on that element, otherwise **open**. "Mitigated" is a hint, not proof: you still need a test.
4. You document the result in [`findings-template.md`](labs/stride-mcp-architecture/findings-template.md): accept, reject (false positive), re-scope, or add a threat the tool missed.

## 5. Typical false positives and gaps

* `MT-T06` (no TLS) on 127.0.0.1 flows: often acceptable if the loopback is protected and the server authenticates. Record it as an *accepted risk with an owner*.
* The tool cannot see **cross-flow chains** (read a secret from A, post it to B). `MT-I04` and `MT-E04` remind you, but the real control is a policy at the host or gateway.
* The tool does not know your business. Add threats for your own assets (a payment tool, a prod database).

## 6. Quick check

1. Why is the `tools/list` response a Tampering flow and not only an Information flow?
2. Which element gets Repudiation threats in MCP, and what control addresses it?
3. A stdio server and an HTTP server on 127.0.0.1 are both "local". Name one STRIDE threat that exists only for the HTTP one.

## 7. References

* Microsoft STRIDE-per-element (Shostack).
* OWASP MCP Top 10 (beta; verify at owasp.org).
* [Module 04](../../04-mcp-security/README.md) for the defences that map to each finding.
