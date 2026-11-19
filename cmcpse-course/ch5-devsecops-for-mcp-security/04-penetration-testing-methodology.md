# 04. Penetration Testing Methodology for MCP Environments

> **Syllabus:** Penetration testing methodology for MCP environments: scoping an MCP assessment, reconnaissance and enumeration, exploitation and chaining, reporting findings professionally.
> **Time:** 2 hours. **Companion file:** [report-template.md](report-template.md). **Related:** [CAISP ch5 threat modeling](../../caisp-course/ch5-threat-modeling-ai-systems/README.md) for scoping input, [chapter 2](../ch2-understanding-and-attacking-mcp-servers/README.md) for the attacks themselves.

## 1. Why this matters

A pentest answers one question: *what can a real attacker do to this environment, in the time we gave them?* For MCP the environment is bigger than one server: hosts, clients, several servers, the models, the registries, the identity provider, the CI pipeline and the humans who approve actions.

> **Rules of engagement come first.** Test only what is in writing. Use test data and accounts. The techniques in this course are for authorized assessment of your own or your client's systems.

## 2. The phases

```text
Scoping -> Reconnaissance and enumeration -> Exploitation and chaining -> Post-exploitation / impact -> Reporting -> Retest
```

### 2.1 Scoping an MCP assessment

Agree these in a short written document (statement of work plus rules of engagement):

| Item | Questions to settle |
|---|---|
| **Objectives** | Which risks matter? Data theft, unauthorized actions, tenant isolation, supply-chain trust? |
| **Assets in scope** | Which servers (names, versions, URLs), which hosts and clients (Claude Desktop, Cursor, VS Code, internal apps), which gateways, which registries, which CI pipelines |
| **Out of scope** | Production data, third-party SaaS behind the server (the SaaS vendor must agree to test it), real customer accounts, DoS |
| **Model** | Which model and version? Is the model's behavior part of the target (prompt injection tests) or fixed? Token and cost budget |
| **Test accounts and data** | Low and high privilege test users, seeded canary secrets, a staging tenant |
| **Access level** | Black box (no source), grey box (docs, test accounts), white box (source, configs) |
| **Rules** | Allowed hours, rate limits, no destructive tools in production, how to stop the test, emergency contact, data handling and retention |
| **Legal** | Authorization letter, cloud provider policy, safe harbor language |
| **Threat model input** | Use the [chapter 3 DFDs and STRIDE](../ch3-threat-modeling-mcp-architectures/README.md) to pick the highest-risk flows first |
| **Deliverables** | Report format, severity scale, retest included? |

### 2.2 Reconnaissance and enumeration

Goal: build the map of what exists and what each piece can do.

| Target | How to enumerate (authorized) |
|---|---|
| Servers | Host config files (`claude_desktop_config.json`, `.cursor/mcp.json`, `.vscode/mcp.json` and similar; paths vary, verify per product), repo search for `mcp`, process list (`npx`, `uvx`, `python -m`), network listeners on common ports, internal registries. This is also the **shadow MCP** hunt (MCP09). |
| Capabilities | Connect with a client; run `initialize` and read `capabilities`, then `tools/list`, `resources/list`, `resources/templates/list`, `prompts/list` |
| Tools | For each tool: name, description, `inputSchema`, annotations; what sink does it likely hit (shell, file, URL, SQL)? Which tools can write or send? |
| Auth | Is there auth at all? Token type, audience, scopes, token lifetime, where tokens are stored (config files, env, logs) |
| Transport | stdio or Streamable HTTP or legacy SSE; TLS; bound address; Origin handling |
| Supply chain | Package names, versions, registries, pinned or not, signatures, SBOM, maintainers |
| Cross-server | Which servers does one agent see at once? Tool name collisions; shared context |
| Model and host | Which approval prompts exist? Auto-approve settings? System prompt hints |
| Pipeline | Who can change tool descriptions? Which CI secrets? |

Output of this phase: an **attack surface map** (a table or DFD) and a list of hypotheses ("`fetch_url` has no allowlist", "descriptions are not pinned").

### 2.3 Exploitation and chaining

Test each hypothesis with a **proof**, safely (canary files and canary tokens, never real data). The MCP classics:

| Category | Test idea |
|---|---|
| Tool poisoning / rug pull | Does the host or gateway detect a changed description? |
| Prompt injection via tool output | Seed a document the agent will read; does the agent follow it? |
| Command injection / path traversal / SSRF | Same payloads as in the [fuzz lab](labs/fuzz-mcp-tools/README.md), against the real deployment in staging |
| Auth and scope | Token audience confusion, token passthrough, scope creep, cross-tenant access |
| Secrets | Tokens in logs, env, configs, descriptions, error messages |
| Cross-server shadowing | A malicious server's description changes how another server's tool is used |
| Supply chain | Can an unpinned `npx` launch be swapped? Can a PR change a description or a pipeline step ([PPE lab](labs/ppe-mcp-deployment/README.md))? |
| Denial of wallet | Loops and expensive tools without limits |

**Chaining** is where the value is. Single findings are often "medium"; the chain is "critical". An example chain, entirely hypothetical:

1. A public support ticket contains hidden instructions (**indirect prompt injection**, MCP06).
2. The agent reads it with a tool that has a broad database role (**excessive scope**, MCP02).
3. The agent writes the result back into the ticket, visible to the attacker (**exfiltration via a legitimate channel**, MCP10).

This mirrors the public Supabase MCP research (General Analysis, 2025) and the GitHub MCP private-repository leak reported by Invariant Labs (May 2025). Each step alone might be low severity; together they leak a database.

Document each chain as a numbered story with the evidence for every link, and rate the **chain's** impact.

### 2.4 Post-exploitation and impact

Show impact without causing harm: what data class was reached (canary), which actions were possible, how far across tenants and servers, what the logs captured (did the SOC see it?). Stop at proof.

### 2.5 Reporting findings professionally

A report has two audiences: executives (what is the risk, what do we do first) and engineers (exactly how to reproduce and fix). See the full [report-template.md](report-template.md).

Good practice:

- **One finding = one problem + proof + fix.** Title states the impact ("Any user can read files outside the notes folder through `read_note`").
- **Severity with a stated method** (CVSS v3.1/v4.0 plus an explanation of agentic factors such as "requires the agent to process attacker text"). Map to **OWASP MCP Top 10** IDs, **CWE** and, if useful, the OWASP Agentic Top 10 or MITRE ATLAS technique.
- **Reproducible steps** with exact requests, tool names, model version, and a canary proving success. Note model non-determinism ("reproduced 7 of 10 runs").
- **Evidence** redacted: never include real secrets or personal data.
- **Remediation** that is specific and ordered by effort and benefit, with a verification test.
- **Positive findings** (what worked) and **residual risk**.
- **Retest** results and status per finding.
- Be neutral: no blame, no hype. Findings are about systems.

## 3. Hands-on

1. Write a one-page scope for the notes server from the labs (assets, out of scope, rules).
2. Using the [fuzz lab output](labs/fuzz-mcp-tools/README.md), write two findings with the [template](report-template.md): one path traversal, one verbose error.
3. Write one chain (three steps) and rate it.

## 4. Interview questions

- *What is different about scoping an MCP pentest?* The model is part of the target, many components (hosts, clients, servers, registries, CI) are in play, tool actions can have real side effects so destructive tools need rules, and third-party SaaS behind a server needs separate permission.
- *Give an example of chaining.* Injection in content, a broad-scope tool, and an exfiltration channel.
- *How do you report non-deterministic findings?* State the model and version, the number of attempts and success rate, and give a deterministic reproduction against a mock where possible.

## 5. References

- PTES and OWASP Web Security Testing Guide (methodology structure); OWASP AI Testing Guide (verify current version); OWASP MCP Top 10 (beta).
- Invariant Labs (2025) research on tool poisoning and the GitHub MCP issue; General Analysis (2025) on Supabase MCP. Use as secondary sources and verify.
