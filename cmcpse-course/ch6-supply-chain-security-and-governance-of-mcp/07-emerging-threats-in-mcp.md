# 07. Emerging Threats in MCP

> **Syllabus:** Emerging Threats in MCP: agentic worms propagating autonomously through MCP chains, shadow MCP servers in enterprise environments, malicious MCP registries and package poisoning, AI-assisted exploitation targeting MCP deployments.
> **Time:** 2 hours. **General background:** [CAISP ch7 lesson 01: emerging threats in AI](../../caisp-course/ch7-emerging-threats-governance-compliance/01-emerging-threats-in-ai.md) and its [AI worm simulation lab](../../caisp-course/ch7-emerging-threats-governance-compliance/labs/ai-worm-simulation/). Repo: [04 secure-operations (shadow servers, MCP09)](../../04-mcp-security/secure-operations/README.md).

*This lesson is partly **forward-looking**. Where evidence is limited, it says so. Treat the scenarios as threat-model material, not as predictions of what is happening today.*

## 1. Agentic worms propagating through MCP chains

**Idea.** A *worm* copies itself from system to system. In an agentic setting the "code" is a **self-replicating prompt**: an instruction hidden in content that, when an agent reads it, makes the agent (a) do something harmful and (b) **write the same instruction into new content** that other agents will read.

**Research precedent.** **Morris II** (2024; Cohen, Bitton, Nassi) demonstrated a self-replicating adversarial prompt spreading between GenAI-powered email assistants in a *research* setting, using retrieval-augmented generation and automated replies. No claim of real-world spread is made here; it is a proof of concept that shows the mechanism.

**Why MCP chains matter.** MCP gives agents **tools that read and write shared channels**: mail, chat, tickets, wikis, repos, calendars, files. A propagation path needs three things:

```text
READ source  ->  agent obeys hidden instruction  ->  WRITE to a place other agents READ
(mail, ticket,    (no human in the loop, tool          (send mail, comment, commit, doc,
 web page)         allowed to act)                       shared memory, another agent's inbox)
```

Chain examples (hypothetical): a malicious email is read through a mail server's tool; the instruction tells the agent to reply to all contacts with the same text (send tool) and to attach internal files; every recipient's agent repeats the step. Variants spread through shared issue trackers, wikis, pull-request comments or **shared agent memory**.

**What limits it today (and what removes the limit).** Models vary in how often they obey injected text; hosts ask users to approve tool calls; many tools are read-only; outbound rate limits exist. The risk grows with **auto-approval, write+send tools on the same agent as read tools, broad contact access and multi-agent systems that trust each other's output** ([05 multi-agent trust](../../05-agent-security/multi-agent-trust/README.md)).

**Defences (break any of the three links):**

- **Break read to obey:** treat tool results as data; injection screening in the gateway ([ch5 lesson 07](../ch5-devsecops-for-mcp-security/07-ai-firewalls-at-the-gateway.md)); content provenance labels; separate agents for reading untrusted content and for acting.
- **Break obey to write:** human approval for send/post/commit; least privilege (read agents have no write tools); allowlists for recipients and destinations; no auto-reply to arbitrary senders.
- **Break write to read (propagation):** outbound **rate limits and quotas**, duplicate-content detection (the same text sent to many recipients), egress controls, sanitizing content before it enters shared memory.
- **Detect:** audit trails of tool calls; alerts on sudden fan-out (one agent sending to many recipients), repeated identical long payloads, and agents acting on content from external senders.
- **Contain:** kill switch per server and per tool; credential rotation runbook; sandboxed test of the worm pattern in the [CAISP worm simulation lab](../../caisp-course/ch7-emerging-threats-governance-compliance/labs/ai-worm-simulation/) (offline, harmless).

## 2. Shadow MCP servers in enterprise environments (OWASP MCP09)

**What it is.** MCP servers that run in your environment **without approval or inventory**: a developer installs a community server in their IDE, a team stands up an internal server on a shared VM, a SaaS tool enables an MCP connector, a laptop runs a server that binds to `0.0.0.0`. Like shadow IT, but the thing is **wired to an agent with credentials**.

**Why it is dangerous.** Unvetted code, unpinned versions, personal API keys with company data, no logging, no network controls, and agents that can reach it without anyone knowing. Many MCP servers were found listening on all interfaces without authentication by researchers in 2025 (reported; verify numbers) — so the exposure is not hypothetical.

**Detection: inventory from several angles.** No single source is complete.

| Angle | What to look for | Examples |
|---|---|---|
| **Endpoint configs** | MCP client config files in user profiles and repos | Claude Desktop, Cursor, VS Code, Windsurf, Continue and similar config files (paths vary by product and OS: check each product's documentation and keep a maintained list); `.mcp.json` / `mcp.json` in repositories |
| **Processes** | Launch patterns on endpoints and servers | `npx`, `uvx`, `pipx`, `python -m`, `node` processes whose args contain `mcp`; docker containers from MCP images |
| **Network** | Listeners and traffic | Ports in use by local servers; HTTP requests to `/mcp` or `/sse` paths; JSON-RPC bodies with `tools/list`; outbound connections to unknown MCP hosts; EDR and proxy logs |
| **Package managers and registries** | First-seen MCP package names in builds | CI logs; internal registry access logs; SBOMs containing MCP SDKs |
| **Code search** | MCP SDK imports in repos | `from mcp`, `@modelcontextprotocol/sdk`, FastMCP |
| **Identity and SaaS** | OAuth grants and connectors | New app consents; SaaS "MCP connector" settings; API keys created for agents |
| **Cloud and containers** | Deployments exposing MCP endpoints | Kubernetes services, load balancers, serverless functions, security-group scans |

A minimal endpoint sweep you can adapt (a sketch for authorized use on your own machine; paths are examples and differ by product and OS):

```python
import json, pathlib
CANDIDATES = [
    pathlib.Path.home() / ".cursor" / "mcp.json",
    pathlib.Path.home() / ".vscode" / "mcp.json",
    pathlib.Path.cwd() / ".mcp.json",
]
for path in CANDIDATES:
    if path.exists():
        servers = json.loads(path.read_text()).get("mcpServers", {})
        for name, spec in servers.items():
            print(path, name, spec.get("command"), spec.get("args"))   # then compare with the approved inventory
```

**Response.** Do not just ban: provide an **approved catalogue** and a fast approval path, so people have a safe way to do the thing they wanted. Then enforce: policy-as-code on host configs (approved registries, pinned versions), network egress controls, gateway as the only path to remote servers, and periodic discovery with a diff against the inventory. See [lesson 02](02-vetting-third-party-mcp-servers.md) (register) and the [checklist](mcp-compliance-checklist.md) row A3. The repo's [secure-operations lab](../../04-mcp-security/secure-operations/README.md) includes a shadow-server detector.

## 3. Malicious MCP registries and package poisoning

**Registries as targets.** A registry or aggregator is a high-leverage place to attack: one listing reaches many users. Threats:

- **Impersonation and typosquatting** of well-known server names (postmark-mcp style, [lesson 01](01-mcp-supply-chain-overview.md)).
- **Poisoned metadata:** a legitimate-looking listing whose install command points at a malicious package; descriptions with injection text aimed at *agents that browse registries* (an agent that picks servers from a catalogue can itself be steered).
- **Fake popularity** (stars, downloads) to rank higher.
- **Malicious registries and mirrors:** a "mirror" you are told to use (config in a README, a one-click install link) that serves modified packages.
- **Namespace takeover** after a maintainer leaves or a domain expires.
- **Delayed activation:** clean for many versions, then malicious (postmark-mcp), or malicious only for some targets (checks the environment).
- **Package poisoning inside a legitimate project:** a compromised maintainer account or CI ([ch5 lesson 06](../ch5-devsecops-for-mcp-security/06-pipeline-attacks-on-mcp.md)).
- **Self-propagating package attacks** on language registries (npm worms that steal tokens and republish) have been reported in 2025; they show how a registry compromise can spread (verify specifics).

**Defences:** curated internal registry or allowlist; pin and hash; verify publisher identity and provenance; install scripts off; analyse new versions in a sandbox; alert on newly published versions of approved packages (diff review); do not let agents install servers on their own; treat registry text as untrusted input; report and take down malicious packages (registry security contacts).

## 4. AI-assisted exploitation targeting MCP deployments (forward-looking)

Attackers can use LLMs the same way defenders do. Plausible uses, all of which lower cost and skill needed rather than create new vulnerability classes:

- **Faster discovery:** scanning code and configs for MCP bugs (the same six patterns as in [ch5 lesson 02](../ch5-devsecops-for-mcp-security/02-sast-and-secret-scanning.md)); drafting exploits for newly published CVEs in MCP tools and helpers.
- **Reconnaissance at scale:** finding exposed MCP endpoints, enumerating tools, and generating tailored payloads per tool schema (the fuzzing approach in [ch5 lesson 03](../ch5-devsecops-for-mcp-security/03-dast-fuzzing-and-runtime-testing.md), automated and adaptive).
- **Better social engineering:** convincing descriptions, README files and fake maintainers to get a poisoned server installed.
- **Adaptive prompt injection:** payloads that are rewritten until they pass a given filter or work on a given model (iterative, automated attacks against regex firewalls are cheap).
- **Autonomous attack agents:** an attacker's agent that chains steps (recon, injection, exfiltration) with little human input.

Evidence note: public reporting on AI-orchestrated attacks exists but is partly vendor-sourced and evolving (verify current reports). Design on the assumption that **cost of attack falls and speed rises**.

**Defences:**

- Assume **faster time from disclosure to exploit**: shorten patch windows for MCP servers and helpers; automate update PRs ([lesson 02](02-vetting-third-party-mcp-servers.md)).
- Do not rely on obscurity or single regex filters; **layer**: least privilege, sandboxing, egress allowlists, approvals, behavioral detection.
- **Use AI defensively and carefully:** LLM-assisted triage of findings, code review and log analysis, with deterministic gates and human decisions kept in the loop (an LLM reviewer can be prompt-injected through the code it reviews).
- Run **continuous adversarial testing** (automated fuzzing and injection suites in CI and against staging).
- Monitor for **machine-speed behavior**: bursts of tool enumeration, rapid retries of variant payloads, unusual call sequences: rate limits and anomaly detection at the gateway.
- Keep logs good enough to reconstruct an automated attack.

## 5. Putting it together: one table

| Threat | First control | Detection | Lab / lesson |
|---|---|---|---|
| Agentic worm | Approvals for send/post; split read and write agents | Fan-out and duplicate-content alerts | [CAISP worm lab](../../caisp-course/ch7-emerging-threats-governance-compliance/labs/ai-worm-simulation/) |
| Shadow MCP server | Approved catalogue, policy on host configs, egress control | Endpoint config, process, network and repo discovery | [04 secure-operations](../../04-mcp-security/secure-operations/README.md) |
| Malicious registry / poisoned package | Allowlist, pin, hash, verify, sandbox new versions | New-version diff alerts, first-seen package alerts | [backdoor lab](labs/backdoor-mcp-package/README.md) |
| AI-assisted exploitation | Layered controls, fast patching, continuous testing | Machine-speed anomaly detection | [ch5 lessons 03, 07](../ch5-devsecops-for-mcp-security/README.md) |

## 6. Interview questions

- *How could a worm spread through MCP and what breaks the chain?* Read-obey-write loop through shared channels; break it with injection screening, least privilege and approvals, and rate limits on outbound writes.
- *How do you find shadow MCP servers?* Combine endpoint config scans, process and network discovery, repo search, package logs and OAuth/SaaS reviews; then provide an approved alternative.
- *What is special about a malicious registry?* High leverage: one listing reaches many installs, and listings can themselves contain injection text aimed at agents.
- *How does AI change the attacker's economics?* Lower cost and faster reconnaissance, payload variation and exploit drafting; so shorten patch time and layer defences.

## 7. References

- Cohen, Bitton, Nassi (2024), "Here Comes the AI Worm" (Morris II). OWASP MCP Top 10, MCP09. Koi Security and Snyk on `postmark-mcp`.
- [CAISP ch7 lesson 01](../../caisp-course/ch7-emerging-threats-governance-compliance/01-emerging-threats-in-ai.md).
