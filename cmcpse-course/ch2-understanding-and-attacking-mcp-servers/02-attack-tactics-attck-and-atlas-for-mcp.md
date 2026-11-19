# Lesson 02: Attack Tactics and Techniques for MCP (ATT&CK and ATLAS)

> **Chapter:** 2 · Understanding and Attacking MCP Servers · **Time:** ~4 hours
> **You will:** use MITRE ATT&CK and MITRE ATLAS as a common language for MCP attacks, and walk through nine tactics (Reconnaissance to Impact) with an MCP-specific example and a detection idea for each.

| | |
|---|---|
| **Prerequisites** | [Lesson 01](01-mcp-attack-surface.md); the general lesson [CAISP ch2, lesson 02: ATT&CK vs ATLAS and the 14 tactics](../../caisp-course/ch2-understanding-and-attacking-llms/02-attck-vs-atlas-and-the-14-tactics.md) (read it first: this lesson does not repeat the general definitions) |
| **Labs** | [01 recon](labs/01-recon-enumeration/README.md), [02 poisoning](labs/02-tool-poisoning/README.md), [03 injection](labs/03-tool-response-injection/README.md), [04 rug-pull](labs/04-rug-pull/README.md), [05 cross-server](labs/05-cross-server-privesc/README.md), [07 worm](labs/07-mcp-worm/README.md), [08 code exec](labs/08-code-exec-to-compromise/README.md) |
| **Syllabus lines** | Attack Tactics and Techniques: MITRE ATT&CK relevance to MCP environments · MITRE ATLAS for agentic AI systems · Reconnaissance · Resource development · Initial access · Execution · Persistence · Privilege escalation · Defense evasion · Exfiltration · Impact |
| **Maps to** | MITRE ATT&CK (Enterprise) · MITRE ATLAS · OWASP MCP Top 10 (2025, beta) · OWASP Agentic Top 10 2026 |

> **Hedge on IDs and names.** ATT&CK and ATLAS are updated several times a year. This lesson names techniques **by name as commonly seen** and gives **no technique IDs**, because IDs and names differ between versions and secondary sources. ATLAS also keeps adding agent-focused techniques (reportedly including ones about agent tool invocation and context poisoning); confirm the exact names and IDs at <https://attack.mitre.org> and <https://atlas.mitre.org> and write the version you used in any report.

---

## 1. MITRE ATT&CK relevance to MCP environments

An MCP server is software on a laptop, a build agent or a cloud VM. So the **classic IT part** of an MCP attack is ordinary ATT&CK:

- The server process runs a shell or reads files: *Command and Scripting Interpreter*, *File and Directory Discovery*.
- The server stores tokens in config files: *Unsecured Credentials*.
- A developer proxy listens on a port: *Exploit Public-Facing Application* (or a local equivalent through the browser).
- A package is replaced: *Supply Chain Compromise*.
- Data leaves through an allowed channel: *Exfiltration Over Web Service*.

ATT&CK is also what your SOC already uses. If an MCP incident is reported as ATT&CK tactics, existing detections, SIEM rules and runbooks can be reused. Cloud and identity matrices matter too: most MCP pivots end at a cloud API or a SaaS token (the pivot in [Lab 08](labs/08-code-exec-to-compromise/README.md)).

What ATT&CK does **not** describe well: a model being steered by text. That is where ATLAS comes in.

## 2. MITRE ATLAS for agentic AI systems

ATLAS uses the same tactic and technique structure for AI systems and is cross-linked with ATT&CK. For agents and MCP, the useful ATLAS ideas are:

- **Prompt injection** (direct and indirect) as a way to get *Initial Access* or *Execution* inside an AI system.
- **Poisoning of what the agent reads** (context, memory, retrieved data, tool descriptions) as persistence and defense evasion.
- **Abusing the agent's tools**: the agent becomes the thing that performs the action (reading files, sending messages, calling APIs) with the user's authority.
- **AI-specific tactics** (the general lesson explains *AI Model Access* and *AI Attack Staging*, with the reported rename to *AI Attack Adaptation*, unconfirmed). Many MCP attacks need neither: the attacker never touches the model, only the text around it.

Rule of thumb for the exam: **ATLAS for how the model is steered, ATT&CK for what happens on the machine and in the cloud afterwards.** Most MCP incidents have both.

The nine sections below follow the course order. The other five tactics of the general list (Model Access, Credential Access, Discovery, Collection, Attack Staging) appear inside these stories and in the [general lesson](../../caisp-course/ch2-understanding-and-attacking-llms/02-attck-vs-atlas-and-the-14-tactics.md).

## 3. Reconnaissance of MCP environments

**Goal:** learn what is there. **Passive:** read public configs and READMEs, search code hosts for `mcp.json` files that contain endpoints and tokens, read a server's published tool list, look at package metadata and maintainers. **Active:** connect to an endpoint and ask the protocol itself. `initialize` returns the server name, version and protocol revision. `tools/list`, `resources/list` and `prompts/list` return the full menu. A deliberately malformed `tools/call` shows how the server reports errors.

**MCP example.** An attacker scans a company's address range for HTTP endpoints that answer a JSON-RPC `initialize`. One answers without credentials and lists `read_file` and `run_shell`. Technique names in this area: *Active Scanning*, *Gather Victim Host Information*, *Search Open Technical Databases* (ATT&CK). In ATLAS the matching ideas are discovering the AI system's tools and capabilities.

**Detection ideas.**
- Log every `initialize`/`tools/list` from a new client or IP. A `tools/list` with no later `tools/call` from a user session is a scan pattern.
- Alert on anonymous requests, repeated malformed `tools/call`, and requests from outside expected ranges.
- Honeypot MCP endpoint with a fake `run_shell` tool: any call is a high-confidence alert.
- Run your own recon regularly: [Lab 01](labs/01-recon-enumeration/README.md).

## 4. Resource development tactic

**Goal:** prepare what the attack needs before touching the target.

**MCP examples.**
- Registering lookalike package or server names (typosquatting) and publishing a useful, clean first version to build trust ([primitive: server impersonation](03-mcp-attack-primitives.md#3-server-impersonation-and-typosquatting)).
- Building a malicious MCP server whose descriptions carry hidden instructions ([Lab 02](labs/02-tool-poisoning/README.md)).
- Writing the poisoned content: a public issue, a web page, a PDF, a calendar invite.
- Compromising a maintainer account or a build pipeline to publish later (see [CAISP ch6](../../caisp-course/ch6-supply-chain-attacks-in-ai/README.md)).
- Hosting an OAuth server that returns hostile metadata (the mcp-remote CVE story, [case 2](05-real-world-case-studies.md#case-2-mcp-remote-cve-2025-6514)).

ATT&CK names: *Acquire Infrastructure*, *Develop Capabilities*, *Compromise Accounts*, *Stage Capabilities*.

**Detection ideas.** This happens outside your network, so detect at **intake**: new-package checks (age, maintainer history, name similarity to known servers), registry allowlists, alerts when a server you use changes owner, and typosquat monitors on names of your own products.

## 5. Initial access tactic

**Goal:** get the first foothold.

**MCP examples.**
1. **Content that the agent reads** (indirect prompt injection): an issue, ticket, email or web page ([Lab 03](labs/03-tool-response-injection/README.md)). No network access needed.
2. **A malicious or hijacked server** that the user installs or a host connects to ([Lab 04](labs/04-rug-pull/README.md)).
3. **An unauthenticated endpoint** or a developer proxy reachable from a browser (Inspector CVE).
4. **A hostile server attacking the client**: crafted OAuth metadata leading to command execution in the client process (mcp-remote CVE).
5. **Valid accounts**: a stolen token from a config file.

ATT&CK names: *Supply Chain Compromise*, *Exploit Public-Facing Application*, *Valid Accounts*, *Phishing* (content that a human or agent follows). ATLAS idea: prompt injection through a data source.

**Detection ideas.** Alert on tool calls that follow immediately after reading content from an untrusted source and that do not match the user's request ("a ticket read was followed by a send_email"). Record a **provenance** field (which output drove this call). Alert on first-time servers, unexpected install commands, and OAuth redirects to unusual hosts.

## 6. Execution tactic

**Goal:** run attacker-chosen actions.

**MCP examples.**
- **Model-mediated execution:** the model calls a legitimate tool with attacker-chosen arguments (send this email, read this file).
- **Code execution in a tool:** `run_command`, `eval`, shell string building, argument injection ([Lab 08](labs/08-code-exec-to-compromise/README.md)).
- **Code execution in the client:** hostile server metadata (mcp-remote), CSRF to a local proxy (Inspector).
- **Install-time execution:** `npx` or `pip` scripts run on install.

ATT&CK names: *Command and Scripting Interpreter*, *User Execution*, *Exploitation for Client Execution*. ATLAS idea: the agent invokes a tool on the attacker's behalf.

**Detection ideas.** Log every tool call with arguments and the identity behind it. Flag shell metacharacters in arguments (`;`, `&&`, `$(`, backticks), tools that spawn child processes, and first-time process trees under the MCP server process (for example a `curl` child of a Node server). Prefer **argv lists** to shell strings so the pattern is rare and easy to alert on.

## 7. Persistence tactic

**Goal:** stay after the first session ends.

**MCP examples.**
- **Rug-pull:** a server that behaves after approval and keeps the approval ([Lab 04](labs/04-rug-pull/README.md)).
- **Config persistence:** the attacker adds an MCP server entry to the host's config so it loads every start (a malicious server that survives restarts).
- **Memory and notes poisoning:** a hostile instruction written to shared memory is re-read by every future session ([Lab 07](labs/07-mcp-worm/README.md)).
- **Standing tokens:** a stolen long-lived token, or an extra OAuth grant.

ATT&CK names: *Boot or Logon Autostart Execution* (config entries), *Account Manipulation*, *Valid Accounts*. ATLAS idea: poisoning the agent's memory or configuration.

**Detection ideas.** Hash and watch the host config file and the server list. Alert when a server definition changes after approval (definition pinning). Scan memory and notes writes for instruction-like text and for sources that were untrusted. Review active OAuth grants and rotate tokens.

## 8. Privilege escalation tactic

**Goal:** get more authority than the first foothold had.

**MCP examples.**
- **Cross-server escalation:** a low-trust server's output makes the agent call a high-trust server's tool ([Lab 05](labs/05-cross-server-privesc/README.md)).
- **Confused deputy:** a powerful server uses its own broad credential for a weak caller ([Lab 06](labs/06-confused-deputy/README.md)).
- **Scope creep:** tokens that gained scopes over time.
- **Process privilege:** a tool that runs as the developer's full user, or as a cloud role with wide rights ([Lab 08](labs/08-code-exec-to-compromise/README.md)).

ATT&CK names: *Abuse Elevation Control Mechanism*, *Valid Accounts*, *Exploitation for Privilege Escalation*. 

**Detection ideas.** Record "who drove this call" (user turn, tool output of server X). Alert when trust increases along the chain (the lab's `detect_escalation`). Compare each call's resource tenant with the caller's tenant. Alert on token audience mismatches and on scope requests larger than before.

## 9. Defense evasion tactic

**Goal:** avoid being noticed or blocked.

**MCP examples.**
- **Hiding instructions:** descriptions that are long or use hidden blocks, zero-width or other invisible characters, or text the UI collapses.
- **Secrecy instructions** ("do not mention this to the user").
- **Looking legitimate:** same name, same version and same definition, with the behavior change on the server side (the postmark-mcp pattern): static review sees nothing.
- **Slow and low:** exfiltrating a small amount per call, inside normal-looking arguments (a `sidenote` parameter).
- **Living off allowed tools:** using the organization's own email or ticket tool as the exfiltration channel.

ATT&CK names: *Masquerading*, *Obfuscated Files or Information*, *Impair Defenses*. 

**Detection ideas.** Normalize and scan all text the model sees, including parameter descriptions, for invisible characters and hidden blocks ([Lab 02 scanner](labs/02-tool-poisoning/README.md)). Pin schemas and reject calls with arguments outside the approved set. Audit at the egress point (mail gateway, proxy) so a change in server behavior is caught even when the definition did not change ([Lab 04 audit_egress](labs/04-rug-pull/README.md)). Show the user the **real** tool call, not the model's summary.

## 10. Exfiltration tactic

**Goal:** get data out.

**MCP examples.**
- A poisoned description makes the agent pass file contents in an extra parameter ([Lab 02](labs/02-tool-poisoning/README.md)).
- An injected instruction sends private records through `send_email`, a comment, or a public pull request (the GitHub research, [case 6](05-real-world-case-studies.md#case-6-invariant-labs-research-tool-poisoning-whatsapp-and-github)).
- A hidden BCC added by a malicious server.
- Data written to a public ticket thread ([Lab 05](labs/05-cross-server-privesc/README.md)).
- Markdown image or link URLs that carry data in the query string (see [guard-io](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/guard-io/README.md)).

ATT&CK names: *Exfiltration Over Web Service*, *Exfiltration Over C2 Channel* (not needed here: the allowed tool is the channel). 

**Detection ideas.** Egress allowlists for recipients and domains. DLP-style checks for secrets and canaries in outgoing tool arguments. Alert when a tool receives data from a higher-trust source than its own trust level (no write-down). Plant **canary tokens** in files and records: any appearance outside its home is a confirmed leak.

## 11. Impact tactic

**Goal:** cause damage.

**MCP examples.**
- **Cloud takeover** after code execution: a stolen key creates an admin user ([Lab 08](labs/08-code-exec-to-compromise/README.md)).
- **Data loss or tampering** through a destructive tool (`delete`, `drop`, `rotate_key`) called by a steered agent.
- **Cross-tenant exposure** from a logic flaw (the Asana case, [case 5](05-real-world-case-studies.md#case-5-asana-mcp-server-june-2025)).
- **Fraud:** payments, refunds, emails sent in the user's name.
- **Denial of service or cost:** loops of tool calls, runaway agents, expensive APIs (see [repo 05 multi-agent-trust, cascading failures](../../05-agent-security/multi-agent-trust/README.md)).
- **Propagation:** a worm that reaches every agent ([Lab 07](labs/07-mcp-worm/README.md)).

ATT&CK names: *Data Destruction*, *Account Access Removal*, *Financial Theft*, *Resource Hijacking*, *Service Stop*.

**Detection ideas.** Rate and volume baselines per agent and per tool. Circuit breakers that stop an agent after too many actions or failures. Human approval for destructive and financial actions. Immutable audit logs for forensics. Tested kill switches ([repo 05 monitoring-and-response](../../05-agent-security/monitoring-and-response/README.md)).

## 12. Putting it together: one story, all tactics

A realistic chain (all simulated in the labs): the attacker publishes a clean helper server (**Resource Development**), users install it, later it changes its description (**Persistence**, **Defense Evasion**). A web page the agent reads tells it to call a file tool (**Initial Access**, **Execution**). The file tool follows a symlink to a credentials file ([Lab 08](labs/08-code-exec-to-compromise/README.md): **Privilege Escalation**). The agent posts the key into a public ticket (**Exfiltration**) and the attacker later creates an admin user in the cloud (**Impact**).

## 13. Hands-on

1. Take the Lab 05 demo output and label each hop with a tactic.
2. For each of the nine sections above, write one detection rule in plain English that your current logging could support. Mark the log source you would need if you do not have it.
3. Use the CAISP lab [`00-atlas-mapping`](../../caisp-course/ch2-understanding-and-attacking-llms/labs/00-atlas-mapping/) to practice mapping narratives to tactics.

## 14. Interview Q&A

**Q: Which tactic is a malicious GitHub issue read by a coding agent?**
Initial Access (indirect prompt injection through a data source), followed by Execution (the agent calls tools) and Exfiltration (data goes out through a legitimate tool).

**Q: Why can a rug-pull defeat static review?**
Review sees a clean definition at approval time. The malicious behavior arrives later, or lives on the server side where the definition does not show it. Detection needs pinning plus runtime and egress monitoring.

## 15. References

- MITRE ATT&CK: <https://attack.mitre.org> · MITRE ATLAS: <https://atlas.mitre.org> (verify names and IDs)
- General lesson: [CAISP ch2 lesson 02](../../caisp-course/ch2-understanding-and-attacking-llms/02-attck-vs-atlas-and-the-14-tactics.md)
- [Repo 04-mcp-security](../../04-mcp-security/README.md), [05-agent-security](../../05-agent-security/README.md)
