# Chapter 2: Understanding and Attacking MCP Servers

This chapter teaches how MCP deployments are attacked: what the attack surface is, which tactics attackers follow, the attack primitives that exist because of MCP, the vulnerability classes that keep coming back, real incidents, and eight hands-on labs that run offline. You attack first, so that the defenses in [Chapter 4](../ch4-defending-and-hardening-mcp-servers/README.md) make sense.

> **Safety.** Every lab is a simulation: fake servers, canary secrets, `.example` domains, harmless payloads (echo, read a canary). Only the optional localhost HTTP server in lab 01 uses a socket, bound to `127.0.0.1` on an ephemeral port. Never test a system you do not own or have written permission to test.

## Syllabus coverage

Every line of the chapter syllabus appears below, in order. Topics are in bold; sub-topics and exercises follow them.

| Syllabus item | Where to study | Lab |
|---|---|---|
| **Introduction to the MCP Attack Surface** | [Lesson 01](01-mcp-attack-surface.md) | [01](labs/01-recon-enumeration/README.md) |
| What attackers look for in an MCP deployment | [01, section 2.1](01-mcp-attack-surface.md#21-what-attackers-look-for-in-an-mcp-deployment) | [01](labs/01-recon-enumeration/README.md) |
| Attack surface mapping for MCP environments | [01, section 2.2](01-mcp-attack-surface.md#22-attack-surface-mapping-for-mcp-environments), diagram [attack surface map](../../images/cmcpse-ch2-attack-surface-map.svg); repo [04 README](../../04-mcp-security/README.md) | [01](labs/01-recon-enumeration/README.md) (recon report) |
| Threat actor profiles and motivations targeting MCP | [01, section 2.3](01-mcp-attack-surface.md#23-threat-actor-profiles-and-motivations) | n/a |
| **Attack Tactics and Techniques** | [Lesson 02](02-attack-tactics-attck-and-atlas-for-mcp.md); general lesson [CAISP ch2 lesson 02](../../caisp-course/ch2-understanding-and-attacking-llms/02-attck-vs-atlas-and-the-14-tactics.md) | see tactic rows |
| MITRE ATT&CK relevance to MCP environments | [02, section 1](02-attack-tactics-attck-and-atlas-for-mcp.md#1-mitre-attck-relevance-to-mcp-environments) | n/a |
| MITRE ATLAS for agentic AI systems | [02, section 2](02-attack-tactics-attck-and-atlas-for-mcp.md#2-mitre-atlas-for-agentic-ai-systems) | n/a |
| Reconnaissance of MCP environments | [02, section 3](02-attack-tactics-attck-and-atlas-for-mcp.md#3-reconnaissance-of-mcp-environments) | [01](labs/01-recon-enumeration/README.md) |
| Resource development tactic | [02, section 4](02-attack-tactics-attck-and-atlas-for-mcp.md#4-resource-development-tactic) | [02](labs/02-tool-poisoning/README.md), [04](labs/04-rug-pull/README.md) |
| Initial access tactic | [02, section 5](02-attack-tactics-attck-and-atlas-for-mcp.md#5-initial-access-tactic) | [03](labs/03-tool-response-injection/README.md) |
| Execution tactic | [02, section 6](02-attack-tactics-attck-and-atlas-for-mcp.md#6-execution-tactic) | [08](labs/08-code-exec-to-compromise/README.md) |
| Persistence tactic | [02, section 7](02-attack-tactics-attck-and-atlas-for-mcp.md#7-persistence-tactic) | [04](labs/04-rug-pull/README.md), [07](labs/07-mcp-worm/README.md) |
| Privilege escalation tactic | [02, section 8](02-attack-tactics-attck-and-atlas-for-mcp.md#8-privilege-escalation-tactic) | [05](labs/05-cross-server-privesc/README.md), [06](labs/06-confused-deputy/README.md) |
| Defense evasion tactic | [02, section 9](02-attack-tactics-attck-and-atlas-for-mcp.md#9-defense-evasion-tactic) | [02](labs/02-tool-poisoning/README.md), [04](labs/04-rug-pull/README.md) |
| Exfiltration tactic | [02, section 10](02-attack-tactics-attck-and-atlas-for-mcp.md#10-exfiltration-tactic) | [02](labs/02-tool-poisoning/README.md), [05](labs/05-cross-server-privesc/README.md) |
| Impact tactic | [02, section 11](02-attack-tactics-attck-and-atlas-for-mcp.md#11-impact-tactic) | [08](labs/08-code-exec-to-compromise/README.md) |
| **MCP-Specific Attack Primitives** | [Lesson 03](03-mcp-attack-primitives.md) | labs 02 to 08 |
| Tool Poisoning attacks | [03, section 1](03-mcp-attack-primitives.md#1-tool-poisoning-attacks); repo [tool-security](../../04-mcp-security/tool-security/README.md) | [02](labs/02-tool-poisoning/README.md) |
| What tool poisoning is and why it works | [03, section 1.1](03-mcp-attack-primitives.md#11-what-tool-poisoning-is-and-why-it-works) | [02](labs/02-tool-poisoning/README.md) |
| Hiding malicious instructions in tool descriptions | [03, section 1.2](03-mcp-attack-primitives.md#12-hiding-malicious-instructions-in-tool-descriptions) | [02](labs/02-tool-poisoning/README.md) |
| Tool schema manipulation | [03, section 1.3](03-mcp-attack-primitives.md#13-tool-schema-manipulation) | [02](labs/02-tool-poisoning/README.md) (schema variant) |
| Prompt Injection via Tool Responses | [03, section 2](03-mcp-attack-primitives.md#2-prompt-injection-via-tool-responses) | [03](labs/03-tool-response-injection/README.md) |
| How tool responses become injection vectors | [03, section 2.1](03-mcp-attack-primitives.md#21-how-tool-responses-become-injection-vectors) | [03](labs/03-tool-response-injection/README.md) |
| Direct vs indirect prompt injection through MCP | [03, section 2.2](03-mcp-attack-primitives.md#22-direct-vs-indirect-prompt-injection-through-mcp) | [03](labs/03-tool-response-injection/README.md) (both) |
| Server Impersonation and Typosquatting | [03, section 3](03-mcp-attack-primitives.md#3-server-impersonation-and-typosquatting); repo [mcp-server](../../04-mcp-security/mcp-server/README.md) | [04](labs/04-rug-pull/README.md), repo [mcp-server lab](../../04-mcp-security/mcp-server/lab/) |
| Registering malicious MCP servers with similar names | [03, section 3.1](03-mcp-attack-primitives.md#31-registering-malicious-mcp-servers-with-similar-names), [05, case 1](05-real-world-case-studies.md#case-1-postmark-mcp-september-2025) | [04](labs/04-rug-pull/README.md) |
| Man-in-the-middle via fake MCP endpoints | [03, section 3.2](03-mcp-attack-primitives.md#32-man-in-the-middle-via-fake-mcp-endpoints), [05, case 2](05-real-world-case-studies.md#case-2-mcp-remote-cve-2025-6514) | n/a (analysis; see repo [authentication](../../04-mcp-security/authentication/README.md)) |
| Rug-Pull Attacks | [03, section 4](03-mcp-attack-primitives.md#4-rug-pull-attacks) | [04](labs/04-rug-pull/README.md) |
| Changing server behavior post-approval by the user or host | [03, section 4.1](03-mcp-attack-primitives.md#41-changing-server-behavior-post-approval-by-the-user-or-host) | [04](labs/04-rug-pull/README.md) |
| Dynamic tool definition manipulation | [03, section 4.2](03-mcp-attack-primitives.md#42-dynamic-tool-definition-manipulation) | [04](labs/04-rug-pull/README.md) (part A) |
| Cross-Server Privilege Escalation | [03, section 5](03-mcp-attack-primitives.md#5-cross-server-privilege-escalation); repo [multi-agent-trust](../../05-agent-security/multi-agent-trust/README.md) | [05](labs/05-cross-server-privesc/README.md) |
| Exploiting trust between MCP servers in multi-agent pipelines | [03, section 5.1](03-mcp-attack-primitives.md#51-exploiting-trust-between-mcp-servers-in-multi-agent-pipelines) | [05](labs/05-cross-server-privesc/README.md) |
| Lateral movement through chained tool calls | [03, section 5.2](03-mcp-attack-primitives.md#52-lateral-movement-through-chained-tool-calls), [05, section 7](05-real-world-case-studies.md#7-attack-chaining-across-multi-server-agentic-pipelines) | [05](labs/05-cross-server-privesc/README.md) |
| Confused Deputy Attacks | [03, section 6](03-mcp-attack-primitives.md#6-confused-deputy-attacks); repo [authentication](../../04-mcp-security/authentication/README.md) | [06](labs/06-confused-deputy/README.md) |
| Tricking a privileged MCP server into acting on behalf of an attacker | [03, section 6.1](03-mcp-attack-primitives.md#61-tricking-a-privileged-mcp-server-into-acting-on-behalf-of-an-attacker) | [06](labs/06-confused-deputy/README.md) |
| Resource Hijacking | [03, section 7](03-mcp-attack-primitives.md#7-resource-hijacking) | [08](labs/08-code-exec-to-compromise/README.md), [01](labs/01-recon-enumeration/README.md) |
| Accessing resources beyond intended scope | [03, section 7.1](03-mcp-attack-primitives.md#71-accessing-resources-beyond-intended-scope) | [08](labs/08-code-exec-to-compromise/README.md) (path escapes) |
| Sensitive data exposure through misconfigured resource endpoints | [03, section 7.2](03-mcp-attack-primitives.md#72-sensitive-data-exposure-through-misconfigured-resource-endpoints) | [01](labs/01-recon-enumeration/README.md) (RECON-05) |
| **MCP Vulnerability Classes** | [Lesson 04](04-mcp-vulnerability-classes.md) | [01](labs/01-recon-enumeration/README.md), [08](labs/08-code-exec-to-compromise/README.md) |
| Unauthenticated MCP endpoints | [04, section 1](04-mcp-vulnerability-classes.md#1-unauthenticated-mcp-endpoints) | [01](labs/01-recon-enumeration/README.md) |
| Insecure transport configurations | [04, section 2](04-mcp-vulnerability-classes.md#2-insecure-transport-configurations) | [01](labs/01-recon-enumeration/README.md) (loopback-only HTTP test) |
| Excessive tool permissions | [04, section 3](04-mcp-vulnerability-classes.md#3-excessive-tool-permissions) | [08](labs/08-code-exec-to-compromise/README.md) |
| Insufficient input and output validation | [04, section 4](04-mcp-vulnerability-classes.md#4-insufficient-input-and-output-validation) | [08](labs/08-code-exec-to-compromise/README.md), [03](labs/03-tool-response-injection/README.md) |
| Insecure prompt handling in tool schemas | [04, section 5](04-mcp-vulnerability-classes.md#5-insecure-prompt-handling-in-tool-schemas) | [02](labs/02-tool-poisoning/README.md) |
| Sensitive information leakage via error messages | [04, section 6](04-mcp-vulnerability-classes.md#6-sensitive-information-leakage-via-error-messages) | [01](labs/01-recon-enumeration/README.md) (RECON-02) |
| Insecure defaults in popular MCP SDKs | [04, section 7](04-mcp-vulnerability-classes.md#7-insecure-defaults-in-popular-mcp-sdks-and-tools) (patterns, no version claims) | [01](labs/01-recon-enumeration/README.md) (sloppy vs hardened fleet) |
| **Real-World MCP Attack Scenarios** | [Lesson 05](05-real-world-case-studies.md) | labs 04 to 08 |
| Case studies of MCP exploitation in the wild | [05, cases 1 to 6](05-real-world-case-studies.md#case-1-postmark-mcp-september-2025): postmark-mcp, mcp-remote CVE-2025-6514, Inspector CVE-2025-49596, Filesystem CVE-2025-53109/53110, Asana, Invariant Labs | [04](labs/04-rug-pull/README.md), [08](labs/08-code-exec-to-compromise/README.md), [06](labs/06-confused-deputy/README.md) |
| Attack chaining across multi-server agentic pipelines | [05, section 7](05-real-world-case-studies.md#7-attack-chaining-across-multi-server-agentic-pipelines), diagram [attack chain](../../images/cmcpse-ch2-attack-chain.svg) | [05](labs/05-cross-server-privesc/README.md) |
| Multi-agent attack propagation patterns | [05, section 8](05-real-world-case-studies.md#8-multi-agent-attack-propagation-patterns); repo [multi-agent-trust](../../05-agent-security/multi-agent-trust/README.md) | [07](labs/07-mcp-worm/README.md) |
| **Hands-on Exercises:** | [Lab index](#lab-index) | all labs |
| MCP server reconnaissance and endpoint enumeration | [01](01-mcp-attack-surface.md) | [01-recon-enumeration](labs/01-recon-enumeration/README.md) |
| Perform a tool poisoning attack on a vulnerable MCP server | [03, section 1](03-mcp-attack-primitives.md#1-tool-poisoning-attacks) | [02-tool-poisoning](labs/02-tool-poisoning/README.md) |
| Exploit prompt injection via crafted tool responses | [03, section 2](03-mcp-attack-primitives.md#2-prompt-injection-via-tool-responses) | [03-tool-response-injection](labs/03-tool-response-injection/README.md) |
| Demonstrate a rug-pull attack by modifying tool behavior post-approval | [03, section 4](03-mcp-attack-primitives.md#4-rug-pull-attacks) | [04-rug-pull](labs/04-rug-pull/README.md) |
| Cross-server privilege escalation in a multi-agent pipeline | [03, section 5](03-mcp-attack-primitives.md#5-cross-server-privilege-escalation) | [05-cross-server-privesc](labs/05-cross-server-privesc/README.md) |
| Confused deputy attack exercise | [03, section 6](03-mcp-attack-primitives.md#6-confused-deputy-attacks) | [06-confused-deputy](labs/06-confused-deputy/README.md) |
| MCP worm propagation | [05, section 8](05-real-world-case-studies.md#8-multi-agent-attack-propagation-patterns) | [07-mcp-worm](labs/07-mcp-worm/README.md) |
| Code execution to complete compromise | [04, classes 3 and 4](04-mcp-vulnerability-classes.md#3-excessive-tool-permissions), [05, case 4](05-real-world-case-studies.md#case-4-anthropic-filesystem-mcp-server-cve-2025-53109--cve-2025-53110) | [08-code-exec-to-compromise](labs/08-code-exec-to-compromise/README.md) |

## Lab index

Run everything: `.venv/Scripts/python -m pytest cmcpse-course/ch2-understanding-and-attacking-mcp-servers` (90 tests, about 4 seconds). Each lab has `demo.py` with real output pasted in its README. Every lab is **self-contained** (it carries its own copy of the small JSON-RPC server `rpc.py`) and shows **vulnerable vs defended** code.

| Lab | Exercise | Vulnerable behavior | Defended behavior | Tests |
|---|---|---|---|---|
| [01-recon-enumeration](labs/01-recon-enumeration/README.md) | Recon and endpoint enumeration | Open endpoints, verbose errors, shell tool, `.env` resource | Auth, generic errors, narrow tools: scan finds nothing | 11 |
| [02-tool-poisoning](labs/02-tool-poisoning/README.md) | Tool poisoning, with schema variant (`sidenote`) | Canary file read and exfiltrated through a hidden parameter | Scanner, baseline pinning, confined `read_file` | 12 |
| [03-tool-response-injection](labs/03-tool-response-injection/README.md) | Injection via tool responses, direct vs indirect | Ticket text makes the agent mail a private record out | Quarantine, taint approval, egress allowlist | 9 |
| [04-rug-pull](labs/04-rug-pull/README.md) | Rug-pull after approval | Swapped description; backdoored release with BCC | Definition pinning, lockfile integrity, egress audit | 11 |
| [05-cross-server-privesc](labs/05-cross-server-privesc/README.md) | Cross-server escalation and lateral movement | Web page to ticket to vault to public ticket | Trust levels: no read-up, no write-down; audit rule | 7 |
| [06-confused-deputy](labs/06-confused-deputy/README.md) | Confused deputy (plus OAuth proxy) | Service role reads any tenant; consent reuse | Audience, scope, tenant checks, row-level security, per-client consent | 11 |
| [07-mcp-worm](labs/07-mcp-worm/README.md) | Worm via tool outputs and shared memory, N agents | One message infects all agents | Output guard, quarantine, purge, containment | 10 |
| [08-code-exec-to-compromise](labs/08-code-exec-to-compromise/README.md) | Code execution to compromise | Shell injection, prefix and symlink escape, credentials, fake cloud admin | argv-only ping, resolve-then-contain, unprivileged user, scoped keys | 19 |

Existing repo labs that go with this chapter: [04 mcp-server lab](../../04-mcp-security/mcp-server/lab/) (typosquat, impostor, shadow tool, registry), [04 tool-security lab](../../04-mcp-security/tool-security/lab/) (poisoning scanner, traversal, SSRF), [04 authentication lab](../../04-mcp-security/authentication/lab/) (confused deputy, passthrough), [04 secure-operations lab](../../04-mcp-security/secure-operations/lab/), [05 multi-agent-trust lab](../../05-agent-security/multi-agent-trust/lab/), and the [CAISP ch7 worm simulation](../../caisp-course/ch7-emerging-threats-governance-compliance/labs/ai-worm-simulation/worm_sim.py).

## Learning order

1. [Lesson 01](01-mcp-attack-surface.md), then run [lab 01](labs/01-recon-enumeration/README.md) (about 3 hours).
2. Read the general [ATT&CK vs ATLAS lesson](../../caisp-course/ch2-understanding-and-attacking-llms/02-attck-vs-atlas-and-the-14-tactics.md), then [Lesson 02](02-attack-tactics-attck-and-atlas-for-mcp.md) (about 5 hours).
3. [Lesson 03](03-mcp-attack-primitives.md) with labs 02 to 06, one primitive at a time: run the demo, read the vulnerable code, read the defended code, run the tests (about 12 hours).
4. [Lesson 04](04-mcp-vulnerability-classes.md) with lab 08 (about 5 hours).
5. [Lesson 05](05-real-world-case-studies.md) with lab 07 (about 5 hours).
6. Read the repo [04-mcp-security](../../04-mcp-security/README.md) module in parallel, then go to [Chapter 3](../ch3-threat-modeling-mcp-architectures/README.md) and [Chapter 4](../ch4-defending-and-hardening-mcp-servers/README.md).

## Mapping to OWASP

**OWASP MCP Top 10 (2025, beta; verify at source)**

| ID | Name | Lessons and labs in this chapter |
|---|---|---|
| MCP01 | Token Mismanagement & Secret Exposure | [04 section 6](04-mcp-vulnerability-classes.md#6-sensitive-information-leakage-via-error-messages), [01](labs/01-recon-enumeration/README.md) (RECON-02), [08](labs/08-code-exec-to-compromise/README.md) (credentials file) |
| MCP02 | Privilege Escalation via Scope Creep | [04 section 3](04-mcp-vulnerability-classes.md#3-excessive-tool-permissions), [03 section 5](03-mcp-attack-primitives.md#5-cross-server-privilege-escalation), [05](labs/05-cross-server-privesc/README.md) |
| MCP03 | Tool Poisoning | [03 section 1](03-mcp-attack-primitives.md#1-tool-poisoning-attacks), [02](labs/02-tool-poisoning/README.md), [04](labs/04-rug-pull/README.md) |
| MCP04 | Software Supply Chain Attacks & Dependency Tampering | [03 section 3](03-mcp-attack-primitives.md#3-server-impersonation-and-typosquatting), [05 cases 1 and 2](05-real-world-case-studies.md#case-1-postmark-mcp-september-2025), [04](labs/04-rug-pull/README.md) |
| MCP05 | Command Injection & Execution | [04 section 4](04-mcp-vulnerability-classes.md#4-insufficient-input-and-output-validation), [08](labs/08-code-exec-to-compromise/README.md) |
| MCP06 | Prompt Injection via Contextual Payloads | [03 section 2](03-mcp-attack-primitives.md#2-prompt-injection-via-tool-responses), [03](labs/03-tool-response-injection/README.md), [07](labs/07-mcp-worm/README.md) |
| MCP07 | Insufficient Authentication & Authorization | [04 sections 1 and 2](04-mcp-vulnerability-classes.md#1-unauthenticated-mcp-endpoints), [03 section 6](03-mcp-attack-primitives.md#6-confused-deputy-attacks), [01](labs/01-recon-enumeration/README.md), [06](labs/06-confused-deputy/README.md) |
| MCP08 | Lack of Audit and Telemetry | Detection ideas in [02](02-attack-tactics-attck-and-atlas-for-mcp.md); audit logs in labs [05](labs/05-cross-server-privesc/README.md) and [06](labs/06-confused-deputy/README.md); defended in repo [secure-operations](../../04-mcp-security/secure-operations/README.md) |
| MCP09 | Shadow MCP Servers | [01 section 2.2](01-mcp-attack-surface.md#22-attack-surface-mapping-for-mcp-environments) (inventory); repo [secure-operations](../../04-mcp-security/secure-operations/README.md) |
| MCP10 | Context Injection & Over-Sharing | [03 section 7](03-mcp-attack-primitives.md#7-resource-hijacking), [05 section 8](05-real-world-case-studies.md#8-multi-agent-attack-propagation-patterns), [07](labs/07-mcp-worm/README.md) (shared memory) |

**OWASP Top 10 for Agentic Applications 2026 (ASI; verify at source)**

| ID | Name | Where in this chapter |
|---|---|---|
| ASI01 | Agent Goal Hijack | Injection via tool responses ([03](labs/03-tool-response-injection/README.md)) |
| ASI02 | Tool Misuse and Exploitation | Tool poisoning, excessive permissions ([02](labs/02-tool-poisoning/README.md), [08](labs/08-code-exec-to-compromise/README.md)) |
| ASI03 | Identity and Privilege Abuse | Confused deputy ([06](labs/06-confused-deputy/README.md)) |
| ASI04 | Agentic Supply Chain Vulnerabilities | Typosquatting, rug-pull, postmark-mcp ([04](labs/04-rug-pull/README.md)) |
| ASI05 | Unexpected Code Execution | Code execution to compromise ([08](labs/08-code-exec-to-compromise/README.md)) |
| ASI06 | Memory and Context Poisoning | Shared memory worm ([07](labs/07-mcp-worm/README.md)) |
| ASI07 | Insecure Inter-Agent Communication | Cross-server and multi-agent chains ([05](labs/05-cross-server-privesc/README.md), [07](labs/07-mcp-worm/README.md)) |
| ASI08 | Cascading Failures | Propagation patterns ([05 section 8](05-real-world-case-studies.md#8-multi-agent-attack-propagation-patterns)) |
| ASI09 | Human-Agent Trust Exploitation | Approval screens that hide poisoning ([03 section 1.1](03-mcp-attack-primitives.md#11-what-tool-poisoning-is-and-why-it-works)) |
| ASI10 | Rogue Agents | Worm containment, quarantine ([07](labs/07-mcp-worm/README.md)) |

## Exam tips

- **Name the primitive, the mechanism and the fix** in one breath. "Rug-pull: server changes behavior after approval; pin definitions and installs by hash, re-approve on change, audit egress."
- **Know what each defense cannot see.** Definition pinning misses server-side behavior changes. Scanners miss paraphrased injections. Egress audit sees outcomes, not intent.
- **Prefer deterministic controls to model-based ones.** Anything that relies on the model "behaving" is a weak answer.
- **Tool poisoning vs injection via tool responses:** poisoning is in the *definition* (description, schema); response injection is in the *result*. Rug-pull is poisoning or behavior change *after* approval.
- **Direct vs indirect injection:** direct uses the writer's own rights, indirect borrows the victim's.
- **Case studies:** be able to give year, root cause, fix and lesson for each of the six. For numbers (CVSS, downloads, customers) say "as reported".
- **Hedge IDs.** Do not quote ATT&CK or ATLAS technique IDs from memory; name techniques and say "verify at the source".
- **Insecure defaults:** talk about *patterns* and how to *test* them, not about specific SDK flaws you cannot verify.

## 15 exam-style questions

<details>
<summary>1. List three things an attacker looks for in an MCP deployment and how you would find each as a defender.</summary>

Exposed or unauthenticated endpoints (send `initialize` with no credentials), tokens and secrets in configs (search `mcp.json`, env files and logs), over-privileged tools (read `tools/list`, check scopes and process owner), and untrusted package sources (inventory install commands and publishers). Also content sources that agents read. The recon lab automates the first and third.
</details>

<details>
<summary>2. Why does tool poisoning work even when the user "approved" the tool?</summary>

The user approves a name or a short summary. The model reads the full description and every parameter description, and treats them as guidance. Hidden blocks, invisible characters and instructions in schema property descriptions are invisible to the user. Defense: show full text, scan it, pin it, and enforce the approved schema on every call.
</details>

<details>
<summary>3. What is tool schema manipulation and how do you detect it?</summary>

Putting instructions in a parameter description or adding an extra parameter (for example `sidenote`) to carry stolen data. Detect it by scanning all schema strings, diffing against the approved baseline, blocking calls with extra arguments, and flagging free-text parameters with no limits.
</details>

<details>
<summary>4. Compare direct and indirect prompt injection through MCP.</summary>

Direct: the user's own input; it uses the user's own rights. Indirect: third-party text in tool results, resources or prompts; it borrows the victim agent's rights, so it is more dangerous. Deterministic defenses (taint, approval, egress allowlist, least privilege) matter more than detectors.
</details>

<details>
<summary>5. How would you stop an agent from leaking data after it read a malicious ticket?</summary>

Mark the ticket tool's output as untrusted; after untrusted content is in context, require human approval for side-effect tools; allowlist outbound recipients and domains; give the agent only the tools and data it needs; quarantine instruction-like text; and keep canaries to prove leaks.
</details>

<details>
<summary>6. What is a rug-pull, and why can a definition hash miss it?</summary>

A rug-pull is a server that behaves until approved and changes later. A definition hash catches changes to the definition, but in the postmark-mcp pattern the definition was unchanged and the code added a hidden BCC. You need lockfiles with integrity hashes, diff review, and egress auditing as well.
</details>

<details>
<summary>7. What does `notifications/tools/list_changed` mean for security?</summary>

A server may change its tool list while connected. Treat it as a security event: re-fetch, compare with the pinned baseline, drop drifted tools, and require re-approval. Also scan from the same client identity the host uses, because a server could serve different definitions to different clients.
</details>

<details>
<summary>8. Explain cross-server privilege escalation. How do trust levels help?</summary>

A low-trust server's output steers the model to call a high-trust server's tool, because both share one context. Trust levels with no read-up and no write-down rules require approval when lower-trust content is in context before a higher-trust tool call, and when higher-trust data is in context before a lower-trust sink. Separate contexts and per-server credentials reduce it further.
</details>

<details>
<summary>9. Describe the confused deputy problem in MCP with one example and its fix.</summary>

A billing server uses its service role to export any tenant's invoices for any caller. Fix: on-behalf-of tokens with audience binding, scope and tenant checks in the server, and row-level security in the data store. In OAuth proxies: per-client consent and exact redirect matching.
</details>

<details>
<summary>10. Why is error-message leakage worse in an agentic system?</summary>

Errors enter the model's context and can be repeated to users, written to tickets or sent out. Attackers can also trigger errors on purpose. Return generic errors with a correlation id and log details server-side with redaction.
</details>

<details>
<summary>11. How do you talk about "insecure defaults in MCP SDKs" without making false claims?</summary>

Describe patterns: binding to all interfaces, no authentication on HTTP, no Origin checks, verbose errors, debug proxies like the Inspector issue. Say that you test any default install yourself, read the SDK's current docs and advisories, and verify at source.
</details>

<details>
<summary>12. What went wrong in the Inspector CVE-2025-49596 and what are the lessons?</summary>

A developer tool with a proxy that could start processes had no authentication between its UI and proxy, so a malicious web page could reach it and get code execution (about CVSS 9.4 as reported; fixed in 0.14.1). Lessons: dev tools are attack surface; localhost is not a boundary; use tokens, Origin/Host checks and loopback binding.
</details>

<details>
<summary>13. What happened in the Filesystem MCP server CVEs (CVE-2025-53109 and CVE-2025-53110), and how do you write a safe path check?</summary>

Symlink and path-prefix weaknesses let paths escape the allowed directory. A safe check resolves symlinks first, then compares path components (not string prefixes), denies by default, and runs under an unprivileged OS user so that a bug is not fatal. Verify details in the advisories.
</details>

<details>
<summary>14. What is the lethal trifecta, and how did the GitHub MCP research illustrate it?</summary>

Private data, untrusted content and a way to communicate out in one agent session. In the research, a malicious public issue made an agent with a broad token read private repositories and post their content in a public pull request. Remove any one element: scope tokens per repo, isolate contexts, or block public writes.
</details>

<details>
<summary>15. How do worms spread across MCP agents and how do you contain them?</summary>

Through messages (spread follows the contact graph) and shared memory (all readers at once), plus tool outputs read by many agents. Contain with an output guard that blocks replication of untrusted inbound text, quarantine of the agent, purging shared memory, signed inter-agent messages, and a practiced incident runbook. Fan-out caps only slow a worm.
</details>

## References

- Model Context Protocol specification, authorization and security best practices: <https://modelcontextprotocol.io/specification> (a 2026-07-28 revision appears to be the latest; verify)
- OWASP MCP Top 10 (2025, beta) and OWASP Top 10 for Agentic Applications 2026 (verify at source)
- MITRE ATT&CK <https://attack.mitre.org> and MITRE ATLAS <https://atlas.mitre.org>
- Public write-ups: Koi Security and Snyk (postmark-mcp), JFrog (CVE-2025-6514), Oligo (CVE-2025-49596), advisories for CVE-2025-53109 and CVE-2025-53110, Asana's June 2025 disclosure, Invariant Labs (tool poisoning, WhatsApp MCP, GitHub MCP). Find the originals and verify details.
- Cohen, Bitton, Nassi, Morris II (2024)
- Repo: [04-mcp-security](../../04-mcp-security/README.md), [05-agent-security](../../05-agent-security/README.md), [caisp-course ch2](../../caisp-course/ch2-understanding-and-attacking-llms/README.md)
