# Chapter 4: Computer-Use, Browser and Coding Agents

This chapter covers agents that **act on a computer**: coding agents in a terminal or editor, browser agents and computer-use agents. You learn the landscape (including the OpenClaw family), how each kind is attacked, the OpenClaw incidents as a case study, and how to defend them with sandboxes, containers, egress control, approvals and audit plugins. Eight labs run offline.

> **Safety.** Every lab is a simulation: a gateway bound to `127.0.0.1` (ephemeral port, started and stopped in tests), mock agents, fixtures, canary secrets, `.example` domains. No command is ever executed, nothing is fetched, and nothing touches a real OpenClaw instance. Never test systems you do not own.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Tool names, numbers and relationships here are hedged: **verify at the source**.

## Syllabus coverage

| Syllabus item | Where to study | Lab |
|---|---|---|
| The Coding and Computer-Use Agent Landscape | [Lesson 01](01-the-coding-and-computer-use-agent-landscape.md) | n/a |
| Coding agents: OpenCode and comparable CLI-based coding agents | [01 section 2](01-the-coding-and-computer-use-agent-landscape.md#2-coding-agents-opencode-and-other-cli-agents) | n/a |
| The OpenClaw ecosystem | [01 section 3](01-the-coding-and-computer-use-agent-landscape.md#3-the-openclaw-ecosystem) | n/a |
| OpenClaw | [01 section 3.1](01-the-coding-and-computer-use-agent-landscape.md#31-openclaw-and-its-history) (history: Clawdbot, Moltbot, OpenClaw) | [openclaw-misconfiguration](labs/openclaw-misconfiguration/README.md) |
| NanoClaw, MiniClaw, SecureClaw, NemoClaw | [01 section 3.2](01-the-coding-and-computer-use-agent-landscape.md#32-the-spin-offs-and-hardening-tools) | [small-model-secure-harness](labs/small-model-secure-harness/README.md), [harness-security-audit](labs/harness-security-audit/README.md) |
| ClawHub skill marketplace | [01 section 3.3](01-the-coding-and-computer-use-agent-landscape.md#33-clawhub-the-skill-marketplace) | [skill-vetting](labs/skill-vetting/README.md) |
| VSCode-integrated agent extensions | [01 section 4](01-the-coding-and-computer-use-agent-landscape.md#4-vs-code-integrated-agent-extensions) | n/a |
| Browser-driving | [01 section 5](01-the-coding-and-computer-use-agent-landscape.md#5-browser-driving-and-computer-use-agents) | [browser-agent-page-injection](labs/browser-agent-page-injection/README.md) |
| computer-use agents | [01 section 5](01-the-coding-and-computer-use-agent-landscape.md#5-browser-driving-and-computer-use-agents) | [browser-agent-page-injection](labs/browser-agent-page-injection/README.md) |
| How agents perceive and act on a screen/DOM | [01 section 6](01-the-coding-and-computer-use-agent-landscape.md#6-how-agents-perceive-and-act-on-a-screen-or-dom) (with SVG) | [browser-agent-page-injection](labs/browser-agent-page-injection/README.md) |
| Attacking Coding Agents | [Lesson 02](02-attacking-coding-agents.md) | [coding-agent-readme-injection](labs/coding-agent-readme-injection/README.md) |
| Prompt injection via various sources | [02 section 1](02-attacking-coding-agents.md#1-prompt-injection-via-various-sources); repo [prompt injection](../../02-llm-security/prompt-injection/README.md) | [coding-agent-readme-injection](labs/coding-agent-readme-injection/README.md) |
| Supply-chain injection through packages or marketplace skills | [02 section 2](02-attacking-coding-agents.md#2-supply-chain-injection-through-packages-or-marketplace-skills); [CAISP ch6](../../caisp-course/ch6-supply-chain-attacks-in-ai/README.md) | [skill-vetting](labs/skill-vetting/README.md) |
| Escaping the intended repository/workspace scope | [02 section 3](02-attacking-coding-agents.md#3-escaping-the-intended-repositoryworkspace-scope) | [workspace-escape](labs/workspace-escape/README.md) |
| Abusing agent-granted shell, filesystem, or network access | [02 section 4](02-attacking-coding-agents.md#4-abusing-agent-granted-shell-filesystem-or-network-access) | [coding-agent-readme-injection](labs/coding-agent-readme-injection/README.md), [workspace-escape](labs/workspace-escape/README.md) |
| Case study: OpenClaw's documented exposed-gateway and malicious-skill incidents | [Lesson 03](03-openclaw-case-study.md) | [openclaw-misconfiguration](labs/openclaw-misconfiguration/README.md), [skill-vetting](labs/skill-vetting/README.md) |
| Attacking Browser and Computer-Use Agents | [Lesson 04](04-attacking-browser-and-computer-use-agents.md) | [browser-agent-page-injection](labs/browser-agent-page-injection/README.md) |
| Malicious page content as an indirect prompt-injection vector | [04 section 1](04-attacking-browser-and-computer-use-agents.md#1-malicious-page-content-as-an-indirect-prompt-injection-vector) | [browser-agent-page-injection](labs/browser-agent-page-injection/README.md) |
| Clickjacking and UI-manipulation attacks against visual/DOM-parsing agents | [04 section 2](04-attacking-browser-and-computer-use-agents.md#2-clickjacking-and-ui-manipulation-attacks) | [browser-agent-page-injection](labs/browser-agent-page-injection/README.md) (fake "Allow" overlay) |
| Credential and session exposure through agent-driven browsing | [04 section 3](04-attacking-browser-and-computer-use-agents.md#3-credential-and-session-exposure-through-agent-driven-browsing) | [browser-agent-page-injection](labs/browser-agent-page-injection/README.md) (autofill) |
| Defending Computer-Use and Coding Agents | [Lesson 05](05-defending-computer-use-and-coding-agents.md) | all defense labs |
| Workspace and filesystem sandboxing | [05 section 1](05-defending-computer-use-and-coding-agents.md#1-workspace-and-filesystem-sandboxing); repo [sandboxing](../../05-agent-security/sandboxing/README.md) | [workspace-escape](labs/workspace-escape/README.md) |
| Container isolation as a security model | [05 section 2](05-defending-computer-use-and-coding-agents.md#2-container-isolation-as-a-security-model); repo [Docker](../../06-ai-devsecops/docker/README.md) | [workspace-escape](labs/workspace-escape/README.md) |
| Hardened forks vs. application-level permissions | [05 section 3](05-defending-computer-use-and-coding-agents.md#3-hardened-forks-vs-application-level-permissions); repo [permissions](../../05-agent-security/permissions/README.md) | [workspace-escape](labs/workspace-escape/README.md), [harness-security-audit](labs/harness-security-audit/README.md) |
| Egress control and network allow-listing for agent processes | [05 section 4](05-defending-computer-use-and-coding-agents.md#4-egress-control-and-network-allow-listing-for-agent-processes) | [browser-agent-page-injection](labs/browser-agent-page-injection/README.md), [harness-security-audit](labs/harness-security-audit/README.md) (NET-01) |
| Human-approval checkpoints for destructive or irreversible actions | [05 section 5](05-defending-computer-use-and-coding-agents.md#5-human-approval-checkpoints-for-destructive-or-irreversible-actions) | [human-approval-checkpoints](labs/human-approval-checkpoints/README.md) |
| Auditing and hardening a harness with a purpose-built security plugin | [05 section 6](05-defending-computer-use-and-coding-agents.md#6-auditing-and-hardening-a-harness-with-a-security-plugin) | [harness-security-audit](labs/harness-security-audit/README.md) |
| Hands-on Exercises: | Labs below | [Lab index](#lab-index) |
| Standing Up OpenClaw and Reproducing a Documented Misconfiguration | [03 section 2](03-openclaw-case-study.md#2-incident-1-exposed-gateways-with-insecure-defaults) | [openclaw-misconfiguration](labs/openclaw-misconfiguration/README.md) (offline twin + hedged real setup guide) |
| Prompt Injecting a Coding Agent via a Malicious README and Commit Message | [02 section 1](02-attacking-coding-agents.md#1-prompt-injection-via-various-sources) | [coding-agent-readme-injection](labs/coding-agent-readme-injection/README.md) |
| Auditing and Hardening an Agent Harness Using a Security Audit Plugin | [05 section 6](05-defending-computer-use-and-coding-agents.md#6-auditing-and-hardening-a-harness-with-a-security-plugin) | [harness-security-audit](labs/harness-security-audit/README.md) |
| Comparing Workspace Escape Resistance Across Standard vs. Container-Isolated Agent Runtimes | [02 section 3](02-attacking-coding-agents.md#3-escaping-the-intended-repositoryworkspace-scope), [05 section 2](05-defending-computer-use-and-coding-agents.md#2-container-isolation-as-a-security-model) | [workspace-escape](labs/workspace-escape/README.md) |
| Deploying a Small-Model-Friendly Secure Harness | [05 section 7](05-defending-computer-use-and-coding-agents.md#7-putting-it-together-a-small-model-friendly-secure-harness) | [small-model-secure-harness](labs/small-model-secure-harness/README.md) |
| Vetting a Marketplace Skill Before Installation | [02 section 2](02-attacking-coding-agents.md#2-supply-chain-injection-through-packages-or-marketplace-skills) | [skill-vetting](labs/skill-vetting/README.md) |
| Attacking a Browser/Computer-Use Agent via Malicious Page Content | [Lesson 04](04-attacking-browser-and-computer-use-agents.md) | [browser-agent-page-injection](labs/browser-agent-page-injection/README.md) |
| Enforcing Human-Approval Checkpoints for Destructive Agent Actions | [05 section 5](05-defending-computer-use-and-coding-agents.md#5-human-approval-checkpoints-for-destructive-or-irreversible-actions) | [human-approval-checkpoints](labs/human-approval-checkpoints/README.md) |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| "OpenClaw" as if it were one stable product | It was **Clawdbot**, then **Moltbot**, then **OpenClaw** (renamed 30 Jan 2026). Old tutorials, domains and packages use the old names, and **typosquats** appeared during the renames. In Feb 2026 it was reported to be moving toward an independent foundation (with OpenAI support) as its creator joined OpenAI. Check the project's own announcements. |
| "NanoClaw, MiniClaw, SecureClaw, NemoClaw" as a fixed set | These are young, fast-moving projects. Reported roles: NemoClaw (NVIDIA; kernel sandbox plus out-of-process policy, does not review skill code), NanoClaw (OS-level containment), SecureClaw (about 56 audit checks from OWASP ASI and MITRE ATLAS), MiniClaw (lightweight, small-model-friendly). Names, scope and maintainers may change; confirm on the repos. |
| "ClawHub skill marketplace" as a trusted catalogue | Early 2026 research reported the **ClawHavoc** malicious-skill campaign (341 of about 2,857 skills flagged in an initial audit, more later; mostly infostealers). Treat any marketplace as a supply chain. |
| Exposed gateways and a token-theft bug as "documented incidents" | Reported: about 135,000 internet-exposed instances (SecurityScorecard; counts vary) and CVE-2026-25253 (about CVSS 8.8, patched, disclosed around 30 Jan 2026). Fixed releases exist; update. |
| "OWASP" framework for agents | The OWASP Top 10 for Agentic Applications 2026 (ASI01 to ASI10) is the current agent list; the LLM Top 10 also has a 2026 edition. |
| "VSCode-integrated agent extensions" | Agent surfaces change fast (for example Copilot agent mode, Continue, Cline, and editor-to-agent protocols such as Zed's Agent Client Protocol). Check current features. |

## Learning order

1. [Lesson 01](01-the-coding-and-computer-use-agent-landscape.md) (landscape, perception). About 3 hours.
2. [Lesson 02](02-attacking-coding-agents.md), then labs [coding-agent-readme-injection](labs/coding-agent-readme-injection/README.md) and [workspace-escape](labs/workspace-escape/README.md). About 6 hours.
3. [Lesson 03](03-openclaw-case-study.md), then [openclaw-misconfiguration](labs/openclaw-misconfiguration/README.md) and [skill-vetting](labs/skill-vetting/README.md). About 5 hours.
4. [Lesson 04](04-attacking-browser-and-computer-use-agents.md) and [browser-agent-page-injection](labs/browser-agent-page-injection/README.md). About 4 hours.
5. [Lesson 05](05-defending-computer-use-and-coding-agents.md), then [human-approval-checkpoints](labs/human-approval-checkpoints/README.md), [harness-security-audit](labs/harness-security-audit/README.md) and [small-model-secure-harness](labs/small-model-secure-harness/README.md). About 7 hours.
6. Read the repo [05-agent-security](../../05-agent-security/README.md) module in parallel, then go to [Chapter 5](../ch5-multi-agent-systems-and-agent-identity/README.md).

## Lab index

All labs run offline: `.venv/Scripts/python -m pytest caase-course/ch4-computer-use-browser-and-coding-agents`.

| Lab | Course exercise | Tests |
|---|---|---|
| [openclaw-misconfiguration](labs/openclaw-misconfiguration/README.md) | Standing Up OpenClaw and Reproducing a Documented Misconfiguration | 14 |
| [coding-agent-readme-injection](labs/coding-agent-readme-injection/README.md) | Prompt Injecting a Coding Agent via a Malicious README and Commit Message | 12 |
| [harness-security-audit](labs/harness-security-audit/README.md) | Auditing and Hardening an Agent Harness Using a Security Audit Plugin | 19 |
| [workspace-escape](labs/workspace-escape/README.md) | Comparing Workspace Escape Resistance Across Standard vs. Container-Isolated Agent Runtimes | 10 |
| [small-model-secure-harness](labs/small-model-secure-harness/README.md) | Deploying a Small-Model-Friendly Secure Harness | 19 |
| [skill-vetting](labs/skill-vetting/README.md) | Vetting a Marketplace Skill Before Installation | 11 |
| [browser-agent-page-injection](labs/browser-agent-page-injection/README.md) | Attacking a Browser/Computer-Use Agent via Malicious Page Content | 16 |
| [human-approval-checkpoints](labs/human-approval-checkpoints/README.md) | Enforcing Human-Approval Checkpoints for Destructive Agent Actions | 29 |

## Mapping to OWASP Agentic Top 10 2026 (verify at source)

| ID | Name | Where in this chapter |
|---|---|---|
| ASI01 | Agent Goal Hijack | README and page injection ([02](02-attacking-coding-agents.md), [04](04-attacking-browser-and-computer-use-agents.md)) |
| ASI02 | Tool Misuse and Exploitation | Shell, filesystem and network abuse ([02 section 4](02-attacking-coding-agents.md#4-abusing-agent-granted-shell-filesystem-or-network-access)) |
| ASI03 | Identity and Privilege Abuse | Exposed gateways, session reuse ([03](03-openclaw-case-study.md), [04 section 3](04-attacking-browser-and-computer-use-agents.md#3-credential-and-session-exposure-through-agent-driven-browsing)) |
| ASI04 | Agentic Supply Chain Vulnerabilities | ClawHavoc, skill vetting ([03](03-openclaw-case-study.md), [skill-vetting](labs/skill-vetting/README.md)) |
| ASI05 | Unexpected Code Execution | curl-pipe-shell, containers ([05](05-defending-computer-use-and-coding-agents.md)) |
| ASI06 | Memory and Context Poisoning | Context from pages and repos (see [chapter 3](../ch3-agent-memory-context-and-tool-use/README.md)) |
| ASI09 | Human-Agent Trust Exploitation | Approval checkpoints, fake dialogs ([human-approval-checkpoints](labs/human-approval-checkpoints/README.md)) |
| ASI10 | Rogue Agents | Audit and monitoring ([harness-security-audit](labs/harness-security-audit/README.md)) |

## Exam tips

- **The model proposes; code and people decide.** Any answer that relies on the model refusing is weak.
- **Two layers per attack.** For each attack give one preventive and one containing control (for example: approval for the command, and a sandbox with egress control).
- **Know why `localhost` is not a boundary:** the user's own browser connects web pages to local services.
- **DOM versus screenshot:** DOM agents are fooled by hidden text and alt text; screenshot agents by fake dialogs and overlays.
- **A skill is text plus code.** That is why marketplaces are a supply chain.
- **Path checks:** canonicalise first, then compare path components. A string prefix check is the classic bug.
- **App-level permissions are not a boundary; containers share a kernel.** Say what each cannot do.
- **Hedge numbers:** "about 135,000 exposed instances", "341 of about 2,857 skills flagged initially", "CVSS about 8.8", all "as reported". Do not quote exploit details.
- **Names:** Clawdbot, Moltbot, OpenClaw; NemoClaw, NanoClaw, SecureClaw, MiniClaw, and what each is for.

## 15 exam-style questions

<details>
<summary>1. Why are coding agents especially exposed to indirect prompt injection?</summary>

They constantly read third-party text (README files, issues, commit messages, dependencies, tool output, web pages) and they hold powerful tools (shell, files, network). The model cannot reliably separate data from instructions, so an attacker who can write in any place the agent reads can try to steer it. Defend with deterministic layers: treat repo text as data, require approval for actions that follow from it, restrict commands, and sandbox.
</details>

<details>
<summary>2. Give four sources of prompt injection for a coding agent other than the user.</summary>

README or docs (including hidden comments), commit messages and PR or issue text, code comments and dependency files, tool or build output, fetched web pages, MCP tool descriptions and results, and images or PDFs.
</details>

<details>
<summary>3. How does a malicious marketplace skill differ from a malicious library?</summary>

A skill contains instructions the agent follows and scripts it may run, so it can both steer the model and execute code. It is installed from strangers on trust. Vet install steps, obfuscation, endpoints, credential paths, name similarity, publisher age, and hash and signature; then run it in a sandbox with no secrets.
</details>

<details>
<summary>4. Name four workspace-escape techniques and the correct fix.</summary>

`..` traversal, absolute paths, symlinks, and prefix tricks such as `/work-evil` starting with `/work`, plus shell `cd`. Fix: canonicalise the path (resolve symlinks and `..`), compare path components against the real root, apply the same rule to every tool including the shell, and prefer isolation where outside paths do not exist.
</details>

<details>
<summary>5. What did reports say about OpenClaw's exposed gateways?</summary>

SecurityScorecard reported about 135,000 internet-exposed instances with insecure defaults (counts vary). Root cause: a gateway meant for one local user was reachable externally with weak defaults such as broad binding and weak or missing auth. Fix: bind to loopback, require authentication, do not expose it, update.
</details>

<details>
<summary>6. Explain CVE-2026-25253 conceptually.</summary>

Reported as a token-theft bug (about CVSS 8.8, patched, disclosed around 30 Jan 2026) where a malicious web page could cause a user's gateway token to be obtained. Concept: the user's browser can reach local services, so a local service that accepts cross-origin requests or reveals a credential can be abused by a web page. Controls: update, Origin checks, never give tokens to pages, scoped short-lived tokens, approvals for dangerous tools.
</details>

<details>
<summary>7. What was ClawHavoc and what is the lesson?</summary>

A campaign of malicious skills on the ClawHub marketplace, mostly delivering infostealers behind fake setup steps. An initial audit flagged 341 of about 2,857 skills; later counts were higher. Lesson: a marketplace is a supply chain; vet, pin, sign, sandbox and keep secrets out of the agent's environment.
</details>

<details>
<summary>8. Map the OpenClaw lessons to OWASP ASI.</summary>

Exposed gateways and token theft: ASI03 (and ASI05). Malicious skills: ASI04 (and ASI05). Approvals against stolen sessions: ASI09. Continuous audit and monitoring: ASI10. Context and page injection: ASI01 and ASI06.
</details>

<details>
<summary>9. How do DOM-reading and screenshot-reading agents differ in attack surface?</summary>

DOM agents see hidden text, off-screen elements, alt text and aria labels that humans cannot see, so they are attacked with hidden instructions. Screenshot agents see pixels, so they are attacked with fake dialogs, text in images, look-alike buttons and overlays. Both need domain allowlists, approvals and no credential autofill.
</details>

<details>
<summary>10. Describe a clickjacking-style attack on an agent and two controls.</summary>

A page shows a fake "Allow" dialog or hides an invisible button over a harmless control; the agent clicks and grants a permission or triggers a download. Controls: remove invisible and full-screen overlay elements from the action surface, treat permission prompts and downloads as human-approval actions, and re-verify the element at the click point.
</details>

<details>
<summary>11. Why is running a browser agent in your personal browser profile dangerous?</summary>

It acts with your cookies, saved passwords and logged-in sessions, so one injection can send mail, change settings or reach internal sites as you. Use a separate empty profile or disposable container browser, no autofill, scoped short-lived logins, a domain allowlist and approvals.
</details>

<details>
<summary>12. Hardened fork versus application-level permissions?</summary>

App-level permissions are checks inside the agent app and can be bypassed by a bug, a spawned shell or a fooled agent that edits its own rules. A hardened fork (NemoClaw-style) moves enforcement to the kernel and to an out-of-process policy the agent cannot change. It still does not review skill code.
</details>

<details>
<summary>13. What does a container give you, and what does it not?</summary>

It limits the filesystem view, user, capabilities, resources and network of the whole process tree. It does not limit what the agent does with what you mounted or the network you allowed, it shares the host kernel, and it does not vet skills. Combine it with least privilege, egress control and approvals.
</details>

<details>
<summary>14. List the properties of a trustworthy human-approval checkpoint.</summary>

Deterministic classification with unknown actions failing closed; the exact action shown (not a summary) with warnings about hidden characters; approval bound to a hash of that action; timeout means deny; single use and short-lived; rendered by trusted code; logged with the approver; used sparingly to avoid approval fatigue.
</details>

<details>
<summary>15. What can a SecureClaw-style audit plugin check, and what can it not?</summary>

Configuration: sandbox on, egress allowlist, approvals for destructive actions, signed and pinned skills, no secrets in the environment, tamper-evident logging, model provider allowlist, gateway bind and auth. Each maps to ASI and ATLAS and produces a score. It cannot see runtime behavior, review a hostile skill's code or detect an injection in progress, so pair it with vetting and monitoring.
</details>

## References

- OWASP GenAI Security Project: Top 10 for Agentic Applications 2026 and the LLM Top 10 2026.
- MITRE ATLAS (atlas.mitre.org); NIST AI RMF and AI 600-1; CISA and Five Eyes, "Careful Adoption of Agentic AI Services" (1 May 2026; verify).
- Reports on OpenClaw exposure (SecurityScorecard), ClawHavoc (Koi Security) and CVE-2026-25253 (verify at the original sources).
- Project pages: OpenClaw, OpenCode, Hermes Agent, NemoClaw, NanoClaw, SecureClaw, MiniClaw (check the official repositories).
- Repo: [05-agent-security](../../05-agent-security/README.md), [02 prompt injection](../../02-llm-security/prompt-injection/README.md), [06 Docker](../../06-ai-devsecops/docker/README.md), [CAISP ch6](../../caisp-course/ch6-supply-chain-attacks-in-ai/README.md), [CMCPSE ch6](../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/README.md).
