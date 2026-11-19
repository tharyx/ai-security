# 07. Insecure Plugin Design (LLM07 in 2023)

> **Maps to:** 2023 LLM07 Insecure Plugin Design | 2025 and 2026: folded into Excessive Agency and Improper Output Handling | **Today's name:** tool security and MCP security.
> **Time:** 1.5 hours. **Deep lesson in this repo:** [04-mcp-security/tool-security](../../04-mcp-security/tool-security/README.md).

## Why this matters

A plugin (also called a tool, connector, action or MCP server) lets the model call another piece of software: search a calendar, query a database, send an email, run code. The model decides **what to call** and **with which arguments**, based on text that an attacker may influence. If the plugin trusts those arguments, the attacker controls the plugin.

In 2023 ChatGPT introduced plugins for third-party services. Plugins were later replaced by other mechanisms (GPT actions, tool calling and MCP), but the design problem is identical. That is why the risk list moved on while the work did not.

## What goes wrong (the 2023 framing)

| Weakness | Plain explanation |
|---|---|
| Free-text input to the plugin | The plugin takes one big string and acts on it, instead of typed, validated fields |
| No input validation | Paths, URLs, SQL, and commands pass through unchecked |
| Weak authentication/authorization | The plugin trusts the model (or the platform) as if it were the user; one shared key for all users |
| Confused deputy | The plugin has more rights than the user, and the model is tricked into using them |
| Excess functionality | One plugin offers write and delete when the task needs read |
| Chaining | Output of plugin A feeds plugin B with no checks (read private data, then send it out) |
| Insecure output | The plugin returns untrusted content that carries a prompt injection |
| Poor error handling | Errors leak internals |

## Plugin/Connected software attack scenarios

Hypothetical but realistic scenarios, each mapped to what we call it today:

1. **Search plugin with raw SQL.** The model builds a `WHERE` clause from the user's text. A crafted request returns other customers' rows. *Today:* tool argument injection; fix with parameterized queries and a read-only scoped account. See `vulnerable_tools.py` in the [tool-security lab](../../04-mcp-security/tool-security/lab/).
2. **File plugin with a path parameter.** `../../etc/secrets` escapes the intended folder. *Fix:* resolve and check the path against an allowed root.
3. **Web fetch plugin and SSRF.** The model is asked to "check this URL" and is pointed at an internal metadata address. *Fix:* URL allowlist and a block on private address ranges.
4. **Email plugin that sends on its own.** Text in a received email tells the assistant to forward the inbox. This is indirect injection plus a plugin with send rights. *Fix:* read-only by default, approval before send, recipient allowlist.
5. **Poisoned tool description.** The plugin's own description contains hidden instructions for the model ("tool poisoning" in MCP). *Fix:* review and pin tool descriptions; scan them. The [tool_scanner.py](../../04-mcp-security/tool-security/lab/tool_scanner.py) in the repo does this.
6. **Malicious or compromised third-party plugin.** A connector you install steals the data it is given. *Fix:* vendor review, sandboxing, least privilege, allowlists. It is a supply chain risk too (see [lesson 05](05-supply-chain-vulnerabilities.md)).

## Mapping to MCP and tool security

| 2023 plugin weakness | Where it is handled now |
|---|---|
| Free-text parameters, no validation | Typed tool schemas and server-side validation ([tool-security](../../04-mcp-security/tool-security/README.md)) |
| Missing authorization | Per-user credentials and authorization on every call; no shared super-key |
| Excess functionality | Task-scoped tool sets and allowlists ([permissions](../../05-agent-security/permissions/README.md)) |
| Chaining | Policy on tool sequences, data-flow rules, approvals |
| Poisoned descriptions | Tool description scanning and pinning |
| Untrusted plugin vendor | MCP server vetting, signing, isolation (see chapter 6 and the [MCP module](../../04-mcp-security/README.md)) |

## Mitigating insecure plugin design

| Control | Type |
|---|---|
| Strict typed parameters; reject anything not in the schema | Hard |
| Validate and sanitize on the tool server, every time (never trust the model) | Hard |
| Authenticate the end user; authorize each call with the user's rights (no confused deputy) | Hard |
| Least privilege: smallest scopes, read-only by default | Hard |
| Human approval for destructive, financial and outbound actions | Hard (process) |
| Allowlists for URLs, paths, recipients, commands | Hard |
| Isolate and sandbox the tool; limit network and file access | Hard |
| Rate limits, step limits and audit logs on tool calls | Hard |
| Vet, pin and review third-party plugins and their descriptions | Process |
| Test with abuse cases | Process |

## Hands-on

Run the [tool-security lab](../../04-mcp-security/tool-security/lab/) (poisoning, injection, traversal and SSRF, with a secure version) and the chapter 4 [llm-agent-vuln-scan](../ch4-ai-attacks-and-defenses-devops/labs/llm-agent-vuln-scan/README.md) (probes for tool misuse and excessive permissions). The chapter's lab index is in the [README](README.md).

## Interview Q&A

<details><summary><b>Q1. What was "Insecure Plugin Design" and where did it go?</b></summary>
It described plugins that accept unvalidated free-text input and have weak access control, so the model (or an attacker steering it) can make the plugin do harmful things. Later OWASP lists folded the problem into Excessive Agency and Improper Output Handling. In practice it is today's tool and MCP security.
</details>

<details><summary><b>Q2. What is the confused deputy problem in this context?</b></summary>
The plugin has more privilege than the user. A prompt injection gets the model to call it, and the plugin uses its own broader rights. Fix: authorize with the end user's identity, not a shared service key.
</details>

<details><summary><b>Q3. How would you secure an "execute SQL" tool?</b></summary>
Do not accept raw SQL. Offer fixed, parameterized operations. If raw SQL is unavoidable, use a read-only, row-scoped database account, a query allowlist or parser, row limits and timeouts, and log everything.
</details>

## References

- OWASP LLM Top 10 (2023 v1.1 entry for plugin design; 2025/2026 entries for Excessive Agency): https://genai.owasp.org/
- Model Context Protocol security guidance: https://modelcontextprotocol.io/ (verify at source)
- Repo: [04-mcp-security/tool-security](../../04-mcp-security/tool-security/README.md)
