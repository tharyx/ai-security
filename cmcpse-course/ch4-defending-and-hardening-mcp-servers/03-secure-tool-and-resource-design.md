# Lesson 03: Secure tool and resource design

> **Chapter 4** · **Time:** ~4 hours · **You will:** design tools with least privilege, scope permissions, validate parameters, sanitize outputs, control resource access, avoid disclosure in descriptions, and defend against poisoning, rug pulls and tool confusion.

| | |
|---|---|
| **Syllabus lines** | Secure Tool and Resource Design (6 lines) |
| **Already in this repo (read first)** | [Module 04, tool-security](../../04-mcp-security/tool-security/README.md): poisoning scanner, shadowing, command injection, path traversal, SSRF; [Module 04, mcp-server](../../04-mcp-security/mcp-server/README.md): rug-pull hash pinning |
| **Labs** | [`defend-tool-poisoning`](labs/defend-tool-poisoning/README.md), [`defend-rug-pull`](labs/defend-rug-pull/README.md), [`defend-tool-confusion`](labs/defend-tool-confusion/README.md), [`mcp-ai-firewall`](labs/mcp-ai-firewall/README.md), [`least-privilege-tools`](labs/least-privilege-tools/README.md) |

---

## 1. Least-privilege tool design principles

* **Narrow purpose.** One tool, one verb, one object: `notes_read`, not `notes` with an `action` argument.
* **Read and write are separate tools**, so a read-only task never receives a write tool.
* **No generic executors.** Avoid `run_command`, `run_sql`, `http_request`, `eval`. If you must, wrap them: a fixed set of commands, a read-only SQL view, an allowlisted host list.
* **Describe side effects honestly** in annotations (for example the MCP `readOnlyHint` and `destructiveHint`; these are hints from the server, so the host must not trust them for security, verify in the spec).
* **Confirm before irreversible acts** (delete, send, pay) with an approval that shows the real arguments.
* **Idempotent and bounded.** Limits on rows, bytes, time and calls.

## 2. Scoping tool permissions to minimum required access

Three scopes line up:

1. **Caller scope:** the role or OAuth scopes of the user and client ([lesson 02](02-authentication-and-authorization.md)).
2. **Tool scope:** the permission each tool needs (a table, denied by default).
3. **Backend scope:** the downstream credential, for example a read-only database role, a per-user token, a directory root.

Configure it as **data**, not code: `policy.yaml` with roles → tools → limits, tested at both list and call time. See [`least-privilege-tools`](labs/least-privilege-tools/README.md). Check the *effective* permission by trying to break it: the tests call hidden tools directly, use `..` in URIs and pass an extra `role` argument.

## 3. Input validation for tool parameters

The model writes the arguments, and the model can be steered by an attacker. Treat arguments as **untrusted input**.

1. **JSON Schema first:** `type`, `enum`, `minLength`/`maxLength`, `pattern`, `minimum`/`maximum`, `required`, and **`additionalProperties: false`**.
2. **Validate again in code** (schemas are advertised to the client; the server must enforce).
3. **Allowlist over blocklist:** an enum of project names beats a regex for bad words.
4. **Canonicalise before checking:** resolve paths against a root (`..`, symlinks, percent-encoding), parse URLs and check the host after DNS resolution (SSRF), normalise Unicode.
5. **Never build a shell line or SQL string from arguments.** Use argument lists without a shell, and parameterised queries. Examples and tests: [Module 04, tool-security](../../04-mcp-security/tool-security/README.md).
6. **Limit size and depth** of arguments (the firewall lab caps request bytes).
7. **Reject unknown fields**, because "extra" fields are how a `role: admin` argument sneaks in (a test in the RBAC lab).

## 4. Output sanitization to prevent injection propagation

A tool result becomes part of the model's context. If it carries instructions, the model may follow them (**indirect prompt injection**), and then use *other* tools to act. The result is the carrier; the damage happens elsewhere ("propagation").

Defenses at the server and at a gateway:

| Control | What it does |
|---|---|
| Return **structured data**, not free text, where possible | Less room to hide instructions |
| **Strip or flag** hidden Unicode, markup, HTML comments | Removes invisible instructions |
| **Injection heuristics** on results | Catches common phrases ("ignore previous instructions", "do not tell the user") |
| **Quarantine** instead of passing a suspicious result | The model never sees it |
| **Redact secrets and PII** | Stops accidental disclosure |
| **Remove markdown images and unknown links** | Closes zero-click exfiltration (an image URL that carries data in the query) |
| **Size caps and truncation** | Prevents context flooding |
| **Taint tracking**: after untrusted content, require human approval for side effects | Breaks the chain even when detection fails |

The [`mcp-ai-firewall`](labs/mcp-ai-firewall/README.md) lab implements the first six in one gateway; its tests also show a **paraphrased injection that gets through**. Heuristics are one layer. For taint and approval see [Module 04, tool-security](../../04-mcp-security/tool-security/README.md) and [Module 05](../../05-agent-security/README.md). The CAISP companion has a related input/output guard: [guard-io](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/guard-io/README.md) and [llm-guard-sanitize](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/llm-guard-sanitize/README.md).

## 5. Resource access controls and scoping

Resources are data a server exposes by URI (`notes://team/roadmap`, `file:///...`). Controls:

* **Resource policy per role**, matched against a **normalised URI** (see the RBAC lab).
* **Roots** (client feature): the host tells the server which directories it may touch. Treat roots as a *hint* from the client; the server must still enforce its own boundary.
* **Per-user filtering** in search results and listings, not only at read time (a search hit leaks existence and titles).
* **Tenant isolation:** a tenant id comes from the verified token, never from arguments (the Asana MCP incident, June 2025, was reported as a tenant isolation flaw; verify details).
* **Output minimisation:** return the fields needed.
* **Subscriptions and templates** (`resources/subscribe`, URI templates) need the same checks on every expansion.

## 6. Avoiding information disclosure in descriptions

Descriptions and schemas are shown to the model, the user and sometimes to everyone who connects. Do not put these in them:

* Secrets, tokens, internal hostnames, IP addresses, file paths, database names, stack traces.
* Business logic or policy that you do not want a user to learn ("admins can bypass the check with ...").
* Instructions to the model that change safety behaviour. Keep descriptions short, factual and stable.

Also keep **error messages** generic and **list results** free of internal ids. Review all text with the scanner from [`defend-tool-poisoning`](labs/defend-tool-poisoning/README.md), which flags sensitive paths and long text.

## 7. Defending the tool metadata attacks (the three lab families)

| Attack | Idea | Defense | Lab |
|---|---|---|---|
| **Tool poisoning** | Hidden instructions in name, description, parameter descriptions, enums, defaults | Scan the **whole definition**, block high-severity, sanitize the rest (normalise, strip invisible, cap lengths, drop defaults), show the model a human-reviewed description | [`defend-tool-poisoning`](labs/defend-tool-poisoning/README.md) |
| **Rug pull** | Definition or version changes after approval | Pin a hash of each tool, verify at list time, on `tools/list_changed`, and **again before the call**; quarantine the changed tool only; sign the pin file; re-approve by a human | [`defend-rug-pull`](labs/defend-rug-pull/README.md) |
| **Tool confusion** | Name collision, look-alike names, "use me instead" text | Namespace as `server.tool`, allowlist, description pinning, strict name charset, look-alike detection | [`defend-tool-confusion`](labs/defend-tool-confusion/README.md) |

Order of defense in a host: allowlist the server → fetch tools → verify pins → scan and sanitize → namespace → give to the model → inspect calls and results at a gateway → log.

## 8. Quick check

1. Why is "I hid the dangerous tool from `tools/list`" not an access control?
2. Give three places an injection can hide besides the description text.
3. A tool returns a markdown image with a long query string. What is the risk and what removes it?
4. What is the time-of-check/time-of-use problem for tool definitions, and what fixes it?

## 9. References

* MCP specification: tools, resources, roots, and security best practices (verify revision).
* OWASP MCP Top 10 (beta): MCP03, MCP05, MCP06, MCP10.
* Invariant Labs research on tool poisoning (April 2025, secondary source; verify).
* [Module 04, tool-security](../../04-mcp-security/tool-security/README.md).
