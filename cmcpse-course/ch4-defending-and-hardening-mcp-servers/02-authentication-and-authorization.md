# Lesson 02: Authentication and authorization for MCP

> **Chapter 4** · **Time:** ~4 hours · **You will:** choose an authentication mechanism per transport, understand OAuth 2.x for HTTP MCP, protect stdio and legacy SSE with tokens, build RBAC for tools and resources, apply least privilege, and verify client identity.

| | |
|---|---|
| **Syllabus lines** | Authentication and Authorization (6 lines) |
| **Already in this repo (read first)** | [Module 04, authentication](../../04-mcp-security/authentication/README.md): OAuth 2.1, PKCE, RFC 9728 and 8707, token passthrough vs exchange, confused deputy, with a lab and tests |
| **This lesson adds** | A transport-by-transport view, RBAC for tools and resources, least-privilege patterns and client identity |
| **Labs** | [`defend-oauth-scopes`](labs/defend-oauth-scopes/README.md), [`least-privilege-tools`](labs/least-privilege-tools/README.md) |

---

## 1. MCP authentication mechanisms overview

The MCP specification treats authorization as **optional** but gives rules when you use it. Names and details change with each revision, so verify at modelcontextprotocol.io/specification. In outline (2025 revisions onward):

| Transport | Recommended mechanism | Notes |
|---|---|---|
| **stdio** (local child process) | Credentials from the **environment** or the OS; the parent process is the trust anchor | The spec says stdio servers should not use the HTTP authorization flow. The risk is the *environment*, see section 3 |
| **Streamable HTTP** (current standard HTTP transport) | **OAuth 2.1**-style authorization: the MCP server is an OAuth *resource server*; an external authorization server issues tokens | Protected Resource Metadata (RFC 9728), authorization server metadata (RFC 8414), PKCE, resource indicators (RFC 8707) |
| **HTTP+SSE** (the 2024-11-05 transport) | Bearer tokens in the `Authorization` header | Deprecated since the 2025-03-26 revision in favour of Streamable HTTP; the syllabus still names it, so know it as history |
| **Local HTTP on 127.0.0.1** | A per-run bearer token plus Origin and Host checks | No OAuth needed for a local helper, but "no auth on localhost" has caused real incidents (see CVE-2025-49596, MCP Inspector) |

Rules that hold for every mechanism: authenticate **every** request (not once per socket), put tokens in headers (never in URLs), keep them short-lived, never log them, and make the server decide authorization from claims it verified itself.

## 2. OAuth 2.0 for MCP over HTTP transport

The flow, in plain steps (details and attacks in [Module 04](../../04-mcp-security/authentication/README.md)):

1. The client calls the MCP server without a token and gets **401** with a `WWW-Authenticate` header that points to the server's **protected resource metadata**.
2. The client reads which **authorization server** to use and its endpoints (metadata discovery).
3. The client identifies itself (a registered client id, dynamic registration, or a client ID metadata document; verify what the current spec requires) and runs **authorization code + PKCE (S256)**. The user consents.
4. The client asks for a token with the **resource indicator** (`resource=https://notes-mcp.acme.example`) so the token is bound to this one server (the `aud` claim).
5. The client calls the server with `Authorization: Bearer <token>`. The server verifies signature, expiry, issuer, **audience** and scopes.
6. If the server needs a downstream API, it uses **token exchange** (RFC 8693) or its own credentials. It does **not** pass the user's token through ("token passthrough" is forbidden by the spec's security guidance).

What the **server** must check (the lab does exactly this, in this order, with a different error for each):

| Check | Failure | Status |
|---|---|---|
| Signature and format | forged or garbled | 401 |
| Expiry, not-before | old token | 401 |
| Issuer | wrong authorization server | 401 |
| **Audience** | token minted for another server (confused deputy) | 401 |
| **Over-scoped** | wildcard scopes, or more than the client may hold | 403 |
| Scope for this tool | token lacks the scope this tool needs | 403 `insufficient_scope`, names the missing scope |

Defending OAuth scopes means three habits:

* **Scope per tool.** `notes.read` needs `notes:read`; `notes.delete` needs `notes:write` and `notes:delete`. Tools missing from the table are denied.
* **Audience binding.** Reject tokens whose `aud` does not list this server.
* **Reject over-scoped tokens.** A real authorization server may mint a broad token by mistake (or be asked to). The resource server keeps its own list of what each client may ever hold and refuses the rest.

Run it: [`defend-oauth-scopes`](labs/defend-oauth-scopes/README.md) (12 tests). Lab tokens use HMAC (shared key); real systems use RS256 or ES256 with a JWKS endpoint so servers can verify but never mint.

## 3. Token-based auth for stdio and SSE transports

**stdio.** There is no network between host and server, so what protects it is the **process boundary** and the **environment**:

* The host starts the server with a command line from `mcp.json`. That line is code ([lesson 04](04-transport-security.md)).
* The child **inherits the parent's environment** by default. If your shell holds `AWS_SECRET_ACCESS_KEY` or `GITHUB_TOKEN`, a third-party server can read them. Pass a minimal environment (`stdio_env()` in the [transport-security lab](labs/transport-security/README.md)).
* Give the server **its own token** for the one downstream API it uses, scoped and short-lived, injected at start, or better fetched from a vault at call time ([lesson 05](05-secrets-management.md)).
* The server cannot identify the *user*. Identity must come from the host (for example an environment variable it sets) or from a downstream login. Do not let tool arguments carry "I am admin".

**SSE (legacy HTTP+SSE) and Streamable HTTP.** Send the bearer token in the `Authorization` header on **each** HTTP request, including the message POSTs. Tokens in the query string end up in logs and referrers; refuse them (a test in Module 04 checks this). Do not rely on a session id (`Mcp-Session-Id`) as authentication: it identifies a session, not a user. Draft spec work proposes changes to sessions, so verify the current text.

**Local HTTP helper.** Generate a random token at start, print it only to the parent, require it on every request, and compare with `hmac.compare_digest`.

## 4. Implementing role-based access control for tools and resources

RBAC maps **roles → tools and resources**. Roles come from the authenticated identity (token claims, directory groups), never from the model or arguments.

```yaml
roles:
  viewer:  {tools: [notes_search, notes_read], resources: ["notes://public/*"]}
  analyst: {tools: [notes_search, notes_read, notes_write], resources: ["notes://public/*", "notes://team/*"]}
  admin:   {tools: ["*all five*"], resources: ["notes://*"]}
```

Enforce it in **two places** (the lab does both with one function so they cannot drift):

| Where | Purpose | If you skip it |
|---|---|---|
| `tools/list`, `resources/list` (filter) | Hide what the caller cannot use. Smaller attack surface, less to leak, less to confuse the model | The model sees tools it can never use; descriptions leak internals |
| `tools/call`, `resources/read` (enforce) | The real check | **Filter-only servers are bypassable**: a client simply calls a tool it never saw listed. The lab test `test_filtering_alone_is_not_enough_the_classic_bug` shows the delete |

More RBAC details in the lab:

* **Unknown or missing role gets nothing** (deny by default).
* **Resource URIs are normalised** (`..`, `%2e%2e`) before matching, so `notes://public/../admin/payroll` cannot match a public pattern.
* **A tool that reads resources applies the same resource policy** (the `notes_read` tool cannot bypass it).
* **Parameter limits per role** (`max_results`) are policy data, not code.
* **Every decision is audited**, including denials.

Role explosion is a real problem. Keep roles few, combine them with scopes, and review them like code. Attribute-based rules (tenant id, data classification) can sit on top.

Run it: [`least-privilege-tools`](labs/least-privilege-tools/README.md) (12 tests).

## 5. Principle of least privilege in MCP contexts

Apply it at every level and ask "what is the minimum?":

| Level | Least privilege means |
|---|---|
| Tool set | Only the tools the task needs. A "summarize inbox" agent gets read, not send |
| Tool design | Narrow tools with fixed shapes instead of `run_sql` or `http_request` |
| Arguments | Enums, lengths and roots instead of free strings |
| Token | Fewest scopes, shortest lifetime, one audience |
| Server process | Own OS user, container, read-only filesystem, no network unless needed |
| Downstream credentials | Read-only database user; per-user identity where possible |
| Data | Return needed fields only; filter by the caller's rights |
| Time | Short leases, just-in-time elevation with approval |

Per-task tool lists are a strong pattern: the host (or gateway) gives the model only the tools for the current task and role. Combine with [Module 05 permissions](../../05-agent-security/permissions/README.md).

## 6. Client identity verification

The server must know **which client** (application) is calling, not only which user. Why: a user-consent for "Editor App" must not be usable by "Evil App" that copies its client id (the confused deputy problem for proxy servers with static client ids).

Practical controls:

* **Register clients** and keep a record of allowed redirect URIs and maximum scopes (`client_max_scopes` in the lab). Compare redirect URIs **exactly**.
* **Per-client consent** even for a client that was approved before, when a server acts as an OAuth proxy to a third-party API with one static client id.
* **Use the `client_id` claim** from a verified token in authorization decisions and in the audit log.
* **Public clients cannot keep secrets** (desktop hosts, CLIs): rely on PKCE, not a client secret. Confidential clients (server-side hosts) can authenticate with a secret, a private key JWT or mutual TLS.
* **Client ID metadata documents and dynamic registration** are two ways a client can introduce itself without a pre-shared registration. Both need policy: who may register, what scopes, what redirect URIs, and how you stop an attacker from registering a look-alike. Verify the current spec text.
* **Local client identity** (which process is calling a localhost server) is weak. Use a per-run token handed to the parent only, and Origin checks for browsers.

## 7. Quick check

1. Why must a resource server check `aud` even though the signature is valid?
2. A viewer cannot see `notes_delete` in `tools/list`. Can they still delete? What closes that hole?
3. A stdio server needs a database password. Give two better options than an env var in `mcp.json`.
4. What does the server learn from a verified `client_id` that it cannot learn from the user id?

## 8. References

* MCP specification: authorization and security best practices (modelcontextprotocol.io, verify current revision).
* OAuth 2.1 draft; RFC 9728 (protected resource metadata), RFC 8707 (resource indicators), RFC 8414 (server metadata), RFC 8693 (token exchange), RFC 7636 (PKCE), RFC 7591 (dynamic client registration).
* [Module 04, authentication](../../04-mcp-security/authentication/README.md); [Module 05, agent identity](../../05-agent-security/agent-identity/README.md).
