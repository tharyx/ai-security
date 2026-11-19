# Code review checklist for MCP servers

Use it on every pull request that adds or changes a tool, resource, prompt, transport or dependency. Tick each box and link the test or the line that proves it. "N/A" needs a reason. Items map to the OWASP MCP Top 10 (beta; verify) where useful.

**Server:** `<name and version>` · **PR:** `<link>` · **Reviewer:** `<name>` · **Date:** `<date>`

## A. Scope and design

- [ ] The change adds the **smallest** set of tools; each is narrow (one verb, one object); read and write are separate. (MCP02)
- [ ] No generic executors (`run_command`, `run_sql`, `http_request`, `eval`) without a strict wrapper and approval.
- [ ] A **trust model** is written: transport, identity provider, downstream APIs, data classes.
- [ ] The threat model (chapter 3) was updated and every new finding has a test or an accepted-risk record.

## B. Authentication and authorization

- [ ] Every request is authenticated; tokens only in the `Authorization` header, never in a URL. (MCP07)
- [ ] Token checks: signature, expiry, issuer, **audience**, scopes; over-scoped tokens rejected. (MCP02, MCP07)
- [ ] A **policy table** maps each tool and resource to a scope or role; unknown means **deny**.
- [ ] Enforced at **both** `tools/list` filtering and `tools/call` (and `resources/read`) time.
- [ ] Identity, tenant and role come from the verified session; extra fields are rejected.
- [ ] No token passthrough: downstream calls use exchange or the server's own scoped credential.
- [ ] Client identity (`client_id`) is checked against registered clients and redirect URIs are matched exactly.
- [ ] Local HTTP servers bind to 127.0.0.1, check **Host and Origin**, and require a token.

## C. Tool and resource design

- [ ] `inputSchema` uses types, enums, bounds, patterns, `required` and `additionalProperties: false`; the code validates again.
- [ ] Paths are resolved against a root (symlinks, `..`, encoding); URLs are parsed and the resolved IP checked (SSRF). (MCP05)
- [ ] No shell invocation; if unavoidable, fixed argument lists and an allowlist. SQL is parameterised.
- [ ] Results are minimal, size-bounded and sanitised; no secrets or PII beyond need. (MCP10)
- [ ] Result text cannot carry instructions from untrusted sources unmarked; hidden characters stripped. (MCP06)
- [ ] Descriptions and schemas contain **no** secrets, internal paths or hosts, and no instructions to the model. (MCP01, MCP03)
- [ ] Side-effecting tools need approval or a narrower scope; annotations (read-only, destructive) are accurate but not relied on for security.

## D. Secrets

- [ ] No secret in code, tests, fixtures, schemas, descriptions, docs or `mcp.json` examples. (MCP01)
- [ ] Secrets come from a vault or secret manager at call time; dynamic or short-lived where possible.
- [ ] The process environment is minimal (no inherited cloud keys).
- [ ] Logs and errors are redacted; a test proves a canary secret never appears.

## E. Transport and network

- [ ] HTTPS with validation for non-loopback; no `verify=False`, no `CERT_NONE`.
- [ ] Minimum TLS 1.2; certificates renew automatically; pins (if used) have a backup key.
- [ ] stdio: no shell wrapper, absolute command, pinned package version, no inline secrets in the launch config.
- [ ] Egress is allowlisted; the server runs as non-root with a read-only filesystem where possible.

## F. Errors and logging

- [ ] Errors to the client are generic with a correlation id; no stack traces or internal details.
- [ ] Fail **closed** on policy, vault or validation errors.
- [ ] Every `tools/call` is logged with user, client, server, tool, args hash, redacted args, result size, latency, decision, including **denials**. (MCP08)
- [ ] Logs do not contain tokens or raw sensitive payloads; audit records are tamper-evident for high-risk tools.

## G. Dependencies and release

- [ ] New dependencies justified; pinned with hashes or a lockfile; no `latest`. (MCP04)
- [ ] CI runs dependency scan, secret scan, SAST and the security tests; failures block merge.
- [ ] An SBOM is produced and the release is signed or has provenance.
- [ ] Changing a tool definition (description, schema, annotations) is called out in the changelog and bumps the version (clients re-pin).
- [ ] Registry or package names are scoped and protected against typosquatting.

## H. Tests (must exist and pass)

- [ ] Wrong audience, expired, forged, over-scoped and missing tokens are rejected.
- [ ] A hidden tool called directly is denied; `..` and encoded traversal are denied; extra arguments are rejected.
- [ ] A poisoned-definition fixture is blocked; a rug-pull fixture is detected; a name-collision fixture is not exposed.
- [ ] An injection fixture in a tool result is quarantined or flagged.
- [ ] A canary secret never appears in results, logs, errors or schemas.

## Decision

- [ ] Approve · [ ] Approve with follow-ups (list) · [ ] Request changes (list)

Notes:
