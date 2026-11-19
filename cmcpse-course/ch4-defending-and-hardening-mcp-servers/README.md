# Chapter 4: Defending and hardening MCP servers

> **Time:** ~25 hours · **You will:** apply defense in depth to MCP: authentication and authorization (OAuth scopes, RBAC, least privilege, client identity), secure tool and resource design, transport security (stdio, TLS, pinning, localhost), secrets management with a vault, logging and detection with a signed audit, secure development, and eight offline labs.

## Syllabus coverage

Every syllabus line of the chapter, in course order. "Existing" links go to deeper material already in this repository.

| Syllabus item | Where to study | Lab |
|---|---|---|
| Introduction to MCP Defense | [01 Introduction](01-introduction-to-mcp-defense.md) | - |
| &nbsp;&nbsp;Defense-in-depth principles applied to MCP | [01, section 1](01-introduction-to-mcp-defense.md) ([SVG](../../images/cmcpse-ch4-defense-in-depth.svg)) | - |
| &nbsp;&nbsp;Secure by design for MCP servers | [01, section 2](01-introduction-to-mcp-defense.md) | - |
| &nbsp;&nbsp;Mapping defenses to the attack surface | [01, section 3](01-introduction-to-mcp-defense.md); threats in [chapter 3](../ch3-threat-modeling-mcp-architectures/README.md); existing: [Module 04 OWASP MCP coverage](../../04-mcp-security/README.md#owasp-mcp-top-10-2025-beta-coverage) | - |
| Authentication and Authorization | [02 Authentication and authorization](02-authentication-and-authorization.md); existing: [Module 04, authentication](../../04-mcp-security/authentication/README.md) | [`defend-oauth-scopes`](labs/defend-oauth-scopes/README.md) |
| &nbsp;&nbsp;MCP authentication mechanisms overview | [02, section 1](02-authentication-and-authorization.md) | - |
| &nbsp;&nbsp;OAuth 2.0 for MCP over HTTP transport | [02, section 2](02-authentication-and-authorization.md); existing: [Module 04, authentication](../../04-mcp-security/authentication/README.md) | [`defend-oauth-scopes`](labs/defend-oauth-scopes/README.md) |
| &nbsp;&nbsp;Token-based auth for stdio and SSE transports | [02, section 3](02-authentication-and-authorization.md) | `stdio_env()` in [`transport-security`](labs/transport-security/README.md) |
| &nbsp;&nbsp;Implementing role-based access control for tools and resources | [02, section 4](02-authentication-and-authorization.md) | [`least-privilege-tools`](labs/least-privilege-tools/README.md) |
| &nbsp;&nbsp;Principle of the least privilege in MCP contexts | [02, section 5](02-authentication-and-authorization.md) | [`least-privilege-tools`](labs/least-privilege-tools/README.md) |
| &nbsp;&nbsp;Client identity verification | [02, section 6](02-authentication-and-authorization.md) | `client_max_scopes` in [`defend-oauth-scopes`](labs/defend-oauth-scopes/README.md) |
| Secure Tool and Resource Design | [03 Secure tool and resource design](03-secure-tool-and-resource-design.md); existing: [Module 04, tool-security](../../04-mcp-security/tool-security/README.md) | [`least-privilege-tools`](labs/least-privilege-tools/README.md), [`mcp-ai-firewall`](labs/mcp-ai-firewall/README.md) |
| &nbsp;&nbsp;Least-privilege tool design principles | [03, section 1](03-secure-tool-and-resource-design.md) | [`least-privilege-tools`](labs/least-privilege-tools/README.md) |
| &nbsp;&nbsp;Scoping tool permissions to minimum required access | [03, section 2](03-secure-tool-and-resource-design.md) | [`policy.yaml`](labs/least-privilege-tools/policy.yaml) |
| &nbsp;&nbsp;Input validation for tool parameters | [03, section 3](03-secure-tool-and-resource-design.md); existing: [Module 04, tool-security](../../04-mcp-security/tool-security/README.md) | schema checks in [`rbac_server.py`](labs/least-privilege-tools/rbac_server.py), `forbid_patterns` in [`firewall`](labs/mcp-ai-firewall/policy.yaml) |
| &nbsp;&nbsp;Output sanitization to prevent injection propagation | [03, section 4](03-secure-tool-and-resource-design.md); existing: [guard-io](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/guard-io/README.md), [llm-guard-sanitize](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/llm-guard-sanitize/README.md) | [`mcp-ai-firewall`](labs/mcp-ai-firewall/README.md) |
| &nbsp;&nbsp;Resource access controls and scoping | [03, section 5](03-secure-tool-and-resource-design.md) | `resources/list` and `resources/read` in [`least-privilege-tools`](labs/least-privilege-tools/README.md) |
| &nbsp;&nbsp;Avoiding information disclosure in descriptions | [03, section 6](03-secure-tool-and-resource-design.md) | [`defend-tool-poisoning`](labs/defend-tool-poisoning/README.md) (sensitive-path rule) |
| Transport Security | [04 Transport security](04-transport-security.md) | [`transport-security`](labs/transport-security/README.md) |
| &nbsp;&nbsp;Securing stdio transport | [04, section 1](04-transport-security.md) | `stdio_env()`, `audit_launch_config()` |
| &nbsp;&nbsp;Implementing TLS for SSE and HTTP transports | [04, section 2](04-transport-security.md) | `client_context()`, `server_context()` |
| &nbsp;&nbsp;Certificate validation and pinning | [04, section 3](04-transport-security.md) | `spki_sha256()`, `connect_pinned()` |
| &nbsp;&nbsp;Secure configuration of MCP endpoints | [04, section 4](04-transport-security.md) | `check_request_origin()`, `safe_bind_address()` |
| &nbsp;&nbsp;Network-level controls for MCP server exposure | [04, section 5](04-transport-security.md); existing: [Module 04, secure-operations](../../04-mcp-security/secure-operations/README.md) | - |
| Secrets Management | [05 Secrets management](05-secrets-management.md); existing: [Module 06, runtime security](../../06-ai-devsecops/runtime-security/README.md) | [`secrets-vault`](labs/secrets-vault/README.md) |
| &nbsp;&nbsp;Avoiding credentials and secrets in tool schemas | [05, section 1](05-secrets-management.md) | `test_tools_list_contains_no_secret...` |
| &nbsp;&nbsp;Environment variable security for MCP servers | [05, section 2](05-secrets-management.md) | `stdio_env()` |
| &nbsp;&nbsp;Integrating MCP servers with secrets vaults (HashiCorp Vault) | [05, section 3](05-secrets-management.md) | [`secrets-vault`](labs/secrets-vault/README.md) (mock; optional real dev server) |
| &nbsp;&nbsp;Rotating secrets in agentic environments | [05, section 4](05-secrets-management.md) | `rotate_kv()`, lease revoke tests |
| Logging, Monitoring, and Detection | [06 Logging, monitoring and detection](06-logging-monitoring-detection.md); existing: [Module 04, secure-operations](../../04-mcp-security/secure-operations/README.md), [Module 05, monitoring and response](../../05-agent-security/monitoring-and-response/README.md) | [`tool-invocation-logging`](labs/tool-invocation-logging/README.md) |
| &nbsp;&nbsp;What to log in MCP environments | [06, section 1](06-logging-monitoring-detection.md) | - |
| &nbsp;&nbsp;Logging tool invocations with full context | [06, section 2](06-logging-monitoring-detection.md) | `InvocationLogger` |
| &nbsp;&nbsp;Detecting anomalous and abusive tool usage patterns | [06, section 3](06-logging-monitoring-detection.md) | `detect()` |
| &nbsp;&nbsp;Monitoring agentic pipelines for suspicious behavior | [06, section 4](06-logging-monitoring-detection.md) | - |
| &nbsp;&nbsp;Alerting on indicators of MCP-based attacks | [06, section 5](06-logging-monitoring-detection.md) | `detect()` rules |
| &nbsp;&nbsp;Audit trails and non-repudiation for tool calls | [06, section 6](06-logging-monitoring-detection.md) | `AuditChain`, `verify()` |
| Secure MCP Server Development Practices | [07 Secure MCP development](07-secure-mcp-development.md) | all labs as test templates |
| &nbsp;&nbsp;Secure coding practices for MCP server implementation | [07, section 1](07-secure-mcp-development.md) | - |
| &nbsp;&nbsp;Safe dependency management | [07, section 2](07-secure-mcp-development.md); existing: [Module 06, CI/CD](../../06-ai-devsecops/cicd/README.md) | - |
| &nbsp;&nbsp;Error handling to prevent information disclosure | [07, section 3](07-secure-mcp-development.md) | generic errors in [`vault_mcp_server.py`](labs/secrets-vault/vault_mcp_server.py) |
| &nbsp;&nbsp;Security testing during the development process | [07, section 4](07-secure-mcp-development.md) | every `test_*.py` |
| &nbsp;&nbsp;Code review checklist for MCP servers | [07, section 5](07-secure-mcp-development.md); [`code-review-checklist.md`](code-review-checklist.md) | - |
| Hands-on Exercises: | [08 Hands-on exercises](08-hands-on-exercises.md) | all labs |
| &nbsp;&nbsp;Defending OAuth scopes on MCP server | [02](02-authentication-and-authorization.md) | [`defend-oauth-scopes`](labs/defend-oauth-scopes/README.md) |
| &nbsp;&nbsp;Configure least-privilege tool permissions on a running MCP server | [02](02-authentication-and-authorization.md), [03](03-secure-tool-and-resource-design.md) | [`least-privilege-tools`](labs/least-privilege-tools/README.md) |
| &nbsp;&nbsp;Integrate a secrets vault with an MCP server | [05](05-secrets-management.md) | [`secrets-vault`](labs/secrets-vault/README.md) |
| &nbsp;&nbsp;Configure comprehensive logging for tool invocations | [06](06-logging-monitoring-detection.md) | [`tool-invocation-logging`](labs/tool-invocation-logging/README.md) |
| &nbsp;&nbsp;Defending rug pull attacks | [03, section 7](03-secure-tool-and-resource-design.md) | [`defend-rug-pull`](labs/defend-rug-pull/README.md) |
| &nbsp;&nbsp;Defending tool poisoning | [03, section 7](03-secure-tool-and-resource-design.md) | [`defend-tool-poisoning`](labs/defend-tool-poisoning/README.md) |
| &nbsp;&nbsp;Defending tool confusion | [03, section 7](03-secure-tool-and-resource-design.md) | [`defend-tool-confusion`](labs/defend-tool-confusion/README.md) |
| &nbsp;&nbsp;Deploying and configuring an AI firewall for MCP server | [03, section 4](03-secure-tool-and-resource-design.md) | [`mcp-ai-firewall`](labs/mcp-ai-firewall/README.md) ([SVG](../../images/cmcpse-ch4-ai-firewall.svg)) |

**Not run by the repo author:** the optional real HashiCorp Vault dev server and `hvac` example in the secrets lab (hedged commands). The mock vault covers the same behaviours with tests. Commercial AI firewall and gateway products are described generically only.

## Lab index

| Lab | Course exercise | Tests |
|---|---|---|
| [`defend-oauth-scopes`](labs/defend-oauth-scopes/) | Defending OAuth scopes | 12 |
| [`least-privilege-tools`](labs/least-privilege-tools/) | Least-privilege tool permissions | 12 |
| [`secrets-vault`](labs/secrets-vault/) | Secrets vault integration | 15 |
| [`tool-invocation-logging`](labs/tool-invocation-logging/) | Comprehensive logging | 16 |
| [`defend-rug-pull`](labs/defend-rug-pull/) | Rug pull defence | 13 |
| [`defend-tool-poisoning`](labs/defend-tool-poisoning/) | Tool poisoning defence | 13 |
| [`defend-tool-confusion`](labs/defend-tool-confusion/) | Tool confusion defence | 13 |
| [`mcp-ai-firewall`](labs/mcp-ai-firewall/) | AI firewall for MCP | 18 |
| [`transport-security`](labs/transport-security/) | (TLS, pinning, localhost, stdio) | 16 |

Run the chapter tests: `python -m pytest cmcpse-course/ch4-defending-and-hardening-mcp-servers` (128 tests). The TLS tests need the `cryptography` package and skip without it.

## Learning order

1. [01 Introduction](01-introduction-to-mcp-defense.md): layers and the attack map.
2. [02 Authentication and authorization](02-authentication-and-authorization.md) with [`defend-oauth-scopes`](labs/defend-oauth-scopes/README.md) and [`least-privilege-tools`](labs/least-privilege-tools/README.md).
3. [03 Secure tool and resource design](03-secure-tool-and-resource-design.md) with the poisoning, rug pull, confusion and firewall labs.
4. [04 Transport security](04-transport-security.md) with [`transport-security`](labs/transport-security/README.md).
5. [05 Secrets management](05-secrets-management.md) with [`secrets-vault`](labs/secrets-vault/README.md).
6. [06 Logging, monitoring and detection](06-logging-monitoring-detection.md) with [`tool-invocation-logging`](labs/tool-invocation-logging/README.md).
7. [07 Secure development](07-secure-mcp-development.md) and the [code review checklist](code-review-checklist.md).
8. [08 Hands-on](08-hands-on-exercises.md): compose the labs.

## Exam and interview tips for this chapter

* **Two places for authorization:** filter the list *and* enforce on call. "Hidden is not protected" is a favourite question.
* **Audience binding** is the answer to token passthrough and confused deputy. Know RFC 8707 (resource indicators) and RFC 9728 (protected resource metadata).
* **stdio is not "safe because local":** same-user privileges, inherited environment, command line as code.
* **Pin the key (SPKI), not the certificate,** keep a backup pin, and never disable verification.
* **DNS rebinding:** Host and Origin checks, loopback binding, and auth.
* **Dynamic secrets and leases** beat long-lived shared secrets. Know AppRole versus OIDC/JWT login.
* **Log the decision, not just the call:** denials are the best early signal. Hash chain plus signature plus anchor for audit.
* **Heuristics are one layer.** Say what a firewall cannot catch.
* **Hedge unstable facts:** spec revision text, SSE deprecation status, OWASP MCP Top 10 (beta), product features.

## 15 interview / exam-style questions

<details><summary><b>Q1. What is defense in depth for an MCP server? Give the layers.</b></summary>

Several independent controls so one failure is not a breach: supply chain (allowlist, pins), transport (TLS, Origin checks), identity (OAuth, audience binding), gateway (inspection), tool policy (RBAC, schemas), server logic and secrets (no shell, vault), detection (structured logs, signed audit), and human approval for side effects. Assume the model, the user, the server and the dependencies can each fail.
</details>

<details><summary><b>Q2. Which authentication mechanism fits each transport?</b></summary>

stdio: the process boundary plus credentials from the environment or a vault (the spec says not to use the HTTP authorization flow). Streamable HTTP: OAuth 2.1-style, with the server as resource server, PKCE and resource indicators. Legacy HTTP+SSE: bearer tokens in the Authorization header (the transport is deprecated). Local HTTP helper: a per-run token plus Host and Origin checks. Verify the current spec text.
</details>

<details><summary><b>Q3. What must an MCP resource server check on a token?</b></summary>

Signature, expiry, issuer, audience (the token must be minted for this server), scopes for the requested tool, and that the token is not over-scoped for this client. Each failure maps to 401 or 403 with a different error so you can see which check fired.
</details>

<details><summary><b>Q4. Why is filtering tools/list not an access control?</b></summary>

A client can call a tool it never saw listed. Enforce the same policy at tools/call (and resources/read). Filtering is still useful: it shrinks the attack surface and the model's confusion. Use one function for both so they cannot drift.
</details>

<details><summary><b>Q5. What is token passthrough and why is it forbidden?</b></summary>

The MCP server forwards the client's token to a downstream API. The downstream API then trusts a token not minted for it, audit trails break, and a stolen token works on more systems (confused deputy). Use token exchange or the server's own scoped credential, and validate the audience.
</details>

<details><summary><b>Q6. Name the risks of a stdio server and the fixes.</b></summary>

It runs with the user's privileges, inherits the parent's environment (secrets), and is started by a command line in the host config that is effectively code. Fixes: a minimal environment, no shell wrapper, pinned package versions, absolute paths, no inline secrets, sandboxing, and review and integrity checks on the config file.
</details>

<details><summary><b>Q7. Explain DNS rebinding against a local MCP server and the defences.</b></summary>

A malicious page's hostname is re-resolved to 127.0.0.1, so the browser lets the page call the local server. The request still carries the attacker's Host and Origin. Defences: validate Host and Origin against an allowlist (reject Origin null), bind to 127.0.0.1, require authentication on every request, and keep CORS closed.
</details>

<details><summary><b>Q8. What is SPKI pinning and what are its operational risks?</b></summary>

You pin the base64 SHA-256 of the certificate's SubjectPublicKeyInfo, so renewing with the same key still works. It guards against a mis-issued certificate from a trusted CA. Risks: a key change locks clients out, so pin a backup key and plan rotation. It is added on top of normal validation, never instead of it.
</details>

<details><summary><b>Q9. Why is a tool parameter called api_key a design smell?</b></summary>

It forces the model to hold the secret, so it appears in the context, logs and the provider's systems and can be exfiltrated by an injection. The server should authenticate to downstream systems with its own credential fetched from a vault at call time; the tool takes business arguments only.
</details>

<details><summary><b>Q10. How does a server use HashiCorp Vault safely?</b></summary>

It logs in with a workload identity (AppRole, OIDC/JWT or Kubernetes auth), gets a short-lived token limited by a policy, reads static secrets at call time, and requests dynamic credentials with a lease that it renews early or replaces. It never puts secrets in schemas, env or logs, redacts everything, drops the bootstrap secret_id after use, and fails closed with a generic error if the vault is down.
</details>

<details><summary><b>Q11. How do you rotate a secret without breaking running agent sessions?</b></summary>

Never keep the secret in the conversation. The server fetches the current version on each call, so rotation takes effect at the next call. Keep both versions valid for a short overlap, then revoke the old one. Treat an authentication failure as possible rotation: refetch once, then alert.
</details>

<details><summary><b>Q12. What fields belong in a tool-invocation log record?</b></summary>

Timestamp, event and session ids, user, client id, server, tool, a hash of the raw arguments, redacted arguments, result size, latency, the decision (allow, deny, error) and reason. Add a trace id. Never log tokens or raw sensitive payloads, and log denials.
</details>

<details><summary><b>Q13. How do you make an audit trail tamper-evident, and what can it still miss?</b></summary>

Chain records with prev_hash and hash, sign each hash, and store an anchor (count and last hash) elsewhere. Editing, deleting, reordering or re-hashing without the key is detected; truncating the tail is caught only by the anchor. With HMAC, a key holder can forge, so production uses an asymmetric key and write-once storage. A log proves what the system recorded, not that its content was correct.
</details>

<details><summary><b>Q14. How do you defend against rug pulls, tool poisoning and tool confusion?</b></summary>

Rug pull: pin a hash per tool, verify at list time, on list_changed and before each call, quarantine changed tools, and re-approve by a human. Poisoning: scan the whole definition, block high-severity findings, sanitize, and show a reviewed description. Confusion: namespace tools as server.tool, allowlist approved pairs, pin descriptions, restrict name characters and detect look-alikes.
</details>

<details><summary><b>Q15. What can an AI firewall for MCP do, and what can it not?</b></summary>

It can allowlist tools, cap size and rate, block forbidden patterns and secrets in arguments, quarantine results with injection heuristics or hidden text, redact secrets and PII, remove images and unknown links, and log every decision, failing closed. It cannot catch paraphrased or encoded injections reliably and it adds a component to secure. Keep least privilege, scopes, approvals and logging as the main controls.
</details>

## References

* MCP specification: authorization, transports, security best practices (modelcontextprotocol.io; verify the current revision).
* OAuth 2.1 draft and RFCs 9728, 8707, 8414, 8693, 7636, 7591.
* HashiCorp Vault documentation (auth methods, KV v2, database secrets engine, leases); OWASP Secrets Management Cheat Sheet.
* OWASP MCP Top 10 (beta), OWASP Logging, TLS and Docker cheat sheets; Python `ssl` documentation.
* In this repo: [Module 04](../../04-mcp-security/README.md), [Module 05](../../05-agent-security/README.md), [Module 06](../../06-ai-devsecops/runtime-security/README.md), [CAISP ch4](../../caisp-course/ch4-ai-attacks-and-defenses-devops/README.md).
