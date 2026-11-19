# Lesson 05: Secrets management for MCP servers

> **Chapter 4** · **Time:** ~4 hours · **You will:** keep credentials out of tool schemas, secure environment variables, integrate an MCP server with a secrets vault (HashiCorp Vault pattern: AppRole or OIDC login, dynamic secrets, leases, rotation), and rotate secrets without downtime.

| | |
|---|---|
| **Syllabus lines** | Secrets Management (4 lines) |
| **Already in this repo (read first)** | [Module 06, runtime security](../../06-ai-devsecops/runtime-security/README.md): secrets, the vault pattern, redacted logs, monitoring. [Module 04, secure-operations](../../04-mcp-security/secure-operations/README.md) §2.1: token leakage in logs, per-server secrets |
| **Lab** | [`secrets-vault`](labs/secrets-vault/README.md) (15 tests; mock vault on 127.0.0.1, optional real Vault dev server) |

---

## 1. Avoiding credentials and secrets in tool schemas

A tool schema (name, description, `inputSchema`, defaults, examples) is **shown to the model and often to the user and logs**. Anything in it can be read by the model, echoed in a response, exfiltrated by an injection, or stored by the host.

Do not put in a schema or description:

* API keys, tokens, passwords, connection strings, signed URLs.
* **Secrets as tool parameters.** A parameter such as `api_key` means the *model* must hold the secret, so it will be in the context window, in logs and in the provider's systems. The server should hold the credential and the model should never see it.
* Defaults or examples that contain real values (`"default": "Bearer eyJ..."`).
* Internal hostnames or paths that help an attacker (see [lesson 03](03-secure-tool-and-resource-design.md) on disclosure).

Pattern: the **server** authenticates to downstream systems with its own credentials (fetched at call time, see section 3). The tool takes only business arguments (`month`, `customer_id`). The lab has a test that serialises `tools/list` and asserts that no secret value appears. Add the same test to your own server; scan schemas in CI with the scanner from [`defend-tool-poisoning`](labs/defend-tool-poisoning/README.md) and a secret scanner (gitleaks, trufflehog; verify the current names and options).

## 2. Environment variable security for MCP servers

Environment variables are the most common way to give a stdio server a secret, and they are weak:

| Problem | Why | Mitigation |
|---|---|---|
| Visible to the process and children, and to same-user processes in some systems (`/proc/<pid>/environ`) | Env is plain text in memory and in the kernel's process info | Short-lived, scoped credentials; fetch from a vault instead |
| Inherited by every child process | Third-party code gets parent secrets | Build a minimal env ([lesson 04](04-transport-security.md)) |
| Written to crash dumps, `docker inspect`, CI logs, debug endpoints | Env is easy to print | Never print env; mask in CI; no debug endpoints |
| Hard-coded in `mcp.json` or compose files | Committed to Git | Reference variables (`${NOTES_TOKEN}`) or a secret store; never commit |
| Long-lived | A stolen value works for months | Rotation, leases, expiry |

Better ladders, from weakest to strongest: a literal in the config file (worst) → an env var set by the user's shell → an env var injected by the orchestrator (Kubernetes Secret, CI secret) → a **file mounted with strict permissions** → **fetched at call time from a vault** with a workload identity → **dynamic, short-lived credentials** that are never shared and expire by themselves.

Local developer machines: use the **OS credential store** (Windows Credential Manager, macOS Keychain, libsecret) for tokens that a host caches. Plain JSON token caches are a finding (MT-I02 in chapter 3).

## 3. Integrating MCP servers with secrets vaults (HashiCorp Vault)

**The idea.** The MCP server holds **no long-lived secret**. It proves *who it is* to the vault, gets a short-lived token, and asks for exactly the secrets its policy allows, when it needs them. Verify API details at developer.hashicorp.com/vault; the lab mimics the *shape* of the calls.

```text
MCP server  --(1) login: AppRole role_id + secret_id | OIDC/JWT | Kubernetes service account-->  Vault
            <-(2) client token (TTL, policies) ----------------------------------------------
            --(3) read kv/data/partner   or   read database/creds/reporting  (token in X-Vault-Token)-->
            <-(4) secret   or   {username, password, lease_id, lease_duration}
            ... use it, renew the lease before expiry, revoke or let it expire ...
```

**Authentication methods (how the server proves identity):**

| Method | Use when | Notes |
|---|---|---|
| **AppRole** | Services outside a platform with its own identity | `role_id` (not secret, like a username) + `secret_id` (secret, like a password). Deliver the `secret_id` separately, ideally **one-time** or via **response wrapping**; the client uses it once and forgets it |
| **OIDC / JWT** | CI jobs (GitHub Actions, GitLab), cloud workloads with signed identity tokens | No stored secret at all: the platform issues a signed token; Vault verifies it against the issuer and maps claims to a role |
| **Kubernetes auth** | Pods | The pod's service account token is the identity |
| **Cloud IAM auth** | VMs and functions on AWS, Azure, GCP | The instance identity is the credential |

**Policies = least privilege.** A policy lists which paths the token may read (`kv/data/partner`, `database/creds/reporting`). Tests in the lab show that another AppRole cannot read these paths.

**Secrets engines:**

* **KV (static, versioned):** API keys that another system owns. Read **at call time** (or cache briefly) so a new version takes effect.
* **Dynamic secrets (for example the database engine):** Vault *creates* a database user per request with a **TTL**, so every instance has its own credential that dies by itself. If one leaks, the damage window is short and you know whose it was.

**Leases and rotation:**

* A dynamic secret comes with a **lease** (`lease_id`, `lease_duration`). Renew it while the server needs it, or ask for a new one. **Revoke** a lease to kill a credential at once (incident response).
* Cache until about **80 percent of the lease**, then replace. Never at the last second.
* **Detect rotation or revocation by failure:** if the database says "login failed", fetch once more and retry once; do not loop.
* Static secrets rotate by writing a new version. The server picks it up at the next read. The old value should stop working at the provider after a **grace period** (overlap), so in-flight calls do not fail.

**What the MCP server code must do** (each rule has a test in the lab):

1. No secret in schemas, descriptions or `os.environ`.
2. Bootstrap secret (`secret_id`) is used once and dropped.
3. Redact every log line with a registry of values it has seen plus patterns.
4. Fail closed with a **generic** error if the vault is down; never echo raw exceptions (they can contain secrets).
5. Time-box the vault token; re-login only if allowed (renewable token, platform identity).

**Optional real Vault (dev server, hedged):** see the lab README for `vault server -dev` and an `hvac` example. Dev mode is in-memory, uses HTTP and prints a root token; it is for learning only.

## 4. Rotating secrets in agentic environments

Agents make rotation harder: long-running sessions, many parallel tool calls, tokens copied into contexts, and servers that cache. Plan for it:

| Concern | Practice |
|---|---|
| **Frequency** | Dynamic secrets: minutes to hours. Static keys: on a schedule (30 to 90 days; follow your policy) and on any suspicion |
| **No downtime** | Two valid versions during an overlap window; clients read the *current* version each call; then revoke the old |
| **Long sessions** | Never put a secret in the conversation. The server fetches fresh credentials per call, so rotation does not break the session |
| **Caches** | Cache only until the lease ends (renew early). Provide an admin way to flush |
| **Detection of failure** | Treat an authentication failure as a possible rotation: refetch once, then alert |
| **Incident response** | Runbook: revoke leases, rotate static keys, invalidate tokens, search logs for the key's `args_hash` or fingerprint, notify owners |
| **Evidence** | Log fingerprints (`sha256(secret)[:8]`) and lease ids, never values |
| **Secrets that humans type into prompts** | A redaction layer at the gateway (the firewall lab redacts API keys in arguments and results) and user training |

## 5. Quick check

1. Why is a tool parameter called `api_key` a design smell?
2. Compare AppRole and OIDC/JWT login: where does the initial secret live in each?
3. What is the benefit of dynamic database credentials over one shared password in an env var?
4. A rotation happens while an agent session is running. What design keeps the session working?

## 6. References

* HashiCorp Vault documentation: AppRole, JWT/OIDC and Kubernetes auth methods, KV v2, database secrets engine, leases, response wrapping (verify current pages).
* OWASP Secrets Management Cheat Sheet. NIST SP 800-57 (key management) as background.
* OWASP MCP01 Token Mismanagement and Secret Exposure (beta list).
* [Module 06, runtime security](../../06-ai-devsecops/runtime-security/README.md).
