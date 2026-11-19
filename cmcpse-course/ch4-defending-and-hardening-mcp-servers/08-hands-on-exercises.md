# Lesson 08: Hands-on exercises

> **Chapter 4** · **Time:** ~10 hours · the eight course exercises, mapped to offline labs with tests.

| Course exercise | Lab | What you do | Tests |
|---|---|---|---|
| Defending OAuth scopes on MCP server | [`defend-oauth-scopes`](labs/defend-oauth-scopes/README.md) | Enforce scopes per tool, audience binding, reject over-scoped and wrong-audience tokens | 12 |
| Configure least-privilege tool permissions on a running MCP server | [`least-privilege-tools`](labs/least-privilege-tools/README.md) | Role policy applied at list and call time; resource scoping | 12 |
| Integrate a secrets vault with an MCP server | [`secrets-vault`](labs/secrets-vault/README.md) | AppRole login, dynamic credentials, leases, rotation, redaction; optional real Vault dev server | 15 |
| Configure comprehensive logging for tool invocations | [`tool-invocation-logging`](labs/tool-invocation-logging/README.md) | Structured log, detections, signed hash chain, anchor | 16 |
| Defending rug pull attacks | [`defend-rug-pull`](labs/defend-rug-pull/README.md) | Pin, verify, quarantine, diff, approve | 13 |
| Defending tool poisoning | [`defend-tool-poisoning`](labs/defend-tool-poisoning/README.md) | Scan whole definitions, block, sanitize, pin reviewed text | 13 |
| Defending tool confusion | [`defend-tool-confusion`](labs/defend-tool-confusion/README.md) | Namespacing, allowlist, description pinning, look-alike detection | 13 |
| Deploying and configuring an AI firewall for MCP server | [`mcp-ai-firewall`](labs/mcp-ai-firewall/README.md) | Gateway with a policy file; inspect requests and results | 18 |
| (extra) Transport security | [`transport-security`](labs/transport-security/README.md) | TLS context, SPKI pinning, Origin checks, config audit | 16 |

## Suggested order

1. `defend-oauth-scopes` then `least-privilege-tools` (identity, then policy).
2. `defend-tool-poisoning`, `defend-rug-pull`, `defend-tool-confusion` (the metadata attacks, one idea each).
3. `mcp-ai-firewall` (inspect traffic) and `transport-security` (the channel).
4. `secrets-vault` then `tool-invocation-logging` (secrets and evidence).
5. Put them together: write down which finding from the [chapter 3 register](../ch3-threat-modeling-mcp-architectures/labs/risk-rating/README.md) each lab closes, and re-run the risk rating with those controls added to the architecture YAML.

## Capstone idea

Build a "hardened notes server" by composing the labs: scopes (`oauth_scopes`) → firewall → RBAC (`rbac_server`) → vault secrets → logging. The test: each attack from the threat model fails at the **first** layer that should stop it, and still fails if you remove that layer (so the second layer holds). Compare with the gateway mini-project in [Module 04](../../04-mcp-security/README.md).

## Self-check

* Which lab shows that "hide the tool" is not an access control?
* Which two labs together stop a rug pull that also contains hidden instructions?
* Which control stops a localhost server being called from a web page, and which lab tests it?
* How do you prove after an incident that a log was not edited, and what can it not prove?
