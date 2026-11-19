# Lab 06: Auditing MCP Server Connections for Data Integrity (Hermes-style config)

> **Chapter 3 exercise:** Auditing Hermes Agent's MCP Server Connections for Data Integrity
> **Study first:** [Lesson 04, section 2.2](../../04-defending-memory-context-and-tool-use.md#22-mcp-level-data-integrity-checks)
> **Generic material in this repo:** [CMCPSE defend-rug-pull](../../../../cmcpse-course/ch4-defending-and-hardening-mcp-servers/labs/defend-rug-pull/README.md) · [CAISP ch6 signing and MLBOM](../../../../caisp-course/ch6-supply-chain-attacks-in-ai/README.md) · [04-mcp-security](../../../../04-mcp-security/README.md)

Offline, harmless and tested. No network, no API key, no GPU, no Docker needed by the tests. Secrets are canaries or clearly fake values; domains end in `.example`. The model is a `MockLLM` subclass: deterministic and deliberately gullible. The lab is **self-contained** (it does not import code from another lab).

## What it simulates

Part A audits an **illustrative** Hermes-style server list: pinned versions and integrity hashes, tool-definition hashes, transport, authentication, literal secrets, tool allowlists, bind address, deprecated SSE. `check_definitions` compares live tool definitions with pinned hashes. Part B signs each result (HMAC over server, tool, arguments, result and nonce), verifies, rejects replays, and keeps a hash-chained log.

## Files

`mcp_audit.py` (`audit_config`, `check_definitions`, `SigningServer`, `VerifyingClient`) · `hermes-mcp.example.yaml` · `demo.py` · `test_caase_ch3_mcp_audit.py`

## Vulnerable vs defended

| | |
|---|---|
| **Vulnerable** | A list with unpinned packages, plain HTTP, no auth, a literal key, wildcard tools and no definition pins; results trusted as received. |
| **Defended** | Findings with severities for each problem; definition drift flagged as critical; signed results (tampered result, arguments or tool name fail); replayed messages rejected; tampering with the stored log located by index. A plain SHA-256 ('hashed') mode is shown and its limit stated: it detects change but cannot say who made it. |

## Run it

```powershell
.venv/Scripts/python caase-course/ch3-agent-memory-context-and-tool-use/labs/06-mcp-integrity-audit/demo.py
.venv/Scripts/python -m pytest caase-course/ch3-agent-memory-context-and-tool-use/labs/06-mcp-integrity-audit -v
```

## Real demo output

(Canary suffixes are random on every run.)

```text
== config audit
  [high    ] AUD-01 shady-search: package/version not pinned (use an exact version and an integrity hash)
  [high    ] AUD-02 shady-search: tool definitions are not hash-pinned (rug-pull blind spot)
  [high    ] AUD-03 shady-search: remote server over plain HTTP
  [high    ] AUD-04 shady-search: remote server without authentication
  [critical] AUD-05 shady-search: literal secret in env SEARCH_API_KEY (reference a secret store instead)
  [medium  ] AUD-06 shady-search: no tool allowlist (every tool the server exposes is reachable)
  [high    ] AUD-07 shady-search: bound to all interfaces
  [high    ] AUD-02 legacy-notes: tool definitions are not hash-pinned (rug-pull blind spot)
  [medium  ] AUD-06 legacy-notes: no tool allowlist (every tool the server exposes is reachable)
  [low     ] AUD-08 legacy-notes: deprecated HTTP+SSE transport; move to Streamable HTTP

== definition drift
  [critical] AUD-09: definition of get_ticket changed since it was pinned

== response integrity
  honest      : (True, 'ok')
  replay      : (False, 'replayed message')
  tampered    : (False, 'bad signature (result or arguments altered, or wrong key)')
  log tamper at index: 0
```

17 tests pass.

## Try it yourself

Pin the hashes in the example YAML, change one description and watch AUD-09 fire. Add a rule for servers launched with `sudo` or with a home-directory mount. Add key rotation to the signer.

## Limits

The YAML shape is illustrative, not the real Hermes schema. Most real MCP servers do not sign results today; a gateway you control can sign or hash on their behalf.

## Real-tool guide: Hermes Agent MCP connections (hedged)

> Not run by the repo author. Hermes Agent (Nous Research, open source, launched in 2026) is a fast-moving project: read the docs at hermes-agent.nousresearch.com for the current commands and config format.

Typical audit steps (names may differ in your version):

1. Inventory: `hermes mcp list` to see every configured MCP server, its transport (stdio or HTTP) and any per-server tool filter.
2. Test: `hermes mcp test <name>` to connect and list the tools the server exposes. Save the tool list.
3. Hash the saved tool definitions (the `tool_hash` function in this lab) and keep the hashes in a file under version control. Re-run later and diff.
4. Check each entry against the audit rules: exact version and integrity hash, HTTPS and authentication for remote servers, secrets by reference, a tool allowlist, loopback binding.
5. Remove what you do not need: `hermes mcp remove <name>`.

If your version of the config file differs from the illustrative YAML here, adapt `audit_config` to read the real keys; the checks do not change.
