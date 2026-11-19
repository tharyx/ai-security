# Lab 01: MCP Reconnaissance and Endpoint Enumeration

> **Chapter 2 exercise:** MCP server reconnaissance and endpoint enumeration
> **Study first:** [Lesson 01](../../01-mcp-attack-surface.md), [Lesson 02, Reconnaissance](../../02-attack-tactics-attck-and-atlas-for-mcp.md#3-reconnaissance-of-mcp-environments), [Lesson 04](../../04-mcp-vulnerability-classes.md) · **Defending chapter:** [Chapter 4](../../../ch4-defending-and-hardening-mcp-servers/README.md) · **Repo twin:** [04-mcp-security](../../../../04-mcp-security/README.md)

Offline, harmless and tested. Nothing opens a network connection except the optional localhost-only HTTP server in lab 01. Secrets are canaries; domains end in `.example`. The same `rpc.py` (a tiny MCP-style JSON-RPC 2.0 server, not the official SDK) is copied into every lab, so each lab is self-contained.

## What it simulates

A simulated network of three fake MCP endpoints on reserved names (`files.corp.example:8001`, `notes...`, `crm...`). The scanner sends `initialize`, `tools/list`, `resources/list`, `prompts/list` and one malformed `tools/call` to each, then writes a recon report with findings mapped to the OWASP MCP Top 10 (2025, beta).

## Files

`rpc.py` (tiny JSON-RPC MCP-style server, same copy in every lab) · `fleet.py` (sloppy and hardened fleets) · `recon.py` (scanner and report) · `http_transport.py` (optional: serve one server over real HTTP bound to `127.0.0.1` on an ephemeral port; started and stopped in tests) · `demo.py` · `test_recon.py`

## Vulnerable vs defended

| | |
|---|---|
| **Vulnerable** | `files`: no auth, verbose errors that leak a canary DB password, `run_shell` and `read_file` tools, a `.env` resource. `notes`: no auth. `crm`: token required. |
| **Defended** | All three require tokens, generic errors, no shell tool, constrained schemas. An anonymous scan sees nothing. |

## Run it

```powershell
.venv/Scripts/python cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/01-recon-enumeration/demo.py
.venv/Scripts/python -m pytest cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/01-recon-enumeration -v
```

## Real demo output

(Canary suffixes are random on every run.)

```text
### VULNERABLE FLEET (anonymous scan)
MCP RECON REPORT
============================================================
files.corp.example:8001  auth=none  file-helper 0.3.0 (protocol 2025-06-18)
  tools=['read_file', 'run_shell'] resources=['file:///srv/app/.env'] prompts=['explain_error']
  [HIGH  ] RECON-01 Unauthenticated MCP endpoint  -> MCP07 Insufficient Authentication & Authorization
  [HIGH  ] RECON-03 Over-broad tool: read_file  -> MCP02 Privilege Escalation via Scope Creep
  [HIGH  ] RECON-03 Over-broad tool: run_shell  -> MCP02 Privilege Escalation via Scope Creep
  [HIGH  ] RECON-05 Sensitive resource exposed: file:///srv/app/.env  -> MCP10 Context Injection & Over-Sharing
  [MEDIUM] RECON-04 Weak input schema: read_file  -> MCP05 Command Injection & Execution
  [MEDIUM] RECON-04 Weak input schema: run_shell  -> MCP05 Command Injection & Execution
  [MEDIUM] RECON-02 Verbose error leakage  -> MCP01 Token Mismanagement & Secret Exposure
notes.corp.example:8002  auth=none  notes-mcp 1.1.0 (protocol 2025-06-18)
  tools=['add_note'] resources=[] prompts=['summarize_notes']
  [HIGH  ] RECON-01 Unauthenticated MCP endpoint  -> MCP07 Insufficient Authentication & Authorization
crm.corp.example:8003  auth=required
  authentication required: nothing enumerated anonymously
------------------------------------------------------------
findings by severity: high=5, medium=3

### HARDENED FLEET (anonymous scan)
MCP RECON REPORT
============================================================
files.corp.example:8001  auth=required
  authentication required: nothing enumerated anonymously
notes.corp.example:8002  auth=required
  authentication required: nothing enumerated anonymously
crm.corp.example:8003  auth=required
  authentication required: nothing enumerated anonymously
------------------------------------------------------------
findings by severity: none
```

## Try it yourself

Remove the token from one hardened server and predict the finding. Add a tool called `eval_sql` and see which rule fires. Add a new finding rule (for example: description longer than 500 characters).

## Limits

Real scanners also check TLS, Origin handling and rate limits; this lab keeps to the protocol level.
