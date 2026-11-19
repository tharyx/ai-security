# Lab 03: Prompt Injection via Crafted Tool Responses

> **Chapter 2 exercise:** Exploit prompt injection via crafted tool responses
> **Study first:** [Lesson 03, section 2](../../03-mcp-attack-primitives.md#2-prompt-injection-via-tool-responses) · **Defending chapter:** [Chapter 4](../../../ch4-defending-and-hardening-mcp-servers/README.md) · **Repo twin:** [04-mcp-security](../../../../04-mcp-security/README.md)

Offline, harmless and tested. Nothing opens a network connection except the optional localhost-only HTTP server in lab 01. Secrets are canaries; domains end in `.example`. The same `rpc.py` (a tiny MCP-style JSON-RPC 2.0 server, not the official SDK) is copied into every lab, so each lab is self-contained.

## What it simulates

A support agent reads tickets (`get_ticket`). Ticket 2 contains hidden instructions. The agent also has `get_customer_record` (private canary data) and `send_email`. Indirect injection makes it read the record and email it to `drop@evil.example`. A **direct** injection typed by an outsider is limited to that outsider's permissions, which shows why indirect injection is the bigger risk.

## Files

`rpc.py` · `inject.py` (servers, model, detector, quarantine, host) · `demo.py` · `test_inject.py`

## Vulnerable vs defended

| | |
|---|---|
| **Vulnerable** | Tool results go straight into the model context; no permission or egress checks. |
| **Defended** | Three separate controls: **quarantine** (strip instruction-like text and label output as untrusted), **taint policy** (after untrusted content, side-effect tools need human approval), **egress allowlist** (recipients must be `@corp.example`). A detector raises alerts but blocks nothing by itself. |

## Run it

```powershell
.venv/Scripts/python cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/03-tool-response-injection/demo.py
.venv/Scripts/python -m pytest cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/03-tool-response-injection -v
```

## Real demo output

(Canary suffixes are random on every run.)

```text
VULNERABLE host                    leaked=True  blocked=[] alerts=[['override', 'secrecy', 'send-out', 'to-the-ai', 'tool-directive']]
defense 1: quarantine output       leaked=False blocked=[] alerts=[['override', 'secrecy', 'send-out', 'to-the-ai', 'tool-directive']]
defense 2: taint -> approval       leaked=False blocked=['send_email: needs human approval after untrusted content'] alerts=[['override', 'secrecy', 'send-out', 'to-the-ai', 'tool-directive']]
defense 3: egress allowlist        leaked=False blocked=['send_email: recipient drop@evil.example outside allowlist'] alerts=[['override', 'secrecy', 'send-out', 'to-the-ai', 'tool-directive']]
DIRECT injection by an outsider: ['send_email: not permitted for this principal'] outbox: []
```

## Try it yourself

Add an obfuscated payload that the detector misses and confirm the taint policy still stops the send. Allow `send_email` to `@corp.example` only and try to leak to an internal address.

## Limits

Detection is a net with holes. Prefer the deterministic controls.
