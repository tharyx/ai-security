# Lab 03: Abusing Function-Calling Parameters (offline twin of an MCP tool in a chat UI)

> **Chapter 3 exercise:** Abusing Function-Calling Parameters via LibreChat's MCP Tools
> **Study first:** [Lesson 03, section 2.1](../../03-attacking-tool-and-function-calling-interfaces.md#21-function-calling-abuse-and-parameter-injection)
> **Generic material in this repo:** [CMCPSE lab 08 code execution to compromise](../../../../cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/08-code-exec-to-compromise/README.md) · [04-mcp-security tool-security](../../../../04-mcp-security/tool-security/README.md)

Offline, harmless and tested. No network, no API key, no GPU, no Docker needed by the tests. Secrets are canaries or clearly fake values; domains end in `.example`. The model is a `MockLLM` subclass: deterministic and deliberately gullible. The lab is **self-contained** (it does not import code from another lab).

## What it simulates

A chat host lets a gullible function-calling model call `get_orders` (SQL on sqlite) and `read_report` (files). The model copies user words into parameters. Attacks: SQL injection (`1 OR 1=1`), object-level authorization bypass (asking for customer 2), path traversal (`../secrets.txt`), extra and mistyped parameters.

## Files

`fc_abuse.py` (`Workspace`, `OrdersServer`, `ChatModel`, `ChatHost`, `validate`) · `demo.py` · `test_caase_ch3_fc_abuse.py`

## Vulnerable vs defended

| | |
|---|---|
| **Vulnerable** | f-string SQL, unchecked path join, the customer id taken from the argument. |
| **Defended** | JSON-schema validation (`additionalProperties: false`, patterns, enums), **bound SQL parameters**, the customer id taken from the **session** (not the argument), path confinement. Each control tested alone: schema alone does not stop a valid-looking foreign id; bound parameters alone do not stop traversal. |

## Run it

```powershell
.venv/Scripts/python caase-course/ch3-agent-memory-context-and-tool-use/labs/03-function-call-parameter-abuse/demo.py
.venv/Scripts/python -m pytest caase-course/ch3-agent-memory-context-and-tool-use/labs/03-function-call-parameter-abuse -v
```

## Real demo output

(Canary suffixes are random on every run.)

```text
== VULNERABLE
  orders for 1 OR 1=1                              -> leaked=True  '[[10, "book", "vip"], [11, "pen", "vip"], [1'
  orders for 2                                     -> leaked=True  '[[12, "laptop", "CANARY-BOB-NOTE-b64df8f3d0"'
  report ../secrets.txt                            -> leaked=True  'internal token CANARY-SECRET-FILE-7b8f4832da'
  call get_orders {"customer_id": "1", "debug": "1"} -> leaked=False '[[10, "book", "vip"], [11, "pen", "vip"]]'
== DEFENDED
  orders for 1 OR 1=1                              -> leaked=False 'error: customer_id has invalid format'
  orders for 2                                     -> leaked=False '[[10, "book", "vip"], [11, "pen", "vip"]]'
  report ../secrets.txt                            -> leaked=False 'error: name not in enum'
  call get_orders {"customer_id": "1", "debug": "1"} -> leaked=False 'error: unexpected parameter debug'
```

12 tests pass.

## Try it yourself

Add a `limit` parameter and a way to abuse it (huge value). Add a `format` enum parameter that selects a template and see how an unvalidated value becomes a second injection.

## Limits

The real exercise uses LibreChat and a real MCP server (guide below). This twin uses the same bug classes without any network or UI.

## Real-tool guide: LibreChat with an MCP server (hedged)

> Not run by the repo author. LibreChat changes quickly: read the current docs (librechat.ai) before you start. Use a **local, throwaway** setup with fake data only. Never point this at a shared or production instance.

1. Run LibreChat locally (the project documents Docker Compose and an npm route; Docker needs disk space, so check free space on D: first).
2. Add an MCP server in LibreChat's YAML configuration under an `mcpServers` section (name, `type`/transport, `command` and `args` for stdio, or a `url` for a remote server). Check the docs for the exact keys of your version.
3. Use a deliberately vulnerable **local** MCP server of your own (for example a copy of the CMCPSE labs' tools re-implemented with the official Python SDK, `pip install mcp`), with fake data and canaries.
4. In a chat, ask the model to call the tool with the parameter shapes you tested in this lab (a quoted SQL fragment, a path with `..`, another user's id). Watch whether the model, the UI or the server stops each one.
5. Then fix the server with the same four controls and repeat.

What to observe: which layer refused (model, UI approval prompt, server schema, server logic), and what the tool-call log shows. On this course laptop (no GPU) use a cloud model through OpenRouter or another API for the chat model, not a local one.
