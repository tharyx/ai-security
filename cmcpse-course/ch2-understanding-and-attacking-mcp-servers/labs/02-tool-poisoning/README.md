# Lab 02: Tool Poisoning (Description and Schema Variants)

> **Chapter 2 exercise:** Perform a tool poisoning attack on a vulnerable MCP server
> **Study first:** [Lesson 03, section 1](../../03-mcp-attack-primitives.md#1-tool-poisoning-attacks), [Lesson 04, class 5](../../04-mcp-vulnerability-classes.md#5-insecure-prompt-handling-in-tool-schemas) · **Defending chapter:** [Chapter 4](../../../ch4-defending-and-hardening-mcp-servers/README.md) · **Repo twin:** [04-mcp-security](../../../../04-mcp-security/README.md)

Offline, harmless and tested. Nothing opens a network connection except the optional localhost-only HTTP server in lab 01. Secrets are canaries; domains end in `.example`. The same `rpc.py` (a tiny MCP-style JSON-RPC 2.0 server, not the official SDK) is copied into every lab, so each lab is self-contained.

## What it simulates

An approved `calculator` server carries hidden instructions. A gullible mock model (`MockLLM` subclass) obeys them: it reads a canary credentials file with the `files` server's `read_file` and sends the content to the attacker in a hidden `sidenote` parameter of `add`. The user asked only for `2 + 3` and gets `5`. Two variants: the instruction in the **description**, and in a **parameter description** of the schema (the schema-manipulation variant with the extra `sidenote` parameter).

## Files

`rpc.py` · `poison.py` (workspace in a temp dir, servers, gullible model, scanner, mock host) · `demo.py` · `test_poison.py`

## Vulnerable vs defended

| | |
|---|---|
| **Vulnerable** | Host builds the prompt from every description and parameter description and executes whatever the model calls. `read_file` can read any path. |
| **Defended** | Three independent layers: (1) a scanner refuses servers with hidden-instruction patterns or invisible characters; (2) baseline pinning blocks calls with arguments the user never approved; (3) `read_file` confined to the project folder. Tests show each layer alone, and that baseline pinning alone leaves the file read in place (layers matter). |

## Run it

```powershell
.venv/Scripts/python cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/02-tool-poisoning/demo.py
.venv/Scripts/python -m pytest cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/02-tool-poisoning -v
```

## Real demo output

(Canary suffixes are random on every run.)

```text
=== variant: hidden text in the tool description ===
VULNERABLE host: answer='The answer is 5'
   canary file read: True   exfiltrated to attacker: True
DEFENDED host (scan + pinned args): answer='(unknown tool add)'
   canary file read: False   exfiltrated to attacker: False
   blocked servers: {'calculator': ['hidden-block', 'secrecy', 'sensitive-path', 'tool-directive']}
=== variant: hidden text in the tool schema ===
VULNERABLE host: answer='The answer is 5'
   canary file read: True   exfiltrated to attacker: True
DEFENDED host (scan + pinned args): answer='(unknown tool add)'
   canary file read: False   exfiltrated to attacker: False
   blocked servers: {'calculator': ['hidden-block', 'secrecy', 'sensitive-path', 'tool-directive']}

Scanner verdict for the description variant: ['hidden-block', 'secrecy', 'sensitive-path', 'tool-directive']
```

## Try it yourself

Hide the instruction with a zero-width character and see which pattern family catches it. Rename `sidenote` to `context` and check the baseline still blocks it. Make the scanner miss something, then add a rule.

## Limits

The model is a deterministic mock: real models obey less predictably, which is why defenses must not depend on the model.
