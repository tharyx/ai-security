# Lab 05: Cross-Server Privilege Escalation

> **Chapter 2 exercise:** Cross-server privilege escalation in a multi-agent pipeline
> **Study first:** [Lesson 03, section 5](../../03-mcp-attack-primitives.md#5-cross-server-privilege-escalation), [Lesson 05, section 7](../../05-real-world-case-studies.md#7-attack-chaining-across-multi-server-agentic-pipelines) · **Defending chapter:** [Chapter 4](../../../ch4-defending-and-hardening-mcp-servers/README.md) · **Repo twin:** [04-mcp-security](../../../../04-mcp-security/README.md)

Offline, harmless and tested. Nothing opens a network connection except the optional localhost-only HTTP server in lab 01. Secrets are canaries; domains end in `.example`. The same `rpc.py` (a tiny MCP-style JSON-RPC 2.0 server, not the official SDK) is copied into every lab, so each lab is self-contained.

## What it simulates

Three servers share one agent context: `web-reader` (trust 1), `tickets` (trust 2), `vault` (trust 3). A web page makes the agent read a planted ticket, which makes it read a secret from the vault, which it writes to a public ticket. The attacker never calls the vault. Four hops, three servers.

## Files

`rpc.py` · `privesc.py` (servers, chain-following model, host with flow policy, audit rule) · `demo.py` · `test_privesc.py`

## Vulnerable vs defended

| | |
|---|---|
| **Vulnerable** | Flat trust: any server's output can drive any server's tool. |
| **Defended** | Information-flow rules by trust level: **no read-up** (after lower-trust content, higher-trust tools need approval) and **no write-down** (after higher-trust data, lower-trust sinks need approval). A direct user request to the vault still works. `detect_escalation` reads the audit trace and names each hop where trust rose. |

## Run it

```powershell
.venv/Scripts/python cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/05-cross-server-privesc/demo.py
.venv/Scripts/python -m pytest cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/05-cross-server-privesc -v
```

## Real demo output

(Canary suffixes are random on every run.)

```text
== VULNERABLE (flat trust)
   hops: web-reader.fetch_page -> tickets.read_ticket -> vault.get_secret -> tickets.create_ticket
   canary reached the public ticket: True
   blocked: []
   escalation alerts: ['web-reader (trust 1) drove tickets.read_ticket (trust 2)', 'tickets (trust 2) drove vault.get_secret (trust 3)']
== DEFENDED (no read-up / no write-down)
   hops: web-reader.fetch_page
   canary reached the public ticket: False
   blocked: ['tickets.read_ticket: no read-up (context holds trust-1 content)']
   escalation alerts: []
```

## Try it yourself

Give the tickets server trust 3 and see the chain succeed again (a mislabeled trust level is a vulnerability). Add per-server sessions so the agent never holds both contexts.

## Limits

Real multi-agent systems also need authenticated messages between agents; see the repo's multi-agent-trust lab.
