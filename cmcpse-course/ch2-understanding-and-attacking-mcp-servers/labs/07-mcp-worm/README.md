# Lab 07: MCP Worm Propagation and Containment

> **Chapter 2 exercise:** MCP worm propagation
> **Study first:** [Lesson 05, section 8](../../05-real-world-case-studies.md#8-multi-agent-attack-propagation-patterns), repo [CAISP ch7 worm simulation](../../../../caisp-course/ch7-emerging-threats-governance-compliance/labs/ai-worm-simulation/worm_sim.py) · **Defending chapter:** [Chapter 4](../../../ch4-defending-and-hardening-mcp-servers/README.md) · **Repo twin:** [04-mcp-security](../../../../04-mcp-security/README.md)

Offline, harmless and tested. Nothing opens a network connection except the optional localhost-only HTTP server in lab 01. Secrets are canaries; domains end in `.example`. The same `rpc.py` (a tiny MCP-style JSON-RPC 2.0 server, not the official SDK) is copied into every lab, so each lab is self-contained.

## What it simulates

N agents each connect to a `bus` server (messages) and a shared `memory` server. A harmless canary text block in a tool output makes a gullible model copy it into shared memory and message every peer. One outsider message to one agent starts it. Topologies: ring or full; channels: inbox, memory or both.

## Files

`rpc.py` · `worm.py` (servers, gullible model, agents, swarm, guard, containment) · `demo.py` · `test_worm.py`

## Vulnerable vs defended

| | |
|---|---|
| **Vulnerable** | Agents obey instructions found in any tool output and replicate freely. |
| **Defended** | An **output guard** blocks outbound calls whose content replicates untrusted inbound text (4-word shingle overlap) and **quarantines** the agent and purges shared memory. A **fan-out cap** only slows the spread. **`contain()`** is incident response after infection: quarantine infected agents, purge memory, drop worm messages in flight. Normal acknowledgements are not flagged. |

## Run it

```powershell
.venv/Scripts/python cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/07-mcp-worm/demo.py
.venv/Scripts/python -m pytest cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/07-mcp-worm -v
```

## Real demo output

(Canary suffixes are random on every run.)

```text
inbox + shared memory (vulnerable)             infected per round: [8, 8, 8, 8]   alerts=0
inbox only (vulnerable, ring)                  infected per round: [1, 3, 5, 7, 8]   alerts=0
inbox only, fan-out cap 1                      infected per round: [1, 2, 3, 4, 5, 6, 7, 8]   alerts=8
output guard + quarantine                      infected per round: [0, 0, 0, 0]   alerts=1

containment: infected per round before: [1, 3] -> contain(): {'quarantined': 3, 'memory_purged': 0, 'messages_dropped': 4} -> after 5 more rounds: [3, 3, 3, 3, 3]
```

## Try it yourself

Make the payload paraphrase itself each hop and see where the overlap guard fails. Add a signed-message check from the multi-agent-trust lab.

## Limits

The worm is a canary string and a mock model. No network, no real code execution.
