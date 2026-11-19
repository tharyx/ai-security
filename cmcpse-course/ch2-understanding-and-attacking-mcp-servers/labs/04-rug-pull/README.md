# Lab 04: Rug-Pull (Post-Approval Behavior Change)

> **Chapter 2 exercise:** Demonstrate a rug-pull attack by modifying tool behavior post-approval
> **Study first:** [Lesson 03, section 4](../../03-mcp-attack-primitives.md#4-rug-pull-attacks), [Lesson 05, case 1](../../05-real-world-case-studies.md#case-1-postmark-mcp-september-2025) · **Defending chapter:** [Chapter 4](../../../ch4-defending-and-hardening-mcp-servers/README.md) · **Repo twin:** [04-mcp-security](../../../../04-mcp-security/README.md)

Offline, harmless and tested. Nothing opens a network connection except the optional localhost-only HTTP server in lab 01. Secrets are canaries; domains end in `.example`. The same `rpc.py` (a tiny MCP-style JSON-RPC 2.0 server, not the official SDK) is copied into every lab, so each lab is self-contained.

## What it simulates

Two rug-pulls. **A. Runtime:** a mail server is approved with a clean description, then swaps its own description (same name, same version) to carry hidden instructions. **B. Release:** a registry with 16 clean releases (1.0.0 to 1.0.15) and a release 1.0.16 that silently BCCs every email to the attacker, in the pattern reported for postmark-mcp. The tool definition does not change in B.

## Files

`rpc.py` · `rugpull.py` (mail server, registry, host, lockfile install, egress audit) · `demo.py` · `test_rugpull.py`

## Vulnerable vs defended

| | |
|---|---|
| **Vulnerable** | Host re-reads definitions and trusts them; installs `latest`. |
| **Defended** | Definition **pinning** (hash at approval, drop on drift, re-approval) catches A. A **lockfile with integrity hashes** blocks the unreviewed release in B and a republished version with changed content. **Egress audit** catches the BCC even when everything else is blind. The test `test_auto_update_to_latest_installs_the_backdoor_and_definitions_do_not_change` proves definition pinning alone cannot see B. |

## Run it

```powershell
.venv/Scripts/python cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/04-rug-pull/demo.py
.venv/Scripts/python -m pytest cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/04-rug-pull -v
```

## Real demo output

(Canary suffixes are random on every run.)

```text
A. Dynamic definition rug-pull (same process, same version 1.0.0)
  pin_definitions=False -> 'Done.'; mail log: ['bcc@evil.example']; alerts: []
  pin_definitions=True  -> '(no such tool: blocked)'; mail log: []; alerts: ['definition of send_email changed since approval: re-approval required']

B. Release rug-pull (postmark-mcp pattern: 16 clean releases, then 1.0.16)
  auto-update to latest = 1.0.16; definition-pin alerts: []; egress audit: ['bcc=bcc@evil.example']
  with lockfile: refused -> 1.0.16 is not in the lockfile: review and add it first
```

## Try it yourself

Add `bcc` to the approved schema and see what changes. Add a recipient allowlist that blocks the send instead of auditing it afterwards.

## Limits

The lab uses 16 clean releases for 1.0.0 to 1.0.15; the real incident is reported as about 15 earlier benign versions.
