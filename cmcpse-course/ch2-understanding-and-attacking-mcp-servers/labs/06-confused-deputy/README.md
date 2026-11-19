# Lab 06: Confused Deputy

> **Chapter 2 exercise:** Confused deputy attack exercise
> **Study first:** [Lesson 03, section 6](../../03-mcp-attack-primitives.md#6-confused-deputy-attacks), [Lesson 05, case 5](../../05-real-world-case-studies.md#case-5-asana-mcp-server-june-2025) · **Defending chapter:** [Chapter 4](../../../ch4-defending-and-hardening-mcp-servers/README.md) · **Repo twin:** [04-mcp-security](../../../../04-mcp-security/README.md)

Offline, harmless and tested. Nothing opens a network connection except the optional localhost-only HTTP server in lab 01. Secrets are canaries; domains end in `.example`. The same `rpc.py` (a tiny MCP-style JSON-RPC 2.0 server, not the official SDK) is copied into every lab, so each lab is self-contained.

## What it simulates

Part 1: a billing MCP server holds a service role that can read every tenant. A caller from tenant `evilcorp` asks for `acme`'s invoices. Part 2: an OAuth proxy with one static upstream client id remembers the victim's consent, so an attacker-registered client rides it.

## Files

`rpc.py` · `deputy.py` (token service, datastore, billing server, OAuth proxy) · `demo.py` · `test_deputy.py`

## Vulnerable vs defended

| | |
|---|---|
| **Vulnerable** | The server authorizes with its own identity and never compares caller and resource owner; the proxy keys consent on the static upstream client id. |
| **Defended** | Token **audience**, **scope** and **tenant** checks; a **row-level security** check in the data store as a second layer (the test with a deliberately buggy server check still denies); no token passthrough (wrong audience rejected); **per-client consent** and exact redirect matching in the proxy; an audit log that names the caller on every allow and deny. |

## Run it

```powershell
.venv/Scripts/python cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/06-confused-deputy/demo.py
.venv/Scripts/python -m pytest cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/06-confused-deputy -v
```

## Real demo output

(Canary suffixes are random on every run.)

```text
VULNERABLE: mallory (tenant evilcorp) asks for acme -> acme invoices: total 120k, ref CANARY-ACME-INV-682441fff0
   audit: ['export acme (caller unchecked)']
DEFENDED: mallory (tenant evilcorp) asks for acme -> ERROR forbidden
   audit: ['deny acme for mallory: tenant mismatch']

static-id proxy: attacker link -> https://evil.example/cb?code=CODE-1
per-client consent: attacker link -> consent_required
```

## Try it yourself

Remove the audience check and issue a token for `calendar-mcp`. Add a `tenant_admin` scope that may read all tenants and audit its use.

## Limits

Real OAuth flows have more steps (PKCE, resource indicators); see the repo authentication lab.
