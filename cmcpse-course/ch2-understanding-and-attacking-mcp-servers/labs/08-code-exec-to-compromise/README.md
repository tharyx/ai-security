# Lab 08: Code Execution to Complete Compromise

> **Chapter 2 exercise:** Code execution to complete compromise
> **Study first:** [Lesson 04, classes 3 and 4](../../04-mcp-vulnerability-classes.md), [Lesson 05, case 4](../../05-real-world-case-studies.md#case-4-anthropic-filesystem-mcp-server-cve-2025-53109--cve-2025-53110) · **Defending chapter:** [Chapter 4](../../../ch4-defending-and-hardening-mcp-servers/README.md) · **Repo twin:** [04-mcp-security](../../../../04-mcp-security/README.md)

Offline, harmless and tested. Nothing opens a network connection except the optional localhost-only HTTP server in lab 01. Secrets are canaries; domains end in `.example`. The same `rpc.py` (a tiny MCP-style JSON-RPC 2.0 server, not the official SDK) is copied into every lab, so each lab is self-contained.

## What it simulates

A vulnerable server with `run_command`, an injectable `ping_host`, and a `read_file` whose workspace check is a string prefix that does not resolve symlinks. The attack reads a fake credentials canary and uses it on a fake cloud API to create an admin user. Everything runs in memory: a virtual file system, a toy shell that only knows `echo`, `cat`, `ls`, `whoami` and a pretend `ping`, and a fake cloud. Payloads are harmless (`echo`, read a canary). A test proves the lab never imports `subprocess` or `os` and never calls `eval` or `exec`.

## Files

`rpc.py` · `compromise.py` (VFS, FakeShell, CloudAPI, both servers, `attack()`) · `demo.py` · `test_compromise.py`

## Vulnerable vs defended

| | |
|---|---|
| **Vulnerable** | Shell string injection, sibling-prefix bypass (`workspace-secrets`), symlink escape, service account that owns the credentials. |
| **Defended** | No `run_command`; `ping_host` with a strict hostname pattern and an argv list (no shell); `read_file` resolves symlinks then compares path components; the process runs as an unprivileged user so even a buggy path check cannot read the credentials (tested with `contain_paths=False`); scoped read-only cloud keys cap the blast radius if a key leaks. |

## Run it

```powershell
.venv/Scripts/python cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/08-code-exec-to-compromise/demo.py
.venv/Scripts/python -m pytest cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/08-code-exec-to-compromise -v
```

## Real demo output

(Canary suffixes are random on every run.)

```text
=== VULNERABLE vuln-ops (runs as svc)
   1 recon: tools = ['run_command', 'ping_host', 'read_file']
   2 code execution via run_command: YES
   3 injection via ping_host: YES
   4 file read via sibling prefix: READ
   4 file read via symlink: READ
   4 file read via traversal: denied
   6 pivot: used the stolen key against the cloud API, created an admin user
   key stolen: True   cloud compromised: True

=== HARDENED safe-ops (runs as mcp)
   1 recon: tools = ['ping_host', 'read_file']
   2 code execution via run_command: no
   3 injection via ping_host: no
   4 file read via sibling prefix: denied
   4 file read via symlink: denied
   4 file read via traversal: denied
   6 pivot: no credentials obtained
   key stolen: False   cloud compromised: False
```

## Try it yourself

Add a pretend `curl` command and an egress allowlist. Make the hardened `read_file` resolve a relative path against the workspace and test `a/../../x`.

## Limits

The prefix and symlink patterns mirror the reported Filesystem MCP server CVEs; this is not their code.
