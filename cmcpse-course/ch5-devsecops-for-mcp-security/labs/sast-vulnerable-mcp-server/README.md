# Lab: SAST and Secret Scanning on a Deliberately Vulnerable MCP Server

**Course exercise:** "Run SAST scanning against a deliberately vulnerable MCP server codebase". Lesson: [02 SAST and secret scanning](../../02-sast-and-secret-scanning.md).

**Time:** 60 minutes. Offline, standard library only. The vulnerable code is **only parsed, never imported or run, by the scanner**. Every key in it is **FAKE** and marked so.

## Files

| File | Role |
|---|---|
| `vulnerable_server/` | The target: six files (`config.py`, `tools_files.py`, `tools_shell.py`, `tools_web.py`, `tools_math.py`, `server.py`). Do not copy it |
| `fixed_server/` | The reference fix (adds `errors.py` and `schema.py`) |
| `mcp_sast.py` | AST scanner with six MCP rules, MCP001 to MCP006, plus the secret scan |
| `secret_scan.py` | Secret scanner: named regex patterns, generic assignment, entropy. Redacts output |
| `semgrep-mcp-rules.yml` | Optional Semgrep version of some rules (not executed by the author) |
| `demo.py`, `test_cmcpse5_sast.py` | Demo and 29 tests (one is skipped until you set `MY_FIX_DIR`) |

## Steps

1. Scan the vulnerable server and read each finding. For each one write one sentence: what could an attacker do?

```text
.venv/Scripts/python cmcpse-course/ch5-devsecops-for-mcp-security/labs/sast-vulnerable-mcp-server/mcp_sast.py cmcpse-course/ch5-devsecops-for-mcp-security/labs/sast-vulnerable-mcp-server/vulnerable_server
```

2. Copy the vulnerable server and fix **your copy** until the scanner is clean (keep all six tools working):

```text
cp -r cmcpse-course/ch5-devsecops-for-mcp-security/labs/sast-vulnerable-mcp-server/vulnerable_server my_fix_server
.venv/Scripts/python cmcpse-course/ch5-devsecops-for-mcp-security/labs/sast-vulnerable-mcp-server/mcp_sast.py my_fix_server
```

3. Run the tests. The last test is skipped until you point it at your fix:

```text
MY_FIX_DIR=my_fix_server .venv/Scripts/python -m pytest cmcpse-course/ch5-devsecops-for-mcp-security/labs/sast-vulnerable-mcp-server -v
```

(PowerShell: `$env:MY_FIX_DIR="my_fix_server"; .venv/Scripts/python -m pytest ...`)

4. Only after you tried: compare with `fixed_server/`. Which of your choices differ? (For example: is your path check `is_relative_to` or `startswith`? `startswith` is a known weak pattern, see the CVE-2025-53110 class.)

## The six rules

| Rule | Planted in | Fix in `fixed_server/` |
|---|---|---|
| MCP001 shell exec | `tools_shell.py` (`shell=True`, `os.system`) | argument list, `shell=False`, allowlist regex |
| MCP002 path join | `tools_files.py` | `resolve()` plus `is_relative_to()` |
| MCP003 SSRF | `tools_web.py` | https only, host allowlist, no IP literals |
| MCP004 secret in description | `server.py` (an f-string with `config.API_KEY`) | clean description, secret from environment |
| MCP005 bind 0.0.0.0 | `config.py` | `127.0.0.1` |
| MCP006 verbose errors | `server.py` (`traceback.format_exc()`, `str(exc)`) | generic message plus an error id |
| SECRET | `config.py` (four fake keys) | environment variable |

## Expected output (real run)

```text
=== vulnerable_server: 11 finding(s) ===
  config.py:6: MCP005 [medium] '0.0.0.0': Server bound to all interfaces (reachable from the whole network)
  server.py:11: MCP004 [high] Secret inside a tool description (visible to every client and model)
  server.py:71: MCP006 [medium] Exception text or traceback returned to the client (information leak)
  tools_files.py:9: MCP002 [high] in read_note(): Path join without canonicalization and containment check (path traversal)
  tools_shell.py:8: MCP001 [high] subprocess.run(...) Shell execution: user text can become a command (MCP05 command injection)
  tools_shell.py:13: MCP001 [high] os.system(...) Shell execution: user text can become a command (MCP05 command injection)
  tools_web.py:7: MCP003 [high] in fetch_url(): Outbound fetch of a non-constant URL without an allowlist (SSRF)
  config.py:10: SECRET [high] api-key-sk sk-F...(43 chars) (FAKE fixture)
  config.py:11: SECRET [high] aws-access-key-id AKIA...(20 chars) (FAKE fixture)
  config.py:12: SECRET [high] github-token ghp_...(40 chars) (FAKE fixture)
  config.py:13: SECRET [high] generic-assignment wJal...(41 chars) (FAKE fixture)
  by rule: {'MCP001': 2, 'MCP002': 1, 'MCP003': 1, 'MCP004': 1, 'MCP005': 1, 'MCP006': 1, 'SECRET': 4}

=== fixed_server: 0 finding(s) ===
  by rule: {}
```

## Optional: Bandit and Semgrep (not executed by the repo author)

```text
pip install bandit semgrep
bandit -r cmcpse-course/ch5-devsecops-for-mcp-security/labs/sast-vulnerable-mcp-server/vulnerable_server
semgrep --config cmcpse-course/ch5-devsecops-for-mcp-security/labs/sast-vulnerable-mcp-server/semgrep-mcp-rules.yml cmcpse-course/ch5-devsecops-for-mcp-security/labs/sast-vulnerable-mcp-server/vulnerable_server
```

Compare: which of the six rules does Bandit find on its own (expect shell and hardcoded-password style checks) and which need a custom rule (path join, SSRF, description secrets, error leakage)? That gap is the reason MCP-specific rules exist. Flags and rule names change between versions: check the tool documentation.

## Limits (be honest in an interview)

The scanner works per function and by name. It does not follow data across files, so a guard in another module can fool it, and an alias such as `run = os.system` hides a sink. Real tools add taint analysis. The tests prove the rules work on this codebase, not that the rules are complete.
