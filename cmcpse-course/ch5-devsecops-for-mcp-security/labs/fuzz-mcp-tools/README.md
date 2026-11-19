# Lab: Fuzzing MCP Tool Inputs

**Course exercise:** "Fuzz MCP tool inputs using a Python-based fuzzing framework". Lesson: [03 DAST, fuzzing and runtime testing](../../03-dast-fuzzing-and-runtime-testing.md).

**Time:** 45 minutes. Offline. **Nothing real runs:** `sandbox()` replaces `subprocess`, `os.system` and `urlopen` with recorders, and the "secret" is a canary file the server should never reach.

The target is the server from the [SAST lab](../sast-vulnerable-mcp-server/README.md): `vulnerable_server/` first, then `fixed_server/`.

## What the fuzzer does

1. Calls `tools/list` and reads every tool's `inputSchema`.
2. **Grammar phase:** every attack payload (traversal, shell metacharacters, SSRF URLs, format strings, odd Unicode, huge strings) against every string parameter.
3. **Mutation phase:** 300 to 500 seeded random mutations of valid arguments: inserted fragments, duplicated or truncated strings, wrong types, edge numbers, missing and extra arguments.
4. **Oracles:** `crash`, `path-traversal`, `command-injection`, `ssrf`, `info-leak` (see the lesson).
5. Reports the first finding per bug class and tool. Same `seed` gives the same result.

I did not use Hypothesis because it is not installed in this repo's environment. `hypothesis_variant.py` shows the same test with Hypothesis (not executed by the author; `pip install hypothesis`), which adds automatic **shrinking**. Other options: **atheris** (coverage-guided, best for parsers and native code) and **boofuzz** (network protocols).

## Steps

```text
.venv/Scripts/python cmcpse-course/ch5-devsecops-for-mcp-security/labs/fuzz-mcp-tools/demo.py
.venv/Scripts/python -m pytest cmcpse-course/ch5-devsecops-for-mcp-security/labs/fuzz-mcp-tools -v
```

1. Read the findings against `vulnerable_server`. For each, open the tool and find the line.
2. Fix your copy of the server (from the SAST lab) and fuzz it: edit `demo.py` to point at your folder.
3. Add a payload group (for example Windows paths `..\\..\\windows`) and rerun.
4. Add an oracle: flag any response bigger than 100 KB.

## Expected output (real run)

```text
=== vulnerable_server: 11 finding(s) {'command-injection': 2, 'crash': 6, 'info-leak': 1, 'path-traversal': 1, 'ssrf': 1} ===
  [command-injection] archive_logs: shell string built from input: 'tar czf x; id.tgz logs'   input={'name': 'x; id'}
  [command-injection] ping_host: shell string built from input: 'ping -c 1 x; id'   input={'host': 'x; id'}
  [crash] apply_discount: TypeError escaped the handler   input=None
  [crash] archive_logs: TypeError escaped the handler   input='x'
  [crash] fetch_url: TypeError escaped the handler   input={}
  [crash] ping_host: TypeError escaped the handler   input={'host': 'example.comexample.comexample.comexample.comexample.comexample.comexample.comexa
  [crash] read_note: TypeError escaped the handler   input={'name': None}
  [crash] split_bill: TypeError escaped the handler   input={'people': 2}
  [info-leak] read_note: error response contains 'Traceback'   input={'name': '....//secret.txt'}
  [path-traversal] read_note: canary from outside the notes directory was returned   input={'name': '../secret.txt'}
  [ssrf] fetch_url: server fetched '../secret.txt'   input={'url': '../secret.txt'}

=== fixed_server: 0 finding(s) {} ===
```

Notes: the `crash` findings are exceptions that escape the handler (type confusion and missing arguments). The `ssrf` finding shows a relative path being passed to `urlopen`: the vulnerable tool fetches whatever string it is given. The fixed server returns **zero findings** for several seeds.

## Why the oracles use canaries and recorders

A fuzzer triggers the bugs it finds. If the target runs `ping x; id` for real, the fuzzer just ran `id`. So the sandbox records the command string instead of running it, and traversal is proven by a canary file outside the notes folder instead of reading real system files.
