# Lab: A mini API fuzzer (fuzzing vs brute forcing)

**Course topics:** "Fuzzing", "Fuzzing 101", "Fuzzing vs Brute Forcing", "Fuzzing APIs Using Open Source and Commercial Tools", "FFUF", "Wfuzz". Lesson: [03 Fuzzing and brute forcing](../../03-fuzzing-and-brute-forcing.md). A property-based fuzzing lab for MCP tools is in [cmcpse-course ch5](../../../../cmcpse-course/ch5-devsecops-for-mcp-security/labs/fuzz-mcp-tools/README.md); this lab is the plain HTTP API version.

**Time:** 45 minutes. **Tests:** 6, all offline. **Safety:** the target is an in-process function; no network. Only test systems you own or have written permission to test.

## Goal

Use the same engine twice: once to **brute force** hidden paths with a wordlist (ffuf/wfuzz style `FUZZ` keyword) and once to **fuzz** JSON fields with malformed values and an oracle that recognises bugs.

## Concept

| | Brute forcing | Fuzzing |
|---|---|---|
| Goal | Find a valid secret or resource | Find a bug |
| Inputs | Many valid-looking candidates (wordlist, numbers) | Malformed, boundary, unexpected types, huge, special characters |
| Success signal | Different status/size (found it) | Oracle: 5xx, stack trace, reflection, timing, business rule broken |
| Examples | Path discovery, coupon codes, passwords | Crash on `"qty": "abc"`, negative quantity accepted |

The fuzzer has two parts: **mutations** (a list of interesting values plus seeded random mutations of a valid seed) and an **oracle** (what counts as a bug). A fuzzer is only as good as its oracle.

## Steps

1. Run the demo. Four hidden paths are found with `-fc 404`; the fuzzer finds the three planted bugs (the stack trace counts as a separate finding).
2. Add `"metrics"` to `HIDDEN_PATHS` and rerun the keyword runner.
3. Add an oracle rule for responses slower than a threshold (you will need to return a simulated duration from `target`).
4. Change the seed. Are the same bug classes still found? Why do real fuzzers save a corpus of interesting inputs?

## Run

```text
.venv/Scripts/python appsec-course/12-input-validation-and-injection/labs/mini-fuzzer/demo.py
.venv/Scripts/python -m pytest appsec-course/12-input-validation-and-injection/labs/mini-fuzzer -q -p no:cacheprovider
```

## Expected output (real run)

```text
== Brute forcing paths (ffuf-style: -u /api/v1/FUZZ -w wordlist -fc 404) ==
  orders           [Status: 201, Size: 38]
  health           [Status: 200, Size: 17]
  internal/debug   [Status: 200, Size: 25]
  backup           [Status: 200, Size: 17]

== Fuzzing POST /api/v1/orders body fields (VULNERABLE) ==
  negative total accepted: 24 input(s), e.g. ('qty', '-1')
  server error: 39 input(s), e.g. ('qty', "''")
  stack trace leaked: 39 input(s), e.g. ('qty', "''")
  unencoded reflection: 2 input(s), e.g. ('qty', "'<script>alert(1)</script>'")

== Fuzzing POST /api/v1/orders body fields (SECURE) ==
  no findings
```

## Run the real tool (hedged)

See [real-tools/fuzzing-tools.md](../../real-tools/fuzzing-tools.md) for Burp Intruder, ZAP Fuzzer, wfuzz and ffuf. Quick ffuf equivalent of the path block:

```text
ffuf -u https://lab.example/api/v1/FUZZ -w wordlist.txt -fc 404
```

## What you learned

- Brute forcing and fuzzing share an engine but differ in inputs and oracle.
- Schema validation (types, ranges, lengths) removes whole classes of fuzzing findings.
