# Lab: Input validation using industry best practices and regex

**Course exercise:** Input validation using industry best practices and regex. Lesson: [02 section 2](../../02-reviewing-code-for-security-defences.md#2-input-validation) and [2.1](../../02-reviewing-code-for-security-defences.md#21-input-validation-with-industry-best-practices-and-regex).

**Time:** 45 minutes. **Tests:** 20, all offline. **Safety:** pure functions; the ReDoS timing demo uses small inputs (under a second).

## Goal

Spot the regex mistakes reviewers see most often, replace them with allowlist validation that matches the whole input, and recognise patterns that can cause ReDoS.

## Concept

[validators.py](validators.py) has weak validators (review findings) and strong ones:

| Weak | Why it fails | Strong |
|---|---|---|
| `re.match(r"[a-z0-9_]{3,20}", s)` | anchors only the start | `USERNAME.fullmatch(normalize(s))` + reserved names |
| `re.match(r"^...$", s)` | `$` matches before a trailing `\n` | `fullmatch` |
| `"<script" not in s.lower()` | blocklist | allowlist (and output encoding at the sink) |
| `re.search(r"\d{6}", s)` | digits anywhere | `fullmatch(r"[1-9][0-9]{5}")` |
| regex-only date | `2026-02-30` passes | regex + `date.fromisoformat` |

Also: `validate_form()` (schema validation that **rejects unknown fields**, so `role=admin` cannot be smuggled in), `strong_quantity()` (ASCII digits and a range; `isdigit()` alone accepts other scripts' digits) and `has_nested_quantifier()` (a heuristic ReDoS detector for shapes like `(a+)+`).

## Run

```text
.venv/Scripts/python appsec-course/02-secure-code-review-and-asvs/labs/input-validation-regex/demo.py
.venv/Scripts/python -m pytest appsec-course/02-secure-code-review-and-asvs/labs/input-validation-regex -q -p no:cacheprovider
```

## Expected output (real run; timings differ on your machine)

```text
field     | input                            | weak  | strong
username  | "bob'; DROP TABLE users--"       | True  | False
username  | 'alice\n'                        | True  | False
username  | 'ａｄｍｉｎ'                          | True  | False
comment   | '<img src=x onerror=alert(1)>'   | True  | False
pin       | '411001 OR 1=1'                  | True  | False

Calendar check: '2026-02-30' regex ok: True | strong_date: False

Schema validation with an extra 'role' field:
({}, ['unknown field: role'])
({'username': 'alice', 'email': 'alice@shop.example', 'pin': '411001', 'quantity': '2'}, [])

ReDoS: nested quantifier detector
  (a+)+$             nested=True
  (\w+\s?)*$         nested=True
  ([a-z0-9]+)*@      nested=True
  [a-z]+$            nested=False
  [A-Z]{3}-[0-9]{4}  nested=False

ReDoS: time for (a+)+$ on 'a'*n + '!' (grows about 2x per extra 'a')
  n=16: 2.4 ms
  n=18: 11.6 ms
  n=20: 51.6 ms
  safe a+$ on n=20: 0.160 ms
```

## Steps

1. For each weak validator, predict the bypass before you read the demo row.
2. The ReDoS timings roughly double or quadruple for every two extra characters. Do **not** try n=30 (it can take minutes). Explain why a 50-character input could hang a web worker.
3. Rewrite `(\w+\s?)*$` (a "words separated by spaces" pattern) without nesting, for example `\w+(?: \w+)*`, and check `has_nested_quantifier` and timing.
4. Add a validator for an Indian PAN-like format (5 letters, 4 digits, 1 letter; use fake values only) with tests for good and bad input.
5. Explain why `O'Brien` must pass name validation, and therefore why validation cannot replace parameterized queries.

## Run the real tools (hedged)

- Online regex testers (regex101 and similar) show matches and steps; use fake data only.
- ReDoS checkers exist for several languages (for example `recheck`, or Semgrep and CodeQL ReDoS queries; verify current names). Linear-time engines: Google RE2 (Python binding `google-re2`), Rust `regex`, Go `regexp`.
- Framework validators: pydantic, marshmallow, Django forms, Java Bean Validation, JSON Schema for APIs.

## What you learned

- Validate on the server with allowlists, full matches, length limits, type conversion and range checks, after normalization.
- `re.match`, `re.search` and `$` are the classic partial-match bugs; use `re.fullmatch`.
- Reject unknown fields to block mass assignment.
- Nested quantifiers can turn one request into a denial of service.
- Validation reduces attack surface; encoding and parameterization at the sink are still required.
