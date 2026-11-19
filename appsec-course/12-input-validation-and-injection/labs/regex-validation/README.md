# Lab: Learning to validate input with regular expressions

**Course exercise:** "Learning To Validate Input With Regular Expressions". Also covers "Implementing Input Validation", "Client-Side vs. Server-Side Validation", "Whitelisting & Blacklisting" and "Implementing Input Sanitization". Lesson: [01 Input validation and sanitization](../../01-input-validation-and-sanitization.md). A related secure-code-review regex lab is in [chapter 02](../../../02-secure-code-review-and-asvs/README.md).

**Time:** 45 minutes. **Tests:** 8, all offline. **Safety:** pure functions. Only test systems you own or have written permission to test.

## Goal

Write allowlist validators that cannot be bypassed, see the classic anchoring mistakes, spot a ReDoS-prone pattern, and prove that client-side checks are not a control.

## Concept

- **`re.fullmatch`** (or `\A...\Z`). `re.match` anchors only the start; `$` also matches before a final newline.
- **Allowlist** what is valid; denylists miss `<ScRiPt>` and `<img onerror>`.
- **Cap the length first**, then run the regex.
- **ReDoS:** nested quantifiers like `(a+)+` backtrack exponentially on a near-miss input. Use simple patterns, length caps, or a linear-time engine (RE2, Rust `regex`, .NET `RegexOptions.NonBacktracking`).
- **Validation** accepts or rejects; **sanitization** changes the input (normalize, strip control characters). Validate first; sanitize only when you must accept messy input.

## Steps

1. Run the demo and read the anchoring table.
2. Write a validator for an Indian mobile number (10 digits starting 6-9) with tests for good and bad values.
3. Run `v.time_regex(r"^(a+)+$", 24)` in a Python shell (it can take seconds). Then add `max_len=20` in front: the problem disappears.
4. Why does the sanitizer apply NFKC before stripping? (Full-width `Ａ` becomes `A`, so later checks see the canonical form.)

## Run

```text
.venv/Scripts/python appsec-course/12-input-validation-and-injection/labs/regex-validation/demo.py
.venv/Scripts/python -m pytest appsec-course/12-input-validation-and-injection/labs/regex-validation -q -p no:cacheprovider
```

## Expected output (real run)

ReDoS timings vary per machine.

```text
== Anchoring mistakes ==
'alice_01'                   re.match=True  ^...$=True  fullmatch=True
'alice; DROP TABLE users'    re.match=True  ^...$=False fullmatch=False
'alice\n'                    re.match=True  ^...$=True  fullmatch=False

== Allowlist vs denylist ==
'Nice post!'                     denylist says safe=True  allowlist accepts=True
'<script>x</script>'             denylist says safe=False allowlist accepts=False
'<ScRiPt>x</ScRiPt>'             denylist says safe=True  allowlist accepts=False
'<img src=x onerror=alert(1)>'   denylist says safe=True  allowlist accepts=False

== Other validators ==
PIN 560001: True | PIN 056001: False
date 2026-11-19: True | date 2026-13-01: False

== ReDoS ==
^(a+)+$      nested-quantifier warning: True
^(\w*)*@     nested-quantifier warning: True
^a+$         nested-quantifier warning: False
  ^(a+)+$ on 'a'*16+'!': 0.002s   ^a+$: 0.000063s
  ^(a+)+$ on 'a'*18+'!': 0.012s   ^a+$: 0.000014s
  ^(a+)+$ on 'a'*20+'!': 0.061s   ^a+$: 0.000013s
  (each +2 characters roughly x4 time; timings vary per machine)

== Client-side check is not a control ==
browser JS accepts it? False -> attacker sends it with curl anyway:
  server without validation: (201, 'created "x\' OR 1=1 --"')
  server with validation   : (422, 'invalid username')

== Sanitization ==
'Alice Smith'
```

## Run the real tool (hedged)

- **Semgrep** has rules for ReDoS-prone regexes and missing anchors; tools such as `recheck` analyse a regex for catastrophic backtracking (verify availability).
- Validate API bodies against your **OpenAPI** schema at the gateway or framework (`pattern`, `maxLength`, `enum`, `additionalProperties: false`).

## What you learned

- Allowlist with fullmatch and a length cap; never trust the browser's validation.
- Regexes are code: review them for anchoring and catastrophic backtracking.
