# Chapter 12: Input Validation and Injection

Every API input is attacker-controlled. This chapter covers how to validate and sanitize it, the injection family that follows when you do not (XSS, SQL, ORM, NoSQL, SSRF, deserialization, mass assignment), fuzzing and brute forcing, output encoding, CSP and Trusted Types, post-exploitation through reverse shells (detection only), and GraphQL attacks. Ten offline labs let you attack toy code and prove each fix.

> **Safety.** Every lab is a simulation: in-memory sqlite, a FAKE network dict for SSRF, a pickle payload that only calls a harmless canary function, structured telemetry fixtures for reverse-shell **detection** (no shell code anywhere), and in-process APIs. Secrets are random values labelled FAKE. Only test systems you own or have written permission to test.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Tool status and version numbers are hedged: **verify at the source**.

## Syllabus coverage

| Syllabus item | Where to study | Lab |
|---|---|---|
| [CASP 5] Introduction to Input Validation | [01 section 1](01-input-validation-and-sanitization.md#1-introduction-to-input-validation) (SVG) | [regex-validation](labs/regex-validation/README.md) |
| [CASP 5] Input Validation | [01 section 2](01-input-validation-and-sanitization.md#2-input-validation-vs-input-sanitization) | [regex-validation](labs/regex-validation/README.md) |
| [CASP 5] Input Sanitization | [01 section 2](01-input-validation-and-sanitization.md#2-input-validation-vs-input-sanitization) | [regex-validation](labs/regex-validation/README.md) (`sanitize_display_name`) |
| [CASP 5] Injection Vulnerabilities | [02 section 1](02-injection-vulnerabilities.md#1-injection-vulnerabilities) | [injection-playground](labs/injection-playground/README.md) |
| [CASP 5] Cross-Site Scripting (XSS) | [02 section 2](02-injection-vulnerabilities.md#2-cross-site-scripting-xss), [04](04-output-encoding-csp-and-trusted-types.md) | [output-encoding-csp-trusted-types](labs/output-encoding-csp-trusted-types/README.md) |
| [CASP 5] SQL Injection | [02 section 3](02-injection-vulnerabilities.md#3-sql-injection) | [injection-playground](labs/injection-playground/README.md), [mini-sqlmap](labs/mini-sqlmap/README.md) |
| [CASP 5] ORM Injection | [02 section 4](02-injection-vulnerabilities.md#4-orm-injection) | [injection-playground](labs/injection-playground/README.md) (order_by oracle) |
| [CASP 5] NoSQL Injection | [02 section 5](02-injection-vulnerabilities.md#5-nosql-injection) | [injection-playground](labs/injection-playground/README.md) (`$ne`, `$regex`) |
| [CASP 5] Server Side Request Forgery | [02 section 6](02-injection-vulnerabilities.md#6-server-side-request-forgery) | [injection-playground](labs/injection-playground/README.md) (FAKE metadata canary) |
| [CASP 5] Deserialization Issues | [02 section 7](02-injection-vulnerabilities.md#7-deserialization-issues) | [insecure-deserialization](labs/insecure-deserialization/README.md) |
| [CASP 5] Mass Assignment Issues | [02 section 8](02-injection-vulnerabilities.md#8-mass-assignment-issues) | [mass-assignment](labs/mass-assignment/README.md) |
| [CASP 5] Fuzzing | [03 section 1](03-fuzzing-and-brute-forcing.md#1-fuzzing-101) | [mini-fuzzer](labs/mini-fuzzer/README.md) |
| [CASP 5] Fuzzing 101 | [03 section 1](03-fuzzing-and-brute-forcing.md#1-fuzzing-101); repo [cmcpse ch5 fuzzing](../../cmcpse-course/ch5-devsecops-for-mcp-security/03-dast-fuzzing-and-runtime-testing.md) | [mini-fuzzer](labs/mini-fuzzer/README.md) |
| [CASP 5] Fuzzing vs Brute Forcing | [03 section 2](03-fuzzing-and-brute-forcing.md#2-fuzzing-vs-brute-forcing) | [mini-fuzzer](labs/mini-fuzzer/README.md) (both modes) |
| [CASP 5] Fuzzing APIs Using Open Source and Commercial Tools | [03 section 4](03-fuzzing-and-brute-forcing.md#4-fuzzing-apis-using-open-source-and-commercial-tools); [real-tools/fuzzing-tools.md](real-tools/fuzzing-tools.md) | [mini-fuzzer](labs/mini-fuzzer/README.md) |
| [CASP 5] Burp Suite Intruder | [03 section 4.1](03-fuzzing-and-brute-forcing.md#41-burp-suite-intruder); [real-tools](real-tools/fuzzing-tools.md#burp-suite-intruder) | [free-coupons](labs/free-coupons/README.md) (Intruder-style numbers payload) |
| [CASP 5] OWASP ZAP Fuzzer | [03 section 4.2](03-fuzzing-and-brute-forcing.md#42-owasp-zap-fuzzer); [real-tools](real-tools/fuzzing-tools.md#zap-fuzzer-zap-by-checkmarx) | [mini-fuzzer](labs/mini-fuzzer/README.md) |
| [CASP 5] Wfuzz | [03 section 4.3](03-fuzzing-and-brute-forcing.md#43-wfuzz); [real-tools](real-tools/fuzzing-tools.md#wfuzz) | [mini-fuzzer](labs/mini-fuzzer/README.md) (`FUZZ` keyword) |
| [CASP 5] FFUF | [03 section 4.4](03-fuzzing-and-brute-forcing.md#44-ffuf); [real-tools](real-tools/fuzzing-tools.md#ffuf) | [mini-fuzzer](labs/mini-fuzzer/README.md) (`-fc 404` style filters) |
| [CASP 5] Injection Defenses | [01 section 8](01-input-validation-and-sanitization.md#8-injection-defenses-summary) | all labs (secure versions) |
| [CASP 5] Implementing Input Validation | [01 section 3](01-input-validation-and-sanitization.md#3-implementing-input-validation) | [regex-validation](labs/regex-validation/README.md), [mini-fuzzer](labs/mini-fuzzer/README.md) (secure target) |
| [CASP 5] Client-Side vs. Server-Side Validation | [01 section 4](01-input-validation-and-sanitization.md#4-client-side-vs-server-side-validation) | [regex-validation](labs/regex-validation/README.md) |
| [CASP 5] Whitelisting & Blacklisting | [01 section 5](01-input-validation-and-sanitization.md#5-whitelisting-and-blacklisting-allowlists-and-denylists) | [regex-validation](labs/regex-validation/README.md) |
| [CASP 5] Implementing Input Sanitization | [01 section 7](01-input-validation-and-sanitization.md#7-implementing-input-sanitization) | [regex-validation](labs/regex-validation/README.md) |
| [CASP 5] Validating With Regular Expressions | [01 section 6](01-input-validation-and-sanitization.md#6-validating-with-regular-expressions) | [regex-validation](labs/regex-validation/README.md) (incl. ReDoS) |
| [CASP 5] Output Encoding | [04 section 1](04-output-encoding-csp-and-trusted-types.md#1-output-encoding) (SVG) | [output-encoding-csp-trusted-types](labs/output-encoding-csp-trusted-types/README.md) |
| [CASP 5] HTML Encoding | [04 section 1.1](04-output-encoding-csp-and-trusted-types.md#11-html-encoding) | [output-encoding-csp-trusted-types](labs/output-encoding-csp-trusted-types/README.md) |
| [CASP 5] HTML Attribute Encoding | [04 section 1.2](04-output-encoding-csp-and-trusted-types.md#12-html-attribute-encoding) | [output-encoding-csp-trusted-types](labs/output-encoding-csp-trusted-types/README.md) |
| [CASP 5] Javascript Encoding | [04 section 1.3](04-output-encoding-csp-and-trusted-types.md#13-javascript-encoding) | [output-encoding-csp-trusted-types](labs/output-encoding-csp-trusted-types/README.md) (incl. nested onclick) |
| [CASP 5] CSS Encoding | [04 section 1.4](04-output-encoding-csp-and-trusted-types.md#14-css-encoding) | [output-encoding-csp-trusted-types](labs/output-encoding-csp-trusted-types/README.md) |
| [CASP 5] Prepared Statements | [02 section 9](02-injection-vulnerabilities.md#9-prepared-statements) | [injection-playground](labs/injection-playground/README.md), [mini-sqlmap](labs/mini-sqlmap/README.md) |
| [CASP 5] Content Security Policy | [04 section 2](04-output-encoding-csp-and-trusted-types.md#2-content-security-policy); headers in [chapter 14](../14-api-defenses-data-security-and-headers/README.md) | [output-encoding-csp-trusted-types](labs/output-encoding-csp-trusted-types/README.md) (CSP evaluator) |
| [CASP 5] Trusted Types | [04 section 3](04-output-encoding-csp-and-trusted-types.md#3-trusted-types) | [output-encoding-csp-trusted-types](labs/output-encoding-csp-trusted-types/README.md) |
| [CASP 5] Getting Free Coupons Without Knowing Coupon Code | [03 section 3](03-fuzzing-and-brute-forcing.md#3-business-logic-brute-force-the-free-coupon-case) | [free-coupons](labs/free-coupons/README.md) |
| [CASP 5] Exploiting Mass Assignment Vulnerabilities | [02 section 8](02-injection-vulnerabilities.md#8-mass-assignment-issues) | [mass-assignment](labs/mass-assignment/README.md) |
| [CASP 5] Insecure Deserialization To Remote Code Execution | [02 section 7](02-injection-vulnerabilities.md#7-deserialization-issues) | [insecure-deserialization](labs/insecure-deserialization/README.md) (pickle canary) |
| [CASP 5] Preventing Insecure Deserialization In Java | [02 section 7, Java](02-injection-vulnerabilities.md#preventing-insecure-deserialization-in-java) (`ObjectInputFilter`, JEP 290/415) | [insecure-deserialization](labs/insecure-deserialization/README.md) (same allowlist idea in Python) |
| [CASP 5] Post Exploitation In APIs Through Reverse Shells | [05 section 1](05-post-exploitation-and-graphql.md#1-post-exploitation-in-apis-through-reverse-shells) (concept, detection, prevention) | [reverse-shell-detector](labs/reverse-shell-detector/README.md) |
| [CASP 5] Automated SQL Injection Using SQLMAP | [02 section 10](02-injection-vulnerabilities.md#10-automated-sql-injection-with-sqlmap); [real-tools/sqlmap.md](real-tools/sqlmap.md) | [mini-sqlmap](labs/mini-sqlmap/README.md) |
| [CASP 5] Learning To Validate Input With Regular Expressions | [01 section 6](01-input-validation-and-sanitization.md#6-validating-with-regular-expressions) | [regex-validation](labs/regex-validation/README.md) |
| [CASP 5] Preventing DOM XSS With Trusted Types | [04 section 3](04-output-encoding-csp-and-trusted-types.md#3-trusted-types) | [output-encoding-csp-trusted-types](labs/output-encoding-csp-trusted-types/README.md) |
| [CASP 5] Attacking GraphQL APIs | [05 section 2](05-post-exploitation-and-graphql.md#2-attacking-graphql-apis) | [graphql-attacks](labs/graphql-attacks/README.md) |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| "Whitelisting & Blacklisting" | Current terms are **allowlist** and **denylist**. Allowlists remain the recommended approach. |
| "OWASP ZAP Fuzzer" | ZAP is now **"ZAP by Checkmarx"** (2024). The Fuzzer add-on and the Automation Framework still exist. |
| **Wfuzz** | Little maintenance in recent years; **ffuf** is the actively maintained equivalent. |
| Injection as an OWASP API Top 10 item | **API8:2019 Injection** was dropped from the 2023 API list (still covered by **A05:2025 Injection** in the web Top 10, A03 in 2021). |
| Trusted Types as Chrome-only | Long supported in Chromium; recent Safari and Firefox releases have added support (check caniuse). |
| Java deserialization filters | **JEP 290** `ObjectInputFilter` (Java 9, backported to 8u121) plus **JEP 415** context-specific filter factory (Java 17). |
| `X-XSS-Protection` as an XSS defence | **Deprecated**; browsers removed the XSS Auditor. Use output encoding, CSP and Trusted Types ([chapter 14](../14-api-defenses-data-security-and-headers/README.md)). |

## How the three courses overlap here

- **CASP 5** owns this chapter. The Security Champion course covers SQLi, XSS, SSRF and command injection as **web basics** in [chapter 01](../01-security-champions-and-appsec-basics/README.md) and as **code review** (input validation, output encoding, parameterized queries) in [chapter 02](../02-secure-code-review-and-asvs/README.md). This chapter is the deeper, API-focused version, so those chapters link here rather than repeating it.
- **CASP 6** repeats "Attacking GraphQL APIs"; its extra lab (suggestions and persisted queries) is in [chapter 13](../13-owasp-api-top-10-and-other-threats/README.md).
- **CASP 7** returns to CSP (at scale, misconfigurations) in [chapter 14](../14-api-defenses-data-security-and-headers/README.md).

## Learning order

1. [Lesson 01](01-input-validation-and-sanitization.md), then the [regex-validation lab](labs/regex-validation/README.md). About 2 hours.
2. [Lesson 02](02-injection-vulnerabilities.md), then [injection-playground](labs/injection-playground/README.md), [mass-assignment](labs/mass-assignment/README.md), [insecure-deserialization](labs/insecure-deserialization/README.md) and [mini-sqlmap](labs/mini-sqlmap/README.md). About 4.5 hours.
3. [Lesson 03](03-fuzzing-and-brute-forcing.md), then [mini-fuzzer](labs/mini-fuzzer/README.md) and [free-coupons](labs/free-coupons/README.md). About 2.5 hours.
4. [Lesson 04](04-output-encoding-csp-and-trusted-types.md), then the [output-encoding-csp-trusted-types lab](labs/output-encoding-csp-trusted-types/README.md). About 2 hours.
5. [Lesson 05](05-post-exploitation-and-graphql.md), then [reverse-shell-detector](labs/reverse-shell-detector/README.md) and [graphql-attacks](labs/graphql-attacks/README.md). About 2.5 hours.
6. Optional: [real-tools/fuzzing-tools.md](real-tools/fuzzing-tools.md) and [real-tools/sqlmap.md](real-tools/sqlmap.md) in your course lab. About 2 hours.

## Lab index

All labs run offline: `.venv/Scripts/python -m pytest appsec-course/12-input-validation-and-injection -q -p no:cacheprovider`.

| Lab | Course exercise | Tests |
|---|---|---|
| [injection-playground](labs/injection-playground/README.md) | SQL, ORM, NoSQL injection and SSRF | 9 |
| [mass-assignment](labs/mass-assignment/README.md) | Exploiting Mass Assignment Vulnerabilities | 5 |
| [insecure-deserialization](labs/insecure-deserialization/README.md) | Insecure Deserialization To RCE; Preventing It In Java | 6 |
| [free-coupons](labs/free-coupons/README.md) | Getting Free Coupons Without Knowing Coupon Code | 6 |
| [mini-fuzzer](labs/mini-fuzzer/README.md) | Fuzzing 101, fuzzing vs brute forcing, ffuf/wfuzz style | 6 |
| [mini-sqlmap](labs/mini-sqlmap/README.md) | Automated SQL Injection Using SQLMAP | 6 |
| [regex-validation](labs/regex-validation/README.md) | Learning To Validate Input With Regular Expressions | 8 |
| [output-encoding-csp-trusted-types](labs/output-encoding-csp-trusted-types/README.md) | Preventing DOM XSS With Trusted Types; output encoding; CSP | 10 |
| [reverse-shell-detector](labs/reverse-shell-detector/README.md) | Post Exploitation In APIs Through Reverse Shells (detection) | 8 |
| [graphql-attacks](labs/graphql-attacks/README.md) | Attacking GraphQL APIs | 8 |

Hedged guides for real tools: [fuzzing tools](real-tools/fuzzing-tools.md) (Burp Intruder, ZAP Fuzzer, wfuzz, ffuf), [sqlmap](real-tools/sqlmap.md).

## Exam tips

- **Validation rejects, sanitization changes, encoding is per output context, parameterization separates code from data.** Know which stops what.
- **Server-side validation is mandatory;** client-side is UX.
- **Allowlist + `fullmatch` + length cap.** Mention `$` and newline, and ReDoS with nested quantifiers.
- **Prepared statements cannot bind identifiers;** allowlist `ORDER BY` columns (ORM injection).
- **NoSQL injection = operator injection** (`$ne`, `$gt`, `$regex`): enforce types.
- **SSRF: resolve, check the IP, connect to that IP, no redirects;** IMDSv2 and egress controls.
- **Deserialization: data-only formats;** Java `ObjectInputFilter` allowlist (JEP 290/415).
- **Fuzzing finds bugs; brute forcing finds secrets.** The oracle defines a fuzzer.
- **Strict CSP = nonces/hashes + `'strict-dynamic'` + `object-src 'none'` + `base-uri 'none'`.**
- **Trusted Types make DOM sinks reject strings;** only policies create trusted values.
- **Reverse shells connect outbound:** detect lineage + socket + egress; prevent with egress deny and shell-less images.
- **GraphQL: authorize per resolver, limit depth/cost/aliases, disable introspection in production.**

## Interview / exam questions

<details>
<summary>1. What is the difference between input validation and input sanitization?</summary>

Validation checks input against rules and accepts or rejects it (type, length, format, range, allowlist). Sanitization modifies input to make it safe (normalizing Unicode, stripping control characters or disallowed HTML). Prefer validation; sanitize only when you must accept rich input, and use maintained libraries.
</details>

<details>
<summary>2. Why is client-side validation not a security control?</summary>

The attacker controls the client. They can call the API directly with curl, a script or an intercepting proxy, skipping any browser or app checks. Only server-side validation is enforced.
</details>

<details>
<summary>3. Why are allowlists preferred over denylists?</summary>

Allowlists define the small set of valid input, so unknown attacks are rejected by default. Denylists try to list bad input and are bypassed by case changes, encodings, alternative syntax and new techniques.
</details>

<details>
<summary>4. Name two regex mistakes that lead to bypasses and one that leads to denial of service.</summary>

Bypass: missing end anchor (re.match only anchors the start) and `$` matching before a trailing newline. DoS: nested quantifiers like `(a+)+` cause catastrophic backtracking (ReDoS). Fix with fullmatch or `\A...\Z`, length caps and simple patterns or a linear-time engine.
</details>

<details>
<summary>5. How do prepared statements prevent SQL injection, and what can they not protect?</summary>

The SQL text and values are sent separately; the database parses the statement with placeholders and binds values as data, so values cannot change the query structure. They cannot bind identifiers such as table or column names or ORDER BY direction, which must be allowlisted.
</details>

<details>
<summary>6. What is ORM injection?</summary>

Injection through an ORM's raw escape hatches (raw SQL, extra(), text(), string-built HQL/JPQL) or through identifiers like order_by that the ORM pastes into SQL. Fix by staying in the parameterized API and allowlisting identifiers.
</details>

<details>
<summary>7. Explain NoSQL operator injection with an example.</summary>

A login builds `{"username": u, "password": p}` from JSON. The attacker sends `"password": {"$ne": ""}`, so the query matches any non-empty password and logs in. Fix: require strings, reject keys starting with `$`, validate against a schema.
</details>

<details>
<summary>8. How do you defend an API feature that fetches user-supplied URLs (SSRF)?</summary>

Allowlist schemes, hosts and ports; resolve the host and block private, loopback, link-local and reserved IPs; connect to the checked IP to avoid DNS rebinding; do not follow redirects; restrict egress from the fetcher; use IMDSv2 or block metadata; return generic errors.
</details>

<details>
<summary>9. Why does insecure deserialization lead to RCE, and how is it prevented in Java?</summary>

Native formats encode which classes to instantiate and call, so attacker bytes can trigger gadget chains in existing libraries. Prevent by not deserializing untrusted native objects (use JSON/protobuf with DTOs), or by allowlisting classes and limits with ObjectInputFilter (JEP 290, JVM-wide factories in JEP 415), plus patching and least privilege.
</details>

<details>
<summary>10. What is mass assignment and how do you fix it?</summary>

The framework binds request fields onto internal models, letting clients set fields like is_admin, role or balance. Fix with per-operation input DTOs that allowlist fields, reject unknown fields, keep server-owned fields out of client control, and use output schemas.
</details>

<details>
<summary>11. Fuzzing vs brute forcing?</summary>

Fuzzing sends malformed or unexpected input to find bugs, judged by an oracle (5xx, stack traces, reflection, broken business rules). Brute forcing tries many valid-looking candidates to find a secret or hidden resource, judged by a different response. Tools like ffuf, wfuzz, Intruder and ZAP Fuzzer do both.
</details>

<details>
<summary>12. Why does output encoding depend on context? Give two contexts.</summary>

Each parser treats different characters as special. HTML body needs entity encoding of `< > & " '`; a JavaScript string needs `\xHH` escapes; attributes need quoting and `&#xHH;`; CSS needs `\HH `. HTML encoding inside an event handler fails because the browser HTML-decodes before running the JavaScript.
</details>

<details>
<summary>13. What makes a CSP strict, and which keywords weaken it?</summary>

Strict: per-response nonces or hashes with 'strict-dynamic', object-src 'none', base-uri 'none', ideally require-trusted-types-for 'script', rolled out in report-only first. Weak: 'unsafe-inline' without nonce/hash, 'unsafe-eval', wildcards or scheme sources (https:, data:) in script-src, and broad CDN allowlists that host JSONP or AngularJS gadgets.
</details>

<details>
<summary>14. How do Trusted Types prevent DOM XSS?</summary>

With require-trusted-types-for 'script', dangerous DOM sinks (innerHTML, eval, script.src) throw on plain strings. Only objects created by named policies are accepted, so all HTML/script creation goes through a few reviewed policies (often using a sanitizer). Prefer textContent where possible.
</details>

<details>
<summary>15. How would you detect and prevent reverse shells from a compromised API server?</summary>

Detect: API runtime spawning a shell or interpreter (process lineage), shells with sockets as stdin/stdout, outbound connections from shells to unknown IPs, command-line indicators, unusual DNS/beaconing; correlate in the SIEM. Prevent: default-deny egress, no shell or network tools in images, non-root, seccomp/AppArmor, read-only filesystems, and fix the RCE root cause.
</details>

## References

- OWASP Input Validation, SQL Injection Prevention, Query Parameterization, Deserialization, SSRF Prevention, Mass Assignment, XSS Prevention, DOM-based XSS Prevention, Content Security Policy and GraphQL cheat sheets.
- OWASP Top 10:2021/2025 (Injection); OWASP API Security Top 10 2019 (API8) and 2023 (API3, API7).
- JEP 290 and JEP 415 (Java serialization filtering); Python `pickle` documentation warning.
- W3C Content Security Policy Level 3; W3C Trusted Types; web.dev "Mitigate XSS with a strict CSP".
- sqlmap, ffuf, wfuzz, ZAP, Burp Suite, Falco and Sigma project documentation.
- Repo: [cmcpse ch5 fuzzing](../../cmcpse-course/ch5-devsecops-for-mcp-security/03-dast-fuzzing-and-runtime-testing.md), [devsecops-course SAST](../../devsecops-course/05-static-analysis-and-secrets/README.md), [devsecops-course DAST](../../devsecops-course/06-dynamic-analysis/README.md), [SIEM](../../cybersecurity-track/06-siem-sentinel-splunk/README.md).

**Next chapter:** [Chapter 13: OWASP API Top 10 and Other API Threats](../13-owasp-api-top-10-and-other-threats/README.md)
