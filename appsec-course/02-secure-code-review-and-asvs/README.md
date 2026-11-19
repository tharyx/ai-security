# Chapter 02: Secure Code Review and OWASP ASVS

This chapter teaches a champion's most frequent hands-on task: reviewing code for security. You learn what secure code review is, a risk-first way to approach it, the tools that support it, and how to check the five defence areas (input validation, output encoding, authentication, authorization, configuration). Then you use OWASP ASVS 5.0 to turn "secure" into a tailored, testable checklist. Five offline labs build a checklist-driven reviewer, fix regex validation, SQL injection and XSS, and generate an ASVS checklist with a CI gate.

> **Safety.** Every lab is a simulation: fixture code that is only parsed, pure functions, in-memory sqlite, and HTML parsed by Python (no browser). Only test systems you own or have written permission to test.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Tool status and version numbers are hedged: **verify at the source**.

## Syllabus coverage

| Syllabus item | Where to study | Lab |
|---|---|---|
| [CSC 2] What is Secure Code Review? | [Lesson 01 section 1](01-secure-code-review-basics.md#1-what-is-secure-code-review) | [code-review-checklist](labs/code-review-checklist/README.md) |
| [CSC 2] How to approach Secure code review? | [01 section 2](01-secure-code-review-basics.md#2-how-to-approach-secure-code-review) (SVG) | [code-review-checklist](labs/code-review-checklist/README.md) |
| [CSC 2] Introduction to tools of the trade | [01 section 3](01-secure-code-review-basics.md#3-introduction-to-tools-of-the-trade); [real-tools/code-review-tools.md](real-tools/code-review-tools.md); [DevSecOps ch05](../../devsecops-course/05-static-analysis-and-secrets/README.md) | [code-review-checklist](labs/code-review-checklist/README.md) (regex + AST rules) |
| [CSC 2] Reviewing the code for security defences | [Lesson 02 section 1](02-reviewing-code-for-security-defences.md#1-reviewing-the-code-for-security-defences) | [code-review-checklist](labs/code-review-checklist/README.md) |
| [CSC 2] Input validation | [02 section 2](02-reviewing-code-for-security-defences.md#2-input-validation) | [input-validation-regex](labs/input-validation-regex/README.md); reviewer rule `VAL001` |
| [CSC 2] Output encoding | [02 section 3](02-reviewing-code-for-security-defences.md#3-output-encoding) | [xss-review-and-fix](labs/xss-review-and-fix/README.md); reviewer rules `XSS001`, `XSS002` |
| [CSC 2] Defending Authentication | [02 section 4](02-reviewing-code-for-security-defences.md#4-defending-authentication) | [code-review-checklist](labs/code-review-checklist/README.md) (`AUTH001` to `AUTH003`) |
| [CSC 2] Defending Authorization | [02 section 5](02-reviewing-code-for-security-defences.md#5-defending-authorization) | [code-review-checklist](labs/code-review-checklist/README.md) (`AUTHZ001`, `AUTHZ002`) |
| [CSC 2] Security Misconfigurations | [02 section 6](02-reviewing-code-for-security-defences.md#6-security-misconfigurations) | [code-review-checklist](labs/code-review-checklist/README.md) (`CONF001` to `CONF004`) |
| [CSC 2] OWASP ASVS Framework | [Lesson 03 section 1](03-owasp-asvs.md#1-owasp-asvs-framework) | [asvs-checklist-generator](labs/asvs-checklist-generator/README.md) |
| [CSC 2] Understanding OWASP ASVS | [03 section 2](03-owasp-asvs.md#2-understanding-owasp-asvs) | [asvs-checklist-generator](labs/asvs-checklist-generator/README.md) |
| [CSC 2] Using ASVS to Secure Applications & APIs | [03 section 3](03-owasp-asvs.md#3-using-asvs-to-secure-applications-and-apis) | [asvs-checklist-generator](labs/asvs-checklist-generator/README.md) (web profile and API profile) |
| [CSC 2] Creating Checklists with OWASP ASVS | [03 section 4](03-owasp-asvs.md#4-creating-checklists-with-owasp-asvs) (SVG) | [asvs-checklist-generator](labs/asvs-checklist-generator/README.md) |
| [CSC 2] Input validation using industry best practices and regex | [02 section 2.1](02-reviewing-code-for-security-defences.md#21-input-validation-with-industry-best-practices-and-regex) | [input-validation-regex](labs/input-validation-regex/README.md) |
| [CSC 2] Reviewing code for SQL Injection and Fixing with Parameterized queries | [02 section 7](02-reviewing-code-for-security-defences.md#7-reviewing-for-sql-injection-and-fixing-with-parameterized-queries) | [sqli-review-and-fix](labs/sqli-review-and-fix/README.md) |
| [CSC 2] Reviewing for XSS and Implementing Output encoding to prevent client-side attacks like XSS | [02 section 8](02-reviewing-code-for-security-defences.md#8-reviewing-for-xss-and-implementing-output-encoding) | [xss-review-and-fix](labs/xss-review-and-fix/README.md) |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| **OWASP ASVS** (course material may show 4.0.3) | **ASVS 5.0.0 was released in May 2025.** Chapters were reorganized (for example V1 is now Encoding and Sanitization, new chapters for Self-contained Tokens, OAuth and OIDC, and WebRTC) and requirement ids changed. Keep your own stable ids and map them to ASVS ids in a column; cite ids with the version (`v5.0.0-...`). |
| Semgrep as the free SAST default | Semgrep changed the licence of its community rules and some engine features; the **Opengrep** fork appeared in 2025. Check what you may use. |
| SonarLint | Renamed **SonarQube for IDE** (verify). |
| bleach for HTML sanitizing in Python | bleach is deprecated; consider nh3 (verify current recommendations). |
| Password hashing "with a salt" | Use Argon2id first, then scrypt, bcrypt or PBKDF2-HMAC-SHA256 (about 600,000 iterations) per the OWASP Password Storage Cheat Sheet; NIST SP 800-63B-4 favours length over complexity and no forced rotation. |

## How the three courses overlap here

- **CSC 2** owns this chapter. The API Security course returns to input validation, regex and output encoding in **chapter 12** (deeper: ReDoS, NoSQL and ORM injection, CSP and Trusted Types), and to ASVS for APIs in **chapter 16**, which links back here for the checklist generator instead of rebuilding it.
- The DevSecOps course covers the **tools** (SAST, custom rules, secrets) in depth: [DevSecOps ch05](../../devsecops-course/05-static-analysis-and-secrets/README.md). This chapter focuses on the **reviewer's judgement** and the checklist.
- Threat modeling (chapters 03 to 07) supplies the context a reviewer needs: which flows cross trust boundaries and which data is sensitive.

## Learning order

1. [Lesson 01](01-secure-code-review-basics.md): what review is and how to approach it. About 1 hour.
2. [Lesson 02](02-reviewing-code-for-security-defences.md) sections 1 to 6, then the [code-review-checklist lab](labs/code-review-checklist/README.md). About 2 hours.
3. Lesson 02 section 2.1 and the [input-validation-regex lab](labs/input-validation-regex/README.md). About 1 hour.
4. Lesson 02 section 7 and the [sqli-review-and-fix lab](labs/sqli-review-and-fix/README.md). About 1 hour.
5. Lesson 02 section 8 and the [xss-review-and-fix lab](labs/xss-review-and-fix/README.md). About 1 hour.
6. [Lesson 03](03-owasp-asvs.md) and the [asvs-checklist-generator lab](labs/asvs-checklist-generator/README.md). About 1.5 hours.
7. Hedged real-tool commands: [real-tools/code-review-tools.md](real-tools/code-review-tools.md). Then answer the 15 questions and go to chapter 03.

## Lab index

All labs run offline: `.venv/Scripts/python -m pytest appsec-course/02-secure-code-review-and-asvs -q -p no:cacheprovider`.

| Lab | Course exercise | Tests |
|---|---|---|
| [code-review-checklist](labs/code-review-checklist/README.md) | Reviewing the code for security defences (validation, encoding, authentication, authorization, misconfiguration) | 12 |
| [input-validation-regex](labs/input-validation-regex/README.md) | Input validation using industry best practices and regex | 20 |
| [sqli-review-and-fix](labs/sqli-review-and-fix/README.md) | Reviewing code for SQL Injection and Fixing with Parameterized queries | 9 |
| [xss-review-and-fix](labs/xss-review-and-fix/README.md) | Reviewing for XSS and Implementing Output encoding | 16 |
| [asvs-checklist-generator](labs/asvs-checklist-generator/README.md) | Creating Checklists with OWASP ASVS | 12 |

Hedged guide for real tools: [real-tools/code-review-tools.md](real-tools/code-review-tools.md).

## Exam tips

- **Review approach in one line:** scope by risk, get context, run tools, review hotspots manually (source to sink plus control check), confirm, report with fix and test.
- **Tools find dangerous patterns; people find missing controls** (especially authorization).
- **`re.fullmatch`**, not `re.match` or `search`; `$` allows a trailing newline.
- **Values are bound; identifiers are allowlisted.** You cannot bind an `ORDER BY` column.
- **Output encoding depends on context:** body, attribute (quoted), URL (scheme allowlist), JavaScript (JSON + escape `<`), CSS (validate).
- **ASVS 5.0.0 (May 2025), levels L1 to L3;** L2 is the usual target. Say "verify the version" if asked about ids.
- **A checklist needs evidence and a gate,** or it becomes shelfware.

## Interview / exam questions

<details>
<summary>1. What is secure code review, and how is it different from running SAST?</summary>

A systematic, risk-focused examination of source code to find security weaknesses and confirm that required controls exist and are correct. SAST automates pattern and dataflow checks; review adds human judgement on context, business logic and missing controls, and triages tool output.
</details>

<details>
<summary>2. Describe a practical approach to a secure code review.</summary>

Scope the change and its risk; gather context (threat model, data, framework); run SAST, SCA and secrets tools; review hotspots manually by tracing sources to sinks and checking each endpoint's controls against a checklist; confirm findings with a test or PoC; report location, impact, fix, reference and a regression test.
</details>

<details>
<summary>3. Which areas of a codebase would you review first, and why?</summary>

Authentication, session handling, authorization and data access, input handling at trust boundaries, rendering of user data, external calls (URL fetches, shell), file handling, crypto and configuration. These are where a single mistake has the highest impact.
</details>

<details>
<summary>4. Name four input validation best practices.</summary>

Server-side allowlists; full-string matches with length limits; normalization before validation; conversion to real types with range or semantic checks; rejection of unknown fields; size limits on bodies and files.
</details>

<details>
<summary>5. What is wrong with `re.match(r"^[a-z]+$", s)` as a validator?</summary>

`$` matches before a trailing newline, so `abc\n` passes. Without `^`, `re.match` already anchors only the start. Use `re.fullmatch(r"[a-z]+", s)` (or `\A...\Z`) and add a length limit.
</details>

<details>
<summary>6. What is ReDoS and how do you prevent it?</summary>

Regular expression denial of service: patterns with nested or overlapping quantifiers such as `(a+)+$` backtrack exponentially on crafted input, tying up CPU. Prevent with simpler patterns, input length limits, timeouts, linear-time engines such as RE2, and ReDoS checks in SAST.
</details>

<details>
<summary>7. Why is input validation not enough to stop injection?</summary>

Valid data can still contain dangerous characters (a name like O'Brien, a comment with `<`), validation can be bypassed or missing on one path, and data from other sources (database, partner APIs) may not pass through it. The sink defence (parameterization, encoding) is required.
</details>

<details>
<summary>8. How do you fix SQL injection when the user chooses the sort column?</summary>

Identifiers cannot be bound as parameters. Map the user's choice to a fixed SQL fragment through an allowlist (`{"price": "price", "-price": "price DESC"}`) and reject anything else; in Oracle, DBMS_ASSERT can validate a simple SQL name before concatenation.
</details>

<details>
<summary>9. Give the output encoding rule for HTML body, attribute, URL and JavaScript contexts.</summary>

Body: HTML-encode. Attribute: always quote it and HTML-encode including quotes. URL: allow only http/https schemes, then attribute-encode. JavaScript string: JSON-encode and escape `<`, `>` and `&` so `</script>` cannot close the block, or better, pass data through a data attribute or JSON block.
</details>

<details>
<summary>10. Which template or framework features should a reviewer search for when hunting XSS?</summary>

Anything that disables auto-escaping: `|safe`, `{% autoescape false %}`, `Markup`, `mark_safe`, React `dangerouslySetInnerHTML`, Vue `v-html`, Angular `bypassSecurityTrust*`; and DOM sinks such as `innerHTML`, `outerHTML`, `document.write`, `eval` and string `setTimeout`.
</details>

<details>
<summary>11. What do you check when reviewing authentication code?</summary>

Password hashing algorithm and parameters (Argon2id, scrypt, bcrypt, PBKDF2), constant-time comparison of secrets, brute-force protection, MFA support, session id regeneration at login and server-side logout, cookie flags, safe reset tokens, no hard-coded credentials.
</details>

<details>
<summary>12. Why are authorization bugs hard for tools, and how do reviewers find them?</summary>

The bug is usually a missing check, and tools cannot know the intended rule. Reviewers verify that every route has an explicit rule with deny by default, that every object access filters by the current user or a policy, that client-supplied roles and ids are not trusted, and they test with two users.
</details>

<details>
<summary>13. What is OWASP ASVS and how does it differ from the OWASP Top 10?</summary>

ASVS is a standard of testable security requirements, organised in chapters and three levels, used for requirements, review, testing and procurement. The Top 10 is an awareness list of the biggest risk categories, not a complete or testable standard.
</details>

<details>
<summary>14. Explain ASVS levels and how you choose one.</summary>

L1 is the baseline every app should meet; L2 is for most apps handling sensitive data or transactions (the usual target); L3 is for critical, high-assurance systems. Choose with the product owner from data sensitivity, impact and regulatory needs; each level includes the lower ones.
</details>

<details>
<summary>15. How would you build and maintain an ASVS checklist for an API team?</summary>

Import the current ASVS export, pick a level, filter by the API's features (tokens, OAuth, no cookies or UI), give each item a stable internal id mapped to the ASVS id, attach evidence (tests, scans, review notes), track status, and gate CI on failed or untested L1 items. Keep it in the repo and update the mapping when ASVS changes.
</details>

## References

- OWASP Code Review Guide, OWASP ASVS 5.0.0, OWASP WSTG, OWASP Proactive Controls.
- OWASP Cheat Sheets: Input Validation, Cross Site Scripting Prevention, SQL Injection Prevention, Query Parameterization, Authentication, Authorization, Password Storage, Regular Expression Denial of Service.
- NIST SP 800-63B (current revision; verify), CWE-20, CWE-79, CWE-89, CWE-1333 (ReDoS).
- Repo: [DevSecOps SAST and custom rules](../../devsecops-course/05-static-analysis-and-secrets/README.md), [requirements as code](../../devsecops-course/03-security-requirements-and-threat-modeling/03-security-requirements-as-code.md), [Oracle security controls](../../cybersecurity-track/11-database-security/02-oracle-security-controls.md), [Chapter 01 vulnerable shop](../01-security-champions-and-appsec-basics/labs/vulnerable-shop/README.md).

**Previous chapter:** [Chapter 01: Security Champions and AppSec Basics](../01-security-champions-and-appsec-basics/README.md) · **Next chapter:** [Chapter 03: Risk Management and Threat Modeling Overview](../03-risk-management-and-threat-modeling-overview/README.md)
