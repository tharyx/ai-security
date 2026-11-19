# Lab: A secure code review checklist as code

**Course topics:** Reviewing the code for security defences (input validation, output encoding, defending authentication, defending authorization, security misconfigurations); Introduction to tools of the trade. Lessons: [01 Secure code review basics](../../01-secure-code-review-basics.md), [02 Reviewing code for security defences](../../02-reviewing-code-for-security-defences.md).

**Time:** 60 minutes. **Tests:** 12, all offline. **Safety:** fixture files are only parsed, never imported or run; the secret in the vulnerable settings is labelled FAKE.

## Goal

See how a review checklist becomes automated rules, what such rules catch, and what a human still has to judge.

## Concept

[reviewer.py](reviewer.py) scans `.py`, `.html` and `.js` files under a folder with two techniques:

- **Line regexes** (like grep or simple Semgrep patterns): `|safe`, `innerHTML`, `hashlib.md5`, `== token`, `DEBUG = True`, `verify=False`, `re.match` without an end anchor, hard-coded secrets.
- **Python AST checks** (structure-aware): string-built SQL reaching `execute()` directly or through a variable (`SQL001`), HTML f-strings with unescaped values (`XSS001`), `@app.route` handlers without an auth decorator (`AUTHZ001`), `SELECT ... WHERE id = ?` without an owner column (`AUTHZ002`).

Each finding has a checklist area, severity and an ASVS 5.0 chapter reference (verify at source). `checklist()` turns findings into PASS/FAIL per area; `gate()` returns 1 if any high-severity finding exists.

Fixtures: [fixtures/vulnerable](fixtures/vulnerable) (a Flask-style app, settings and a template with planted bugs) and [fixtures/fixed](fixtures/fixed) (the reviewed version).

## Run

```text
.venv/Scripts/python appsec-course/02-secure-code-review-and-asvs/labs/code-review-checklist/demo.py
.venv/Scripts/python appsec-course/02-secure-code-review-and-asvs/labs/code-review-checklist/reviewer.py path/to/your/code
.venv/Scripts/python -m pytest appsec-course/02-secure-code-review-and-asvs/labs/code-review-checklist -q -p no:cacheprovider
```

## Expected output (real run)

```text
# Secure code review: fixtures/vulnerable

| Checklist area | Result |
|---|---|
| Injection (SQL) | FAIL |
| Input validation | FAIL |
| Output encoding | FAIL |
| Authentication | FAIL |
| Authorization | FAIL |
| Security misconfiguration | FAIL |

| Rule | Sev | Location | Finding | ASVS 5.0 chapter (verify) |
|---|---|---|---|---|
| SQL001 | high | app.py:23 | SQL built from strings reaches execute(); use bind parameters (in search()) | V1 Encoding and Sanitization |
| XSS001 | high | app.py:24 | HTML built with untrusted values and no escape() (in search()) | V1 Encoding and Sanitization |
| AUTH001 | high | app.py:30 | fast unsalted hash (MD5/SHA-1) used; use Argon2id, scrypt, bcrypt or PBKDF2 | V6 Authentication / V11 Cryptography |
| SQL001 | high | app.py:31 | SQL built from strings reaches execute(); use bind parameters (in login()) | V1 Encoding and Sanitization |
| AUTH002 | medium | app.py:32 | secret compared with ==; use hmac.compare_digest() | V6 Authentication / V11 Cryptography |
| AUTHZ001 | high | app.py:39 | route has no authentication/authorization decorator (/invoice/<int:invoice_id> in invoice()) | V8 Authorization |
| AUTHZ002 | high | app.py:40 | object fetched by id without an owner filter (possible IDOR/BOLA) | V8 Authorization |
| AUTHZ001 | high | app.py:45 | route has no authentication/authorization decorator (/admin/users in admin_users()) | V8 Authorization |
| AUTHZ001 | high | app.py:50 | route has no authentication/authorization decorator (/account/password in change_password()) | V8 Authorization |
| AUTH002 | medium | app.py:51 | secret compared with ==; use hmac.compare_digest() | V6 Authentication / V11 Cryptography |
| AUTHZ001 | high | app.py:57 | route has no authentication/authorization decorator (/profile in profile()) | V8 Authorization |
| VAL001 | medium | app.py:59 | re.match() without an end anchor accepts trailing junk; use re.fullmatch() | V2 Validation and Business Logic |
| CONF004 | high | app.py:61 | TLS certificate verification disabled (verify=False) | V12 Secure Communication |
| XSS001 | high | app.py:62 | HTML built with untrusted values and no escape() (in profile()) | V1 Encoding and Sanitization |
| CONF001 | high | app.py:66 | debug mode enabled | V13 Configuration |
| CONF001 | high | settings.py:2 | debug mode enabled | V13 Configuration |
| CONF002 | medium | settings.py:3 | wildcard host or CORS origin | V13 Configuration / V4 API and Web Service |
| AUTH003 | high | settings.py:4 | hard-coded secret; load it from a secrets manager or the environment | V13 Configuration |
| CONF003 | medium | settings.py:5 | session cookie without Secure or HttpOnly | V7 Session Management / V3 Web Frontend Security |
| CONF003 | medium | settings.py:6 | session cookie without Secure or HttpOnly | V7 Session Management / V3 Web Frontend Security |
| CONF002 | medium | settings.py:7 | wildcard host or CORS origin | V13 Configuration / V4 API and Web Service |
| XSS002 | high | templates/profile.html:3 | auto-escaping switched off or a dangerous DOM sink | V3 Web Frontend Security |
| XSS002 | high | templates/profile.html:5 | auto-escaping switched off or a dangerous DOM sink | V3 Web Frontend Security |

findings: 23, gate exit code: 1

# Secure code review: fixtures/fixed

| Checklist area | Result |
|---|---|
| Injection (SQL) | PASS |
| Input validation | PASS |
| Output encoding | PASS |
| Authentication | PASS |
| Authorization | PASS |
| Security misconfiguration | PASS |

| Rule | Sev | Location | Finding | ASVS 5.0 chapter (verify) |
|---|---|---|---|---|

findings: 0, gate exit code: 0
```

## Steps

1. Read [fixtures/vulnerable/app.py](fixtures/vulnerable/app.py) **before** running the demo. Write your own list of findings. Compare with the report: what did you find that the tool did not, and the other way round?
2. Compare each finding with the matching lines in [fixtures/fixed/app.py](fixtures/fixed/app.py).
3. **False negative:** in the vulnerable app, change `db.execute(sql)` to `db.execute(build_sql(q))` where `build_sql` returns an f-string. Does `SQL001` still fire? (No: the check does not follow function calls. Real dataflow tools such as CodeQL do.)
4. **False positive:** add `FORGOT_PASSWORD = "/account/forgot-password"` (a route constant) to the fixed settings. `AUTH003` fires on a harmless path. How would you tune the rule?
5. **Missing-control limit:** delete the `AND user_id = ?` from the fixed invoice query. `AUTHZ002` catches this one because the SQL is visible; an ORM call such as `Invoice.get(id)` would not be caught. That is why authorization is reviewed by people and tested with two users.
6. Point `reviewer.py` at one of your own small Python projects and triage the results.

## Run the real tools (hedged)

- **Semgrep / Opengrep, CodeQL, Bandit:** commands and a Semgrep version of `SQL001` in [real-tools/code-review-tools.md](../../real-tools/code-review-tools.md).
- Compare: `bandit -r fixtures/vulnerable` should report MD5, `verify=False`, `debug=True` and the hard-coded key (verify output format).

## What you learned

- A review checklist (validation, encoding, authentication, authorization, configuration) maps naturally to rules and ASVS chapters.
- Regex rules are fast but noisy; AST rules understand structure; neither understands intent.
- Tools are good at **dangerous patterns** and weak at **missing controls**, so a human still reviews authorization and business logic.
