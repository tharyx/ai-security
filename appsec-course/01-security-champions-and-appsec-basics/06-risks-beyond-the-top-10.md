# Lesson 06: Risks Beyond the Top 10, and the Hands-On Exercises

**Syllabus items covered:** [CSC 1] Risks beyond the top 10; Cross-Site Scripting (XSS); Insecure Direct Object Reference (IDOR); Unvalidated Requests and Forwards; XML External Entities (XXE); Cross-Site Request Forgery (CSRF); and the concepts behind the hands-on exercises (SQL injection fundamentals, XSS, CSRF, SSRF, command injection, IDOR, security misconfigurations, open redirect).

**Time:** 2 hours. **Labs:** [vulnerable-shop](labs/vulnerable-shop/README.md), [intercepting-proxy](labs/intercepting-proxy/README.md). **Safety:** in-process toy apps; no real network or shell. Only test systems you own or have written permission to test.

The items in this lesson are older names that were merged into broader Top 10 categories over the years (XSS into Injection, IDOR into Broken Access Control, XXE into Misconfiguration, CSRF dropped as its own entry). They are still very common in real apps and exams, so you must know each one by name.

## 1. Cross-Site Scripting (XSS)

The attacker gets their JavaScript to run in another user's browser **in the context of your site**, so it can read the page, act as the user, or steal non-HttpOnly cookies and tokens in `localStorage`.

| Type | Where the payload lives | Lab |
|---|---|---|
| **Reflected** | In the request (for example `?q=<script>...`), echoed back immediately | `reflected_xss` |
| **Stored** | Saved by the server (review, profile) and shown to every visitor | `stored_xss` |
| **DOM-based** | Client-side JavaScript copies attacker data (for example `location.hash`) into a sink such as `innerHTML` | chapter 02 reviewer flags `innerHTML` |

**Defenses:** context-aware **output encoding** (HTML body, attribute, JavaScript, URL, CSS; chapter 02 lab), template auto-escaping, safe DOM APIs (`textContent`), HTML sanitizer when markup is truly needed, **Content Security Policy** with nonces as a second layer, `HttpOnly` cookies to limit token theft. Input validation helps but is not the main fix.

## 2. Insecure Direct Object Reference (IDOR)

The app uses an identifier from the client (`/orders/2`, `?invoice=1003`, a JSON `user_id`) to fetch an object and **does not check that the current user may access it**. In API terms it is called **BOLA** (Broken Object Level Authorization, API1 in the OWASP API Top 10).

- **DBA picture:** `SELECT * FROM orders WHERE id = :id` versus `... WHERE id = :id AND user_id = :me`.
- **Defenses:** an ownership or permission check on every object access, ideally in one place (repository layer, policy engine, row-level security); random ids (UUIDs) make guessing harder but are **not** a fix; tests with two users.

## 3. Unvalidated redirects and forwards

The app sends the user to a URL or internal page taken from a parameter:

- **Redirect** (`302 Location: <param>`): an **open redirect**. Phishing links look trustworthy (`https://shop.example/logout?next=https://evil.example/login`) and it can leak OAuth codes or tokens when used in redirect URIs.
- **Forward** (server-side, to an internal handler): may skip access checks if the target page assumes the caller already checked.

**Defenses:** avoid user-controlled destinations; use an id that maps to an allowlisted URL; or allow only local paths: starts with `/`, not `//`, no backslash, no scheme or host after parsing (`safe_next()` in the lab). Re-check authorization on forwarded targets.

## 4. XML External Entities (XXE)

An XML parser that processes a **DOCTYPE** with external entities can be told to read local files (`file:///etc/passwd`), make network requests (SSRF) or blow up memory ("billion laughs" entity expansion).

```xml
<?xml version="1.0"?>
<!DOCTYPE order [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<order><note>&xxe;</note></order>
```

- **Where it appears:** SOAP APIs, SAML, file uploads that are XML inside (DOCX, XLSX, SVG), RSS imports.
- **Defenses:** disable DTDs and external entities in the parser (each language has a setting; in Java set the `disallow-doctype-decl` feature; in Python use a hardened parser such as defusedxml); prefer JSON where possible; validate against a schema; patch XML libraries. Python's standard `xml.etree` does not fetch external entities but is still exposed to entity expansion attacks, which is why defusedxml exists (verify current Python docs). Chapter 13 has an XXE lab.

## 5. Cross-Site Request Forgery (CSRF)

A page on another site makes the victim's browser send a request to your site; the browser attaches the victim's cookies automatically, so the request is authenticated. The attacker cannot read the response, but can **change state**: email, password, transfer.

- **Example:** `csrf_change_email` in the lab: a POST with only the session cookie changes the email.
- **Defenses:** anti-CSRF **tokens** (synchronizer token per session or per form, checked with a constant-time compare); **SameSite** cookies (`Lax` or `Strict`; Chromium defaults to Lax when the attribute is missing, other browsers may not, so set it explicitly); check `Origin`/`Sec-Fetch-Site` headers for state-changing requests; never change state with GET; re-authentication for critical actions. **CORS is not CSRF protection.** APIs that use `Authorization: Bearer` headers instead of cookies are not exposed to classic CSRF.

## 6. The hands-on exercises in one table

Each course exercise has an offline version in [vulnerable-shop](labs/vulnerable-shop/README.md) (vulnerable vs secure, with tests). The proxy skills come from [intercepting-proxy](labs/intercepting-proxy/README.md).

| Course exercise | The bug in the toy shop | The fix in `SecureShop` | Test proves |
|---|---|---|---|
| Working with Burp Suite | n/a | n/a | proxy lab: tamper, history, Repeater, Intruder |
| SQL Injection Fundamentals | Search and login build SQL with f-strings | Bind parameters (`?`), hash compared in code | UNION leak and `admin'--` bypass fail |
| Cross Site Scripting (XSS) | Search term and reviews printed raw | `html.escape` on output, CSP header | `<script>` and `<img onerror>` come back encoded |
| Cross Site Request Forgery (CSRF) | Email change trusts the cookie alone | Per-session token, `Origin` check, `SameSite=Lax` | Request with no token gets 403 |
| Exploiting Server Side Request Forgery (SSRF) | `/stock?url=` fetches anything | Exact host allowlist on the parsed URL, https only | FAKE metadata canary never returned; prefix-check bypass shown |
| Exploiting Command Injection | Host placed in a shell command line | Strict host regex and argv list, no shell | `; cat /etc/passwd` never reaches the executor |
| Insecure Direct Object References Fundamentals | Order fetched by id only | `WHERE id = ? AND user_id = ?`, 404 otherwise | Alice cannot read Bob's order |
| Security Misconfigurations | Debug endpoint, listing, default admin, stack traces, banner, missing headers, weak cookies | All removed or hardened | `misconfig_scan` returns an empty list |
| Open Redirect Vulnerabilities | `Location` copied from `?next=` | `safe_next()` local-path rule | Five bypass variants fall back to `/` |

**Command injection note.** The lab never runs a shell. `FakeShell` uses `shlex` to show how `/bin/sh` would split the line at `;`, `&&`, `|`, `$( )` and backticks, and records the commands that **would** run. The real fix in Python is `subprocess.run(["ping", "-c", "1", host], shell=False)` after validating `host`, or better a library call that needs no external program.

## 7. Scenario: the support portal

A support portal lets agents preview a customer's uploaded "invoice.xml" and has a "back to ticket" link built from `?return=`. A champion review finds: the XML preview resolves external entities (XXE reading `/etc/passwd` in the test environment), the return link is an open redirect, and the "close ticket" button is a GET request with no token (CSRF from any page an agent visits). Fixes: hardened XML parser with DTDs disabled, local-path-only redirect, POST with a CSRF token. The champion adds three test cases modelled on the vulnerable-shop tests so the bugs cannot return.

## 8. Checklist

- [ ] I can explain reflected, stored and DOM XSS and the main fix (output encoding).
- [ ] I can explain IDOR with a SQL `WHERE` clause.
- [ ] I can write a safe local-redirect rule and three payloads it must block.
- [ ] I can show an XXE payload and say how to disable it.
- [ ] I can explain why SameSite helps but a CSRF token is still the primary control.
- [ ] I ran the vulnerable-shop demo and can explain each row.
