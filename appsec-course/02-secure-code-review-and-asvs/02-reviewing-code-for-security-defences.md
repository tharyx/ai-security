# Lesson 02: Reviewing Code for Security Defences

**Syllabus items covered:** [CSC 2] Reviewing the code for security defences; Input validation; Output encoding; Defending Authentication; Defending Authorization; Security Misconfigurations; Input validation using industry best practices and regex; Reviewing code for SQL Injection and Fixing with Parameterized queries; Reviewing for XSS and Implementing Output encoding to prevent client-side attacks like XSS.

**Time:** 3 hours with labs. **Labs:** [code-review-checklist](labs/code-review-checklist/README.md), [input-validation-regex](labs/input-validation-regex/README.md), [sqli-review-and-fix](labs/sqli-review-and-fix/README.md), [xss-review-and-fix](labs/xss-review-and-fix/README.md). **Safety:** toy code and in-memory sqlite only. Only test systems you own or have written permission to test.

## 1. Reviewing the code for security defences

A reviewer checks that each **defence** is present, in the right place, and correctly built. Five defence areas cover most web and API code:

| Defence | Belongs at | Review question | ASVS 5.0 chapter (verify) |
|---|---|---|---|
| Input validation | Entry point / service layer | Is every input checked against what is allowed? | V2 Validation and Business Logic |
| Output encoding and safe interpreters | Each sink (HTML, SQL, shell, URL) | Is data kept as data at every sink? | V1 Encoding and Sanitization |
| Authentication | Login, sessions, tokens, reset | Are identities proven and sessions protected? | V6 Authentication, V7 Session Management |
| Authorization | Every request and every object | Is this user allowed to do this to this object? | V8 Authorization |
| Secure configuration | Settings, deployment, headers | Are defaults safe in production? | V13 Configuration |

The [code-review-checklist lab](labs/code-review-checklist/README.md) turns this table into rules that scan a vulnerable and a fixed Flask-style fixture and produce a PASS/FAIL checklist.

## 2. Input validation

**Goal:** reject data that is not what the application expects, as early as possible, on the **server** (client-side checks are for user experience only).

Best practices (OWASP Input Validation Cheat Sheet, ASVS V2):

- **Allowlist, not blocklist.** Describe what is allowed (`[a-z0-9_]{3,20}`), not what is forbidden (`<script>`). Blocklists miss `<img onerror=...>`, encodings and new tricks.
- **Syntactic and semantic checks.** Syntax: type, length, format. Semantics: is the value valid in context (a start date before the end date, a quantity in stock, an id the user owns).
- **Convert to real types** (int, date, enum) and check ranges. A regex cannot know that `2026-02-30` is not a date.
- **Normalize first** (Unicode NFKC, case, trimming) and validate the normalized value, or fullwidth `ａｄｍｉｎ` slips past a reserved-name check.
- **Reject unknown fields** to block mass assignment (`role=admin` added to a profile update).
- **Limit sizes** of strings, arrays, files and request bodies.
- **Validation is not the main fix for injection.** It reduces attack surface; parameterization and encoding at the sink are still required, because some valid data (a name like O'Brien) contains dangerous characters.

### 2.1 Input validation with industry best practices and regex

Regex mistakes a reviewer must spot:

| Code | Problem | Fix |
|---|---|---|
| `re.match(r"[a-z0-9_]{3,20}", s)` | Only the **start** must match; `bob'; DROP TABLE users--` passes | `re.fullmatch(...)` |
| `re.match(r"^[a-z]+$", s)` | `$` also matches before a final `\n`, so `alice\n` passes | `fullmatch`, or `\A...\Z` |
| `re.search(r"\d{6}", pin)` | Finds digits anywhere in junk | `fullmatch(r"[1-9][0-9]{5}")` |
| `if "<script" not in s.lower()` | Blocklist | Allowlist + output encoding |
| `^(a+)+$`, `^(\w+\s?)*$` | Nested quantifiers: exponential backtracking (**ReDoS**) on crafted input | Simplify the pattern, bound input length, use a linear-time engine (RE2) where available |
| `\d` in Python `str` patterns | Matches non-ASCII digits (for example Arabic-Indic) | `[0-9]` or `re.ASCII` |
| Email regex of 400 characters | Unmaintainable and still wrong | Simple shape check plus a confirmation email |

Useful patterns from the [input-validation-regex lab](labs/input-validation-regex/README.md): Indian PIN code `[1-9][0-9]{5}`, E.164 phone `\+[1-9][0-9]{6,14}`, SKU `[A-Z]{3}-[0-9]{4}`, username `[a-z0-9_]{3,20}` after NFKC and a reserved-name check.

## 3. Output encoding

**Goal:** when data is written into a language (HTML, JavaScript, SQL, shell, URL, CSS), make sure it stays **data** in that language. The rule depends on the **context**:

| Context | Example sink | Correct defence |
|---|---|---|
| HTML body | `<p>{name}</p>` | HTML-encode `& < > " '` (`html.escape`) or auto-escaping templates |
| HTML attribute | `<div title="{bio}">` | **Quote** the attribute and HTML-encode with quotes |
| URL in `href`/`src` | `<a href="{site}">` | Allow only `http`/`https` schemes, then attribute-encode |
| JavaScript string | `<script>var n = "{nick}";</script>` | JSON-encode and escape `<`, `>`, `&` (so `</script>` cannot close the block); better: put data in a `data-` attribute or JSON block and read it |
| CSS | `style="color: {c}"` | Validate against a strict allowlist; avoid user data in CSS |
| SQL | query text | Bind parameters (not encoding) |
| Shell | command line | Argument list, no shell (not encoding) |

Section 8 and the [xss-review-and-fix lab](labs/xss-review-and-fix/README.md) show each context failing and being fixed.

## 4. Defending authentication

Review points (ASVS V6, V7; NIST SP 800-63B; chapter 10 goes deeper for APIs):

- **Password storage:** Argon2id first; scrypt; bcrypt (72-byte input limit); PBKDF2-HMAC-SHA256 with a high iteration count (about 600,000 per current OWASP guidance) where FIPS is needed. Flag `md5`, `sha1`, unsalted `sha256` and home-made schemes.
- **Comparison of secrets:** `hmac.compare_digest` (constant time), not `==`, for tokens, HMACs and reset codes.
- **Password policy:** length over complexity (at least 15 characters when a password is the only factor, 8 with MFA in NIST SP 800-63B-4; verify), no forced rotation, breached-password checks.
- **Brute force:** rate limits, progressive delays, lockout with care (lockout can be a denial of service), CAPTCHA only as an extra signal.
- **MFA:** available, phishing-resistant (passkeys/WebAuthn) preferred; SMS is weakest.
- **Sessions:** new session id at login (prevents fixation), server-side logout, idle and absolute timeouts, `HttpOnly`, `Secure`, `SameSite` cookies.
- **Reset flows:** random, single-use, short-lived tokens; same response whether or not the account exists; do not build reset links from the `Host` header.
- **No hard-coded credentials** and no secrets in code (load from a vault or environment).

## 5. Defending authorization

Authorization bugs are the most common serious finding, and the hardest for tools, because the bug is a **missing** line.

- **Every route** has an explicit rule (decorator, middleware, policy), and the default is deny. The lab's `AUTHZ001` rule flags routes without one.
- **Every object access** filters by the current user or checks a policy: `WHERE id = ? AND user_id = ?` (lab rule `AUTHZ002`). Oracle VPD or Postgres row-level security can enforce this in the database as a second layer.
- **Function-level** checks for admin actions are on the server, not hidden buttons.
- **Never trust** a role, user id or tenant id sent by the client (cookie, hidden field, JWT claim you did not verify).
- **Centralize** logic (one policy module or engine such as OPA, Cedar or Casbin) so reviewers check one place.
- **Test** with at least two users and two roles; chapter 11 covers authorization models and BOLA/BFLA in depth.

## 6. Security misconfigurations

Configuration is code; review it like code.

| Look for | Why it matters |
|---|---|
| `DEBUG = True`, `app.run(debug=True)` | Interactive debuggers and stack traces in production |
| `ALLOWED_HOSTS = ["*"]`, CORS `*` (worse with credentials) | Host header attacks, cross-origin data theft |
| `SESSION_COOKIE_SECURE = False`, `HTTPONLY = False` | Session theft over HTTP or by XSS |
| `verify=False` on HTTP clients | Man-in-the-middle on outbound calls |
| Secrets in settings files | Leak through git, logs, images |
| Missing security headers (CSP, HSTS, nosniff) | Weaker browser-side protection |
| Default accounts, sample apps, directory listing | Easy entry points |
| Verbose errors | Information disclosure |

The fixed fixture loads secrets from the environment and sets safe cookie, host and CORS values; the reviewer's `CONF00x` rules show the difference.

## 7. Reviewing for SQL injection and fixing with parameterized queries

**What to look for:** any SQL text built with `+`, `%`, `.format()` or f-strings and passed to `execute`, `raw`, `executemany`, or a stored procedure that uses dynamic SQL. Follow variables: `sql = "..." + q` followed by `execute(sql)` is the same bug.

**Fix patterns** (all in the [sqli-review-and-fix lab](labs/sqli-review-and-fix/README.md)):

```python
# Values: bind parameters (positional ? or named :name). Wildcards go into the VALUE.
db.execute("SELECT name FROM products WHERE name LIKE ?", (f"%{q}%",))

# Identifiers (column for ORDER BY) cannot be bound: map to an allowlist.
SORT = {"name": "name", "price": "price", "-price": "price DESC"}
order = SORT[sort_key]            # KeyError/ValueError for anything else

# IN lists: one placeholder per value, values converted to int first.
ids = [int(x) for x in csv.split(",")]
db.execute(f"SELECT ... WHERE id IN ({','.join('?' * len(ids))})", ids)
```

The same in Java and in Oracle PL/SQL:

```java
PreparedStatement ps = conn.prepareStatement("SELECT id, role FROM users WHERE username = ?");
ps.setString(1, username);
```

```sql
-- Vulnerable: EXECUTE IMMEDIATE 'SELECT ... WHERE name = ''' || p_name || '''';
EXECUTE IMMEDIATE 'SELECT price FROM products WHERE name = :1' INTO v_price USING p_name;
-- Identifiers: validate with DBMS_ASSERT.SIMPLE_SQL_NAME / an allowlist before concatenating.
```

**Remember:** ORMs are safe only when used as intended (`filter(name=q)`), not with raw strings; second-order injection (stored data later concatenated) is real; the database account should have least privilege so an injection cannot drop tables. The ORDER BY case in the lab shows a **blind boolean oracle**: changing the sort order leaks one bit per request, which is how tools such as sqlmap extract data without visible errors.

## 8. Reviewing for XSS and implementing output encoding

**What to look for:** string-built HTML (`f"<p>{x}</p>"`, `"%s" % x`), template escapes switched off (`|safe`, `{% autoescape false %}`, `Markup`, `mark_safe`, React `dangerouslySetInnerHTML`, Vue `v-html`, Angular `bypassSecurityTrust...`), DOM sinks (`innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout(string)`), unquoted attributes, user URLs in `href`, user data inside `<script>` blocks.

**Fix:** apply the context rule from section 3 at the sink. The [xss-review-and-fix lab](labs/xss-review-and-fix/README.md) has five payloads, one per context, and an oracle that proves which markup would execute:

| Field | Payload | Wrong | Right |
|---|---|---|---|
| name (body) | `<script>alert(1)</script>` | raw | `html.escape` |
| website (href) | `javascript:alert(1)` | raw | scheme allowlist then encode (result `#`) |
| bio (attribute) | `x onmouseover=alert(1)` | unquoted, even if escaped | quoted and escaped |
| nickname (JS) | `";alert(1);//` and `</script><script>...` | inside `"..."` raw | `json.dumps` + escape `<>&` as `<...` |
| color (CSS) | `red;background:url(javascript:...)` | raw | allowlist `#rrggbb` |

Then add **CSP** (nonces, `object-src 'none'`, `base-uri 'none'`) as a second layer and **Trusted Types** in modern browsers to lock DOM sinks (chapter 12).

## 9. Scenario: reviewing a profile feature

A pull request adds user profiles with a bio, a website link and a "theme colour". Meera reviews it with the chapter's checklist:

1. **Input validation:** the colour is any string. She asks for `#rrggbb` only.
2. **Output encoding:** the template uses `{{ bio|safe }}` "so users can use bold". She asks for auto-escaping plus an HTML sanitizer allowlisting `<b>` and `<i>`, and a scheme check on the website link.
3. **Authentication:** the profile update endpoint compares a CSRF token with `==`. She asks for `hmac.compare_digest` (or the framework's built-in CSRF).
4. **Authorization:** `POST /profile/<user_id>` updates whatever id is in the URL. She asks for the id to come from the session instead.
5. **Misconfiguration:** a new settings line `CORS_ALLOWED_ORIGINS = ["*"]` was added "for testing". She asks for it to be removed.

Each comment cites the ASVS chapter and links a test from this chapter's labs as an example.

## 10. Checklist

- [ ] I can name the five defence areas and where each belongs.
- [ ] I can spot `match` vs `fullmatch`, `$` vs `\Z`, blocklists and ReDoS patterns.
- [ ] I can list the output encoding rule for five contexts.
- [ ] I can review password storage, secret comparison and session handling.
- [ ] I check every route and every object access for authorization.
- [ ] I can fix SQLi for values, identifiers and IN lists, in Python, Java and PL/SQL.
- [ ] I know the template and DOM features that switch off XSS protection.
