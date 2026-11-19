# Lab: The vulnerable shop (SQLi, XSS, CSRF, SSRF, command injection, IDOR, misconfiguration, open redirect)

**Course exercises:** SQL Injection Fundamentals; Cross Site Scripting (XSS); Cross Site Request Forgery (CSRF); Exploiting Server Side Request Forgery (SSRF); Exploiting Command Injection; Insecure Direct Object References Fundamentals; Security Misconfigurations; Open Redirect Vulnerabilities. Lessons: [05 OWASP Top 10](../../05-owasp-top-10.md), [06 Beyond the Top 10](../../06-risks-beyond-the-top-10.md).

**Time:** 90 minutes. **Tests:** 32, all offline. **Safety:** an in-process toy shop. There is no socket, no real network call (SSRF uses `fake_fetch` with a FAKE metadata canary) and no shell (`FakeShell` only shows what a shell would run). Only test systems you own or have written permission to test.

## Goal

See each classic web bug work, then see one small server-side change stop it, and prove both with tests.

## Concept

[shop.py](shop.py) has two classes with the same routes:

- `VulnerableShop`: every bug is marked `VULN` in a comment.
- `SecureShop(VulnerableShop)`: overrides only the handlers that need a fix, so you can read the bug and the fix side by side.

The app is a function, `handle(method, path, headers, body) -> (status, headers, body)`, the same shape as a web framework's request handler. [attacks.py](attacks.py) holds one function per exercise; the demo and the tests run the **same** attack against both classes.

| Route | Exercise | Vulnerable | Secure |
|---|---|---|---|
| `GET /search?q=` | SQLi, reflected XSS | f-string SQL, raw echo | bind parameter, `html.escape` |
| `POST /login` | SQLi login bypass, default creds | f-string SQL, `admin`/`admin` | bind parameter, `hmac.compare_digest`, strong lab password |
| `POST /product/1/review`, `GET /product/1` | stored XSS | raw review HTML | encoded output + CSP |
| `POST /account/email` | CSRF | cookie alone is enough | token + `Origin` check + `SameSite=Lax` |
| `GET /stock?url=` | SSRF | fetches anything | parsed-URL exact host allowlist, https only |
| `GET /tools/ping?host=` | command injection | string sent to `FakeShell` | strict regex + argv list (`FakeExec`) |
| `GET /orders/<id>` | IDOR | id only | `AND user_id = ?`, 404 |
| `GET /logout?next=` | open redirect | `Location: next` | `safe_next()` local paths only |
| `/debug`, `/static/`, errors, headers | misconfiguration | on, listing, stack trace, banner | off, 403, reference id, security headers |

## Run

```text
.venv/Scripts/python appsec-course/01-security-champions-and-appsec-basics/labs/vulnerable-shop/demo.py
.venv/Scripts/python -m pytest appsec-course/01-security-champions-and-appsec-basics/labs/vulnerable-shop -q -p no:cacheprovider
```

## Expected output (real run)

```text
Exercise                       | Vulnerable | Secure
----------------------------------------------------------
SQL injection (UNION)          | EXPLOITED  | blocked
                               |   vuln:   HTTP 200, users table leaked: True
                               |   secure: HTTP 200, users table leaked: False
SQL injection (login bypass)   | EXPLOITED  | blocked
                               |   vuln:   HTTP 200 for username admin'--
                               |   secure: HTTP 401 for username admin'--
Reflected XSS                  | EXPLOITED  | blocked
                               |   vuln:   HTTP 200, raw <script> in page: True
                               |   secure: HTTP 200, raw <script> in page: False
Stored XSS                     | EXPLOITED  | blocked
                               |   vuln:   HTTP 200, raw <img onerror> stored: True
                               |   secure: HTTP 200, raw <img onerror> stored: False
CSRF                           | EXPLOITED  | blocked
                               |   vuln:   HTTP 200: email changed
                               |   secure: HTTP 403: cross-site request blocked
SSRF to metadata               | EXPLOITED  | blocked
                               |   vuln:   HTTP 200, canary returned: True
                               |   secure: HTTP 400, canary returned: False
Command injection              | EXPLOITED  | blocked
                               |   vuln:   HTTP 200, injected command reached the shell: [['cat', '/etc/passwd']]
                               |   secure: HTTP 400, injected command reached the shell: no
IDOR                           | EXPLOITED  | blocked
                               |   vuln:   HTTP 200: order 2: Tea pot to 7 Hill Street, Kochi
                               |   secure: HTTP 404: no such order
Open redirect                  | EXPLOITED  | blocked
                               |   vuln:   HTTP 302, Location: https://evil.example/login
                               |   secure: HTTP 302, Location: /

Misconfiguration scan, vulnerable: ['MISSING_HEADER:Content-Security-Policy', 'MISSING_HEADER:X-Content-Type-Options', 'MISSING_HEADER:Strict-Transport-Security', 'MISSING_HEADER:Referrer-Policy', 'SERVER_VERSION_BANNER', 'DEBUG_ENDPOINT_ENABLED', 'DIRECTORY_LISTING', 'DEFAULT_CREDENTIALS', 'COOKIE_WITHOUT_HTTPONLY', 'COOKIE_WITHOUT_SECURE', 'COOKIE_WITHOUT_SAMESITE', 'VERBOSE_ERRORS']
Misconfiguration scan, secure:     []
```

## Steps

1. **SQL injection.** Read `VulnerableShop.search`. Write out the SQL the UNION payload produces. Why does it need the same number of columns (3)? Then read `SecureShop.search`: the `%` wildcards are added to the **value**, not the SQL text.
2. **Login bypass.** `admin'--` turns the rest of the query into a comment. Why does the secure version also compare the hash in Python with `hmac.compare_digest`?
3. **XSS.** Change the stored payload to `<svg onload=steal()>`. Does the secure page still encode it? (Yes: encoding does not care which tag you use; a blocklist would.)
4. **CSRF.** In `SecureShop.change_email`, delete the token check and run the tests. Which test fails? Put it back.
5. **SSRF.** Run `shop.naive_prefix_check("https://stock.partner.example@169.254.169.254/")` in a Python shell. The text starts with the right host but the real host (after `@`) is the metadata address.
6. **Command injection.** Call `shop.FakeShell().run("ping -c 1 8.8.8.8 && id")` and read `.executed`. Then compare `FakeExec.run_argv`.
7. **IDOR.** Log in as bob and read order 1. What status does the secure shop return, and why not 403?
8. **Open redirect.** Add a sixth bypass to the parametrized test (for example `/%2F%2Fevil.example` or a tab character) and decide whether `safe_next` needs a change.
9. **Misconfiguration.** Make `SecureShop.debug` return 200 again and watch `test_misconfig_scan...` fail.

## Run the real tools (hedged)

Use the course lab environment or a local training app you run yourself (for example OWASP Juice Shop or DVWA in Docker), never a real site.

- **Burp Suite:** proxy the browser, send each request to Repeater, try the payloads above. See [real-tools/burp-suite.md](../../real-tools/burp-suite.md).
- **sqlmap** (only on your own lab target; verify flags): `sqlmap -u "http://127.0.0.1:3000/search?q=mug" --batch --level 2`.
- **ZAP baseline** for misconfiguration and header findings (verify image name): `docker run --rm -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://host.docker.internal:3000`.
- **Command injection, SSRF:** only in the course lab, where internal targets are prepared for you.

## What you learned

- Every bug here is the server **trusting input**: as SQL text, as HTML, as a URL, as a shell line, as an object id, as a redirect target, or trusting that a request came from your own page.
- Every fix is **server-side** and small: bind parameters, output encoding, a token, an allowlist on parsed data, an argv list, an owner filter.
- A test that runs the **attack** against both versions is the best evidence that a fix works and stays working.
