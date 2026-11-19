# Lab: Security headers analyzer (HSTS, Cache-Control, XFO vs frame-ancestors, CSP, CORS, cookies)

**Course items:** "Security Headers", "X-XSS-Protection", "HTTP Strict Transport Security (HSTS)", "Cache-Control", "X-Frame-Options", "X-Frame-Options vs frame-ancestors", "Common Misconfigurations While Using CSP", "Cross-Origin Resource Sharing (CORS)", "Cookie Based Implementations", "Token Based Implementations". Lesson: [03 security headers](../../03-security-headers-csp-and-cors.md).

**Time:** 60 minutes. **Tests:** 10, all offline. **Safety:** header dictionaries in JSON fixtures; no requests are sent. The session values are FAKE. Only test systems you own or have written permission to test.

## Goal

Build the tool you would use in a code review or a CI gate: give it a response's headers and get a list of findings with severities. Then use the same module to compare a **vulnerable CORS origin check** with a **secure** one, and to model **SameSite** cookie behaviour for cookie-based sessions.

## Concept

[headers.py](headers.py):

| Check ids | What they look for |
|---|---|
| `XXP-01` | `X-XSS-Protection` enabled. It is **deprecated**: browsers removed the XSS Auditor, and the filter itself caused information leaks. Send `0` or omit it, and use CSP. |
| `HSTS-01..03` | Missing HSTS, `max-age` below one year, no `includeSubDomains` |
| `CACHE-01` | Sensitive API response without `Cache-Control: no-store` |
| `FRAME-01..03` | No clickjacking protection; XFO only (prefer CSP `frame-ancestors`); obsolete `ALLOW-FROM` |
| `CSP-00..10` | Missing CSP; `unsafe-inline` without nonce/hash; `unsafe-eval`; wildcards; CDN allowlists (JSONP/AngularJS gadgets); `object-src`; `base-uri`; reporting; Report-Only only |
| `CORS-01..03` | `null` origin; `*` with credentials; an untrusted origin reflected with credentials |
| `COOKIE-01..06` | HttpOnly, Secure, SameSite, `__Host-` prefix rules |
| `NOSNIFF-01`, `INFO-01` | `X-Content-Type-Options`; version banners |

`cors_vulnerable_regex()` (unanchored match), `cors_vulnerable_reflect()` and `cors_secure()` (exact allowlist) show the classic CORS bug. `cookie_sent()` models when a browser attaches a cookie, which is the root of CSRF in **cookie-based** implementations. **Token-based** implementations (a bearer token in the `Authorization` header) are not sent automatically, so they avoid CSRF but must keep the token away from XSS (see the lesson).

## Run

```text
.venv/Scripts/python appsec-course/14-api-defenses-data-security-and-headers/labs/security-headers-analyzer/demo.py
.venv/Scripts/python -m pytest appsec-course/14-api-defenses-data-security-and-headers/labs/security-headers-analyzer -v
```

## Expected output (real run)

```text
== legacy_api_response.json: 18 finding(s)
  [LOW] XXP-01 X-XSS-Protection: 1; mode=block is deprecated (auditor removed; it caused bugs). Send 0 or omit it and use CSP
  [HIGH] HSTS-01 no Strict-Transport-Security: first request can be downgraded (SSL stripping)
  [MEDIUM] CACHE-01 sensitive response without Cache-Control: no-store (shared caches and browser history keep it)
  [LOW] FRAME-02 X-Frame-Options only: prefer CSP frame-ancestors (keep XFO for old browsers)
  [MEDIUM] FRAME-03 X-Frame-Options ALLOW-FROM is obsolete and ignored by modern browsers; use frame-ancestors
  [HIGH] CSP-02 'unsafe-inline' in script-src without a nonce/hash: inline XSS runs
  [MEDIUM] CSP-05 allowlisted CDN hosts can serve JSONP/AngularJS gadgets: https://cdnjs.cloudflare.com
  [MEDIUM] CSP-06 object-src is not 'none' (plugins can run script)
  [MEDIUM] CSP-07 no base-uri: an injected <base> tag can hijack relative script URLs
  [LOW] CSP-08 no frame-ancestors: clickjacking protection relies on X-Frame-Options
  [LOW] CSP-09 no reporting endpoint: violations are invisible
  [LOW] NOSNIFF-01 no X-Content-Type-Options: nosniff
  [CRITICAL] CORS-03 origin https://evil.attacker.test reflected with credentials: any site can read this response as the user
  [HIGH] COOKIE-01 session: no HttpOnly, so any XSS can read the session
  [HIGH] COOKIE-02 session: no Secure, so it can travel over plain HTTP
  [MEDIUM] COOKIE-03 session: no SameSite (Chromium defaults to Lax; others differ) - set it explicitly
  [LOW] COOKIE-06 session: consider the __Host- prefix to lock the cookie to this host
  [LOW] INFO-01 Server/X-Powered-By reveal product versions

== hardened_api_response.json: 0 finding(s)

CORS origin checks (vulnerable regex vs exact allowlist):
  https://shop.example                   regex=True  reflect=True  secure=True
  https://shop.example.attacker.test     regex=True  reflect=True  secure=False
  https://evilshop.example               regex=True  reflect=True  secure=False
  null                                   regex=False reflect=True  secure=False

SameSite model: is the session cookie sent?
  SameSite=Strict Secure=True  {'same-site': True, 'cross-site-top-level-get': False, 'cross-site-post': False, 'cross-site-subresource': False}
  SameSite=Lax    Secure=True  {'same-site': True, 'cross-site-top-level-get': True, 'cross-site-post': False, 'cross-site-subresource': False}
  SameSite=None   Secure=True  {'same-site': True, 'cross-site-top-level-get': True, 'cross-site-post': True, 'cross-site-subresource': True}
  SameSite=None   Secure=False {'same-site': False, 'cross-site-top-level-get': False, 'cross-site-post': False, 'cross-site-subresource': False}

Strict CSP for a fresh nonce: script-src 'nonce-FRESHNONCE' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; report-to csp
```

## Steps

1. Fix `legacy_api_response.json` one finding at a time until the analyzer is silent. Compare your result with `hardened_api_response.json`.
2. Change the hardened CSP to `script-src 'self' https:`. Which finding appears and why is it HIGH?
3. Try `https://shop.example.attacker.test` against the regex check, then write an anchored regex that would be correct. Then explain why an exact set is still better.
4. Set the session cookie to `SameSite=None; Secure`. Which request kinds now carry the cookie? What extra control does the API need? (A CSRF token, or a custom header plus a CORS preflight.)
5. Add a check for `Referrer-Policy` and `Permissions-Policy` with a test.

## What you learned

- Several "security headers" from older checklists are now harmful or obsolete (`X-XSS-Protection: 1`, `ALLOW-FROM`).
- A CSP can exist and still be useless (`unsafe-inline`, wildcards, CDN allowlists). The strong pattern is nonces or hashes plus `'strict-dynamic'`, `object-src 'none'` and `base-uri 'none'`.
- CORS is a relaxation of the same-origin policy, not a protection. Reflecting the origin with credentials gives every website read access to the user's data.

## Run the real tool (hedged)

- `curl -sI https://YOUR-LAB-APP/` to see headers; Mozilla HTTP Observatory (now on MDN) and securityheaders.com for public sites you own.
- **Google CSP Evaluator** (csp-evaluator.withgoogle.com) for policies.
- **ZAP** passive scan rules flag missing headers and CORS issues; Burp's scanner flags CORS reflection. See the [devsecops ch06 TLS and misconfiguration lab](../../../../devsecops-course/06-dynamic-analysis/labs/tls-misconfiguration-checks/README.md).
