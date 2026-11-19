# Lesson 03: Security Headers, Content Security Policy, CORS, and Cookie vs Token Implementations

**Syllabus items covered:** "Security Headers", "X-XSS-Protection", "HTTP Strict Transport Security (HSTS)", "Cache-Control", "X-Frame-Options", "X-Frame-Options vs frame-ancestors", "Content Security Policy", "Implementing CSP at Scale", "Common Misconfigurations While Using CSP", "Cross-Origin Resource Sharing (CORS)", "Cookie Based Implementations", "Token Based Implementations" ([CASP 7]).

**Time:** 2 hours. **Labs:** [security-headers-analyzer](labs/security-headers-analyzer/README.md), [csp-xss-mitigation](labs/csp-xss-mitigation/README.md). Attacks on CORS and XSS-to-privilege-escalation are in [chapter 13](../13-owasp-api-top-10-and-other-threats/README.md); output encoding and Trusted Types in [chapter 12](../12-input-validation-and-injection/README.md).

> **Why an API course cares about browser headers.** Most APIs are called by a browser single-page app. The browser enforces these headers. A JSON API that sends no `Cache-Control` or a reflective CORS policy leaks data through the browser even when the API code is correct.

## 1. Security headers at a glance

| Header | Status (Nov 2026; verify on MDN) | Recommended value for an API or SPA |
|---|---|---|
| `Strict-Transport-Security` | Current | `max-age=31536000; includeSubDomains` (add `preload` only when you are sure) |
| `Content-Security-Policy` | Current; the main XSS mitigation | Strict nonce/hash policy; for pure JSON APIs `default-src 'none'; frame-ancestors 'none'` |
| `Cache-Control` | Current | `no-store` for anything user-specific or sensitive |
| `X-Content-Type-Options` | Current | `nosniff` |
| `X-Frame-Options` | Superseded by CSP `frame-ancestors` | `DENY` only for very old browsers |
| `X-XSS-Protection` | **Deprecated** | `0`, or omit it |
| `Referrer-Policy` | Current | `strict-origin-when-cross-origin` or `no-referrer` |
| `Permissions-Policy` | Current | Disable features you do not use (`camera=(), geolocation=()`) |
| CORS headers (`Access-Control-*`) | Current | Exact origin allowlist; credentials only when needed |
| `Server`, `X-Powered-By` | Information leak | Remove, or remove version numbers |

## 2. X-XSS-Protection

This header controlled the **XSS Auditor/filter** in old Chrome, Edge and Safari. The auditor was removed (Chrome 78 in 2019; Edge and Safari later). The filter could be **abused** to selectively disable legitimate scripts and to leak data across origins. OWASP now advises **`X-XSS-Protection: 0`** or no header, and **CSP** instead. A scanner that says "missing X-XSS-Protection: 1; mode=block" is out of date. The syllabus lists the header so you can explain this in an exam.

## 3. HTTP Strict Transport Security (HSTS)

`Strict-Transport-Security: max-age=31536000; includeSubDomains` tells the browser: for one year, connect to this host (and its subdomains) only over HTTPS, and do not let the user click through certificate errors. It stops **SSL stripping**, where an attacker on public Wi-Fi keeps the victim on `http://`.

- The first visit is still exposed. **Preload** (`hstspreload.org`) adds the domain to browsers' built-in lists. It is hard to undo, so every subdomain must support HTTPS first.
- Only sent over HTTPS; ignored over HTTP.
- For non-browser API clients HSTS does nothing. Those clients must simply refuse plain HTTP and verify certificates.

## 4. Cache-Control

Shared caches (CDNs, corporate proxies) and the browser's back/forward cache can store API responses. If `/api/me` returns account details with `Cache-Control: public, max-age=600`, the next user of a shared computer, or of a misconfigured CDN, may see them. This is the defense side of the **web cache deception** attack in chapter 13.

- `Cache-Control: no-store` for user-specific or sensitive responses.
- `private` allows only the browser to cache. `no-cache` means "revalidate before use", which is **not** "do not store".
- Set `Vary: Origin` / `Vary: Authorization` where responses differ, and make sure the CDN cache key includes what matters.

## 5. X-Frame-Options and frame-ancestors

### 5.1 X-Frame-Options

`X-Frame-Options: DENY` or `SAMEORIGIN` stops other sites from loading your page in an `<iframe>`. That defends against **clickjacking**: an invisible frame of your "Transfer" button placed under a fake "Win a prize" button.

### 5.2 X-Frame-Options vs frame-ancestors

| | `X-Frame-Options` | CSP `frame-ancestors` |
|---|---|---|
| Allow several origins | No (`ALLOW-FROM` was never widely supported and is obsolete) | Yes: `frame-ancestors 'self' https://partner.example` |
| Standard | Informational RFC 7034 | CSP Level 2+ |
| Precedence | Ignored by modern browsers when `frame-ancestors` is present | Wins |
| Works in `<meta>` CSP | n/a | **No**, it must be an HTTP header |

Use `frame-ancestors` and keep `X-Frame-Options: DENY` only as a fallback for very old browsers.

## 6. Content Security Policy

CSP is an allowlist the browser enforces: which scripts, styles, frames and connections a page may use. Its main value is **limiting XSS**. Injected markup cannot run if the policy does not allow it.

**Strict CSP** (recommended by Google's web.dev and the OWASP CSP Cheat Sheet; verify):

```text
Content-Security-Policy:
  script-src 'nonce-{random-per-response}' 'strict-dynamic';
  object-src 'none';
  base-uri 'none';
  frame-ancestors 'none';
  report-to csp-endpoint
```

- Every legitimate `<script>` carries `nonce="{same random value}"`. The value is new for **every response** (at least 128 bits).
- `'strict-dynamic'` lets those trusted scripts load their dependencies, and makes the browser ignore host allowlists.
- Static pages can use **hashes** (`'sha256-...'`) of the exact inline scripts instead of nonces.
- `object-src 'none'` blocks plugins; `base-uri 'none'` stops `<base href>` hijacking.
- **Trusted Types** (`require-trusted-types-for 'script'`) closes DOM XSS sinks such as `innerHTML`. It is long supported in Chromium, and recent Safari and Firefox releases have added it (verify on caniuse). See chapter 12.

**Pure JSON APIs** should still send `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`. If a browser is ever tricked into rendering the JSON as HTML, nothing runs.

## 7. Implementing CSP at scale

1. **Inventory** scripts: inline blocks, event handlers (`onclick=`), `javascript:` links, third-party tags.
2. Deploy **`Content-Security-Policy-Report-Only`** with a reporting endpoint (`report-to` with the `Reporting-Endpoints` header; `report-uri` as a legacy fallback). Nothing breaks; you collect violations.
3. **Refactor:** move inline handlers to `addEventListener`, add nonces in the **template engine** (one central place), remove `eval`.
4. **Triage reports:** browser extensions create noise; group by directive and source file.
5. **Enforce**, and keep Report-Only running for the *next* stricter policy.
6. Put the policy in **one place** (gateway, framework middleware or CDN rules), version it in git, and test it in CI with the analyzer from the lab.
7. Monitor violation rates. A spike can mean an attack or a bad deploy.

## 8. Common misconfigurations while using CSP

| Misconfiguration | Why it fails |
|---|---|
| `script-src 'unsafe-inline'` (no nonce or hash) | Inline injection runs, so the policy stops almost nothing |
| `'unsafe-eval'` | `eval`, `new Function` and string `setTimeout` are allowed |
| `script-src *`, `https:` or `data:` | Any host, or a data URL, can serve script |
| Allowlisting big CDNs (`cdnjs.cloudflare.com`, `*.googleapis.com`) | They host old AngularJS and JSONP endpoints, which are "gadgets" that bypass the allowlist |
| Missing `object-src 'none'` | Plugin content (legacy) can run script |
| Missing `base-uri` | An injected `<base>` makes relative script URLs load from the attacker |
| A **static** or predictable nonce | The attacker copies it into the payload (shown in the lab) |
| Report-Only forever | Nothing is blocked |
| Policy in a `<meta>` tag only | `frame-ancestors`, `report-to` and `sandbox` are ignored there |
| Two policies that conflict | Browsers enforce **both**, so the effect is the intersection. Teams then add `unsafe-inline` to "fix" it. |
| `default-src 'self'` with user uploads on the same origin | Uploaded `.js` files become "self" |

## 9. Cross-Origin Resource Sharing (CORS)

The **same-origin policy** stops `evil.example` JavaScript from **reading** responses from `api.bank.example`. CORS lets a server **relax** that for chosen origins. It is not a protection; it is a controlled hole.

- **Simple requests** (GET/POST with simple content types) are sent anyway; CORS only decides whether the script may read the response. So CORS is **not CSRF protection**.
- **Preflight** (`OPTIONS` with `Access-Control-Request-Method`) happens for other methods and for custom headers or JSON content types.
- With `Access-Control-Allow-Credentials: true`, the browser sends cookies and lets the script read the result. Browsers reject `*` with credentials.

**Classic bugs:** reflecting any `Origin` with credentials (every website can read the user's data); trusting `null` (sandboxed iframes send it); unanchored regexes (`shop\.example` matches `shop.example.attacker.test` and `evilshop.example`); trusting all subdomains when one subdomain has XSS or is taken over. **Fix:** an exact allowlist of full origins (scheme, host and port), `Vary: Origin`, credentials only when needed, and no `null`.

## 10. Cookie based and token based implementations

### 10.1 Cookie based implementations

The session id (or a token) sits in a cookie that the browser sends automatically.

- Attributes: `HttpOnly` (JavaScript cannot read it), `Secure`, `SameSite=Lax` or `Strict`, `Path=/`, no `Domain`, and the **`__Host-` prefix**, which forces Secure, `Path=/` and no Domain.
- **Pro:** XSS cannot steal an HttpOnly cookie (it can still make requests while the user is on the page).
- **Con:** automatic sending means **CSRF**. `SameSite=Lax` stops cross-site POSTs (Chromium defaults to Lax when the attribute is missing; other browsers differ, so set it explicitly). Add CSRF tokens or require a custom header for state-changing calls when `SameSite=None` is needed.

### 10.2 Token based implementations

The SPA holds an access token (often a JWT) and sends `Authorization: Bearer ...`.

- **Pro:** not sent automatically, so no CSRF; works across domains and for mobile and service clients.
- **Con:** the token must live somewhere JavaScript can reach. `localStorage` and `sessionStorage` are readable by **any** XSS on the origin, and a stolen token works from anywhere until it expires.
- Mitigations: short access-token lifetimes; refresh-token rotation; sender-constrained tokens (**DPoP**, RFC 9449, or mTLS, RFC 8705); keep tokens in memory only; strict CSP.

### 10.3 What to choose

For browser SPAs, current guidance (OAuth 2.0 for Browser-Based Apps, an IETF draft; verify) favours the **Backend-for-Frontend (BFF)** pattern. A small server-side component does the OAuth flow and keeps the tokens. The browser gets only an `HttpOnly; Secure; SameSite` `__Host-` session cookie, and the BFF adds the bearer token when it calls the API. Mobile apps and service clients use bearer tokens. Chapter 10 covers token storage and XSS in depth.

Lesson 04 shows how a gateway adds these headers to every route in one place.

## 11. Scenario: the analytics subdomain

`api.travel.example` allows CORS for any origin matching `.*\.travel\.example$` with credentials. Marketing runs `blog.travel.example` on a hosted CMS with an old plugin that has stored XSS. An attacker posts a comment whose script calls `fetch("https://api.travel.example/v1/me/bookings", {credentials: "include"})`. The browser sends the user's session cookie, the API reflects the origin, and the script reads every booking with passport numbers.

**Fixes:** an exact origin allowlist (`https://www.travel.example` only); `SameSite=Strict` on the API session cookie (cross-site fetches from `blog` are same-*site*, so SameSite alone does **not** help here, which is a good exam trap); a BFF; patch or isolate the blog on a different registrable domain.

## 12. Checklist

- [ ] I can give the recommended value for each header in section 1 and explain why X-XSS-Protection is `0`.
- [ ] I can explain XFO vs `frame-ancestors` in two sentences.
- [ ] I can write a strict CSP from memory and name five misconfigurations.
- [ ] I can describe a CSP rollout with Report-Only.
- [ ] I can explain why CORS is not CSRF protection, and the reflected-origin bug.
- [ ] I can compare cookie-based and token-based sessions and explain BFF.

## References

- OWASP HTTP Headers, Content Security Policy, Clickjacking Defense, CSRF Prevention and HTML5 Security cheat sheets.
- MDN pages for each header; web.dev "Mitigate cross-site scripting with a strict CSP"; W3C CSP Level 3.
- RFC 6797 (HSTS); RFC 6265bis (cookies, SameSite; draft, verify); Fetch standard (CORS).
- IETF draft "OAuth 2.0 for Browser-Based Applications" (verify status); RFC 9449 (DPoP).
