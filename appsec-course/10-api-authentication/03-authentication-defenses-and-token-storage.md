# Lesson 03: Authentication Defenses and Secure Token Storage

**Syllabus items covered:** "Authentication Defenses", "Secure Authentication Workflows", "Strong Password and Key Validation", "Multi-Factor Authentication", "Securely Storing the Tokens", "Cookies", "Local Storage and Session Storage", "Token Storage and XSS", "Rate Limiting", "CAPTCHA" ([CASP 3]).

**Time:** 2 hours. **Labs:** [weak-password-login](labs/weak-password-login/README.md) (lockout + rate limit), [password-reset-workflow](labs/password-reset-workflow/README.md) (secure workflow), [password-hash-cracking](labs/password-hash-cracking/README.md) (storage), [jwt-attacks](labs/jwt-attacks/README.md) (strict validation). Cookie/CSP labs are in [chapter 14](../14-api-defenses-data-security-and-headers/README.md).

## 1. Authentication defenses and secure authentication workflows

Defense in depth for authentication:

| Layer | Controls |
|---|---|
| **Use a proven identity system** | an OIDC provider (Keycloak, Entra ID, Okta, Auth0, Cognito...) instead of home-made login, sessions and resets |
| **Credentials** | length-based passwords + breached-password checks; passkeys; strong random API keys and client secrets, or better, private-key JWT / mTLS / workload identity |
| **Login flow** | uniform errors, constant-time comparison, rate limits, MFA, session/token rotation on login |
| **Tokens** | short-lived access tokens, rotated refresh tokens, strict validation, sender-constraining (DPoP, mTLS) for high-value APIs |
| **Recovery** | secure reset tokens (single use, expiry, hashed, configured base URL), notifications, MFA re-check |
| **Monitoring** | log logins, failures, resets, MFA changes; alert on spraying, impossible travel, many 401s |

**Secure authentication workflows**, step by step:

1. **Registration:** validate email ownership; check the password against a breached list; do not reveal whether an account exists.
2. **Login:** same response for unknown user and wrong password; run the hash check always; throttle; on success, issue a **new** session/token (prevents session fixation).
3. **Step-up:** require MFA again for sensitive actions (change email, add payee, export data).
4. **Change password / email:** require the current password or MFA; notify the old email; invalidate other sessions and refresh tokens.
5. **Reset:** see [lesson 02 section 8](02-authentication-attacks.md#8-password-reset-workflows) and the [lab](labs/password-reset-workflow/README.md).
6. **Logout:** delete the server session or revoke the refresh token; clear cookies; short access-token lifetime covers the rest.

## 2. Strong password and key validation

**Passwords (NIST SP 800-63B-4, final 2025; verify the details):**

- **Length over complexity:** at least **15 characters** when the password is the only factor, at least **8** when used with MFA; allow at least 64 characters; allow all printable characters, spaces and Unicode.
- **No forced composition rules** (no "must contain a symbol"), **no periodic rotation**; force a change only on evidence of compromise.
- **Blocklist** check against breached and common passwords (for example a k-anonymity range query to a breached-password service, or a local list) and context words (the service name, the username).
- No password hints or knowledge-based questions. Allow paste and password managers.

**Keys and secrets:**

- Generate with a CSPRNG (`secrets.token_urlsafe(32)`); ≥ 128 bits for API keys, ≥ 256 bits for HMAC (JWT) secrets.
- **Validate format and entropy** server-side when a client chooses a secret (webhook secrets, client secrets), and reject short or dictionary values. The [jwt-attacks lab](labs/jwt-attacks/README.md) shows `secret123` falling to a six-word list.
- Store keys hashed; scope, expire and rotate them; scan repos and chat for leaks.

## 3. Multi-factor authentication

| Factor type | Example | Phishing-resistant? | Notes |
|---|---|---|---|
| **Passkeys / WebAuthn / FIDO2** | platform authenticator, security key | **yes** (bound to the site's origin) | preferred; also replaces passwords |
| Smart card / PIV, client certificate | mTLS | yes | enterprise and government |
| TOTP app | 6-digit codes (RFC 6238) | no (can be phished in real time) | good baseline; rate-limit verification |
| Push approval | "Approve sign-in?" | no | **push fatigue / MFA bombing**: use number matching and limits |
| SMS / voice OTP | text message | no | weakest: SIM swap, interception; NIST restricts it |
| Email OTP / magic link | link or code | no | only as good as the mailbox |

API notes: MFA happens at the identity provider; the API sees an access token whose claims (`amr`, `acr`) can say how the user authenticated, so the API can demand step-up for sensitive operations. **Rate-limit OTP verification** (10⁶ codes is a small keyspace) and bind OTPs to the session that requested them.

## 4. Securely storing the tokens

Where a client keeps tokens decides who can steal them.

| Client | Recommended storage |
|---|---|
| Server-side web app / **BFF** (backend-for-frontend) | tokens stay **on the server**; the browser holds only an HttpOnly session cookie |
| Single-page app (SPA) without a BFF | access token **in memory** (a JavaScript variable), short lifetime; refresh via a rotating refresh token in an HttpOnly cookie or silent re-authentication. The BFF pattern is the current recommendation (OAuth for browser-based apps BCP; verify) |
| Mobile app | the OS keystore: iOS Keychain, Android Keystore / EncryptedSharedPreferences |
| Server / service / CI job | a secrets manager or vault, injected at runtime; better, workload identity with no stored secret at all ([chapter 15](../15-implementing-api-security-mechanisms/README.md)) |
| Anywhere | never in source code, URLs, logs, analytics or error reports |

### Cookies

| Attribute | Effect |
|---|---|
| `HttpOnly` | JavaScript cannot read it (`document.cookie`), so XSS cannot **steal** it |
| `Secure` | sent only over HTTPS |
| `SameSite=Lax` / `Strict` | not sent on most cross-site requests, which blocks most CSRF. Chromium defaults to `Lax` when unset; `None` requires `Secure` |
| `__Host-` prefix | must be `Secure`, `Path=/`, and have no `Domain`, so subdomains cannot set or override it |
| `Max-Age` / `Expires` | prefer short sessions; omit for a browser-session cookie |
| `Domain` | omit it unless needed; a parent-domain cookie is sent to every subdomain |

Cookies are sent **automatically**, so cookie-authenticated APIs need **CSRF protection** (SameSite plus anti-CSRF tokens or custom-header checks for state-changing requests). Bearer tokens in an `Authorization` header are not sent automatically, so they are not exposed to CSRF, but they must be stored somewhere JavaScript can reach.

### Local storage and session storage

`localStorage` (persists until cleared) and `sessionStorage` (per tab, until it closes) are simple key-value stores **readable by any JavaScript on the origin**. They are convenient for tokens, which is exactly why XSS payloads look there first. A token in `localStorage` survives browser restarts, so a single XSS gives long-lived access. Recommendation: do not store access or refresh tokens in web storage; if you must, keep lifetimes very short and invest heavily in XSS prevention (CSP, Trusted Types).

### Token storage and XSS

| Storage | XSS can steal the token? | XSS can still use the session? | CSRF? |
|---|---|---|---|
| `localStorage` / `sessionStorage` | **yes**, and send it anywhere | yes | no |
| JavaScript memory | harder (must hook the app at runtime) | yes, while the page is open | no |
| `HttpOnly` cookie | **no** | **yes**: the script can make requests from the victim's browser, and the browser attaches the cookie | yes, unless SameSite / anti-CSRF |
| BFF session cookie (tokens server-side) | no | yes, through the BFF, for the page's lifetime | needs SameSite / anti-CSRF |

The key lesson: **no storage choice survives XSS completely.** HttpOnly stops token *theft* (which matters because a stolen token works from anywhere, for its whole lifetime), but an attacker's script can still act inside the victim's session while it runs. So: prevent XSS (output encoding, CSP, Trusted Types; [chapter 12](../12-input-validation-and-injection/README.md)) and limit the blast radius (short lifetimes, sender-constrained tokens, step-up MFA). The stored-XSS-to-admin scenario is a lab in [chapter 13](../13-owasp-api-top-10-and-other-threats/README.md).

## 5. Rate limiting

Rate limiting counts requests per key (IP, user, API key, device, account) per time window and answers **429 Too Many Requests** with a `Retry-After` header.

| Algorithm | Behaviour |
|---|---|
| Fixed window | simple counter per minute; bursts at window edges |
| Sliding window | smoother counting over the last N seconds |
| **Token bucket** | a bucket of `burst` tokens refilled at `rate` per second; allows short bursts, enforces an average |
| Leaky bucket | smooths output to a fixed rate |

For authentication specifically:

- Limit **per account** (stops brute force on one user), **per IP / device** (stops one attacker on many users) and **globally** for the login endpoint (detects spraying).
- Apply to **every** credential-checking endpoint: login, OTP verify, password reset request and confirm, API-key validation, token endpoint.
- Put coarse limits at the gateway and precise per-account logic in the service.
- Watch for bypasses: spoofed `X-Forwarded-For`, rotating IPs, GraphQL batching, case variants of usernames (`Alice` vs `alice`).

The [weak-password-login lab](labs/weak-password-login/README.md) implements a per-IP token bucket and a per-account lockout. Gateway-level rate limiting is built in [chapters 14 and 15](../15-implementing-api-security-mechanisms/README.md).

## 6. CAPTCHA

A CAPTCHA tries to tell humans from bots. **This course teaches design and trade-offs only, not bypass techniques.**

| Aspect | Notes |
|---|---|
| Current options | Google **reCAPTCHA v3** (invisible score), **hCaptcha**, **Cloudflare Turnstile** (privacy-oriented, mostly non-interactive) |
| Where it helps | public sign-up, login after several failures, password reset requests, comment and contact forms |
| Costs | **accessibility** (visual and audio puzzles exclude some users; follow WCAG and offer alternatives), friction and lost conversions, privacy and third-party data sharing |
| Limits | AI solvers and human solver farms defeat many challenges; pure APIs (mobile, server-to-server) cannot show one |
| Right design | a **friction signal** combined with rate limits, risk scoring (device, IP reputation, behaviour), MFA and monitoring; trigger it adaptively, never as the only control; always verify the token **server-side** |

## 7. Scenario: the SPA that kept tokens forever

A trading-education SPA stored a 30-day access token in `localStorage`. A stored XSS in a forum signature sent `localStorage` contents to an attacker's server; the attacker used the tokens from their own machine for weeks. **Fix plan:** move to a BFF with an `__Host-` HttpOnly, Secure, SameSite=Lax session cookie; access tokens of 5 minutes held only server-side; refresh-token rotation with reuse detection; strict CSP with nonces and Trusted Types; output encoding of forum content; and an alert on token use from new ASNs.

## 8. Self-check

1. Which cookie attributes stop token theft, cross-site sending, and subdomain overrides?
2. Why does HttpOnly not fully protect a session against XSS?
3. Why is a CAPTCHA never enough on its own, and what should accompany it?

Back to the [chapter README](README.md).
