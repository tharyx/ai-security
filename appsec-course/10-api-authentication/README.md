# Chapter 10: API Authentication Attacks and Defenses

This chapter covers how APIs prove who is calling (none, HTTP Basic, API keys, JWTs, OIDC, SAML and mutual TLS), how authentication breaks (brute force, weak password storage, reset flows, lockouts, insecure OIDC configuration, JWT validation mistakes, SQL injection in the login), and how to defend it (secure workflows, strong passwords and keys, MFA, safe token storage, rate limiting and CAPTCHA). Seven offline labs pair every attack with a fixed version.

> **Safety.** Every attack runs only against the lab's own toy code: in-process APIs, an in-memory sqlite3 database, hashes the lab generates from its own tiny password list, brute force capped at 4 lowercase characters, and FAKE secrets assembled at runtime. CAPTCHA is covered as design and trade-offs only. Only test systems you own or have written permission to test.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Tool status and version numbers are hedged: **verify at the source**.

## Syllabus coverage

| Syllabus item | Where to study | Lab |
|---|---|---|
| [CASP 3] Overview of API Authentication | [01 section 1](01-authentication-types.md#1-overview-of-api-authentication) | [auth-methods](labs/auth-methods/README.md) |
| [CASP 3] Types of Authentication | [01 section 2](01-authentication-types.md#2-types-of-authentication) (SVG) | [auth-methods](labs/auth-methods/README.md) |
| [CASP 3] No Authentication (Public APIs) | [01 section 3](01-authentication-types.md#3-no-authentication-public-apis) | [auth-methods](labs/auth-methods/README.md) (`/public`) |
| [CASP 3] HTTP Basic Authentication | [01 section 4](01-authentication-types.md#4-http-basic-authentication) | [auth-methods](labs/auth-methods/README.md) (`/basic`) |
| [CASP 3] API Token Authentication | [01 section 5](01-authentication-types.md#5-api-token-authentication) | [auth-methods](labs/auth-methods/README.md) (`/apikey`) |
| [CASP 3] OIDC Authentication | [01 section 7](01-authentication-types.md#7-oidc-authentication); flows in [chapter 11](../11-api-authorization-and-oauth/README.md); repo [MCP OAuth](../../04-mcp-security/authentication/README.md) | [oidc-config-check](labs/oidc-config-check/README.md) |
| [CASP 3] JSON Web Tokens (JWTs) | [01 section 6](01-authentication-types.md#6-json-web-tokens-jwts) (SVG) | [jwt-attacks](labs/jwt-attacks/README.md) |
| [CASP 3] SAML Tokens | [01 section 8](01-authentication-types.md#8-saml-tokens); XML attacks in [chapter 13](../13-owasp-api-top-10-and-other-threats/README.md) | n/a (concept) |
| [CASP 3] Mutual TLS | [01 section 9](01-authentication-types.md#9-mutual-tls) | [auth-methods](labs/auth-methods/README.md) (`/mtls`, simulated) |
| [CASP 3] Authentication Attacks | [02 section 1](02-authentication-attacks.md#1-authentication-attacks-the-map) | all attack labs |
| [CASP 3] Brute Force | [02 section 2](02-authentication-attacks.md#2-brute-force) | [weak-password-login](labs/weak-password-login/README.md) |
| [CASP 3] Weak Password Storage | [02 section 4](02-authentication-attacks.md#4-weak-password-storage); storage lab in [chapter 14](../14-api-defenses-data-security-and-headers/README.md) | [password-hash-cracking](labs/password-hash-cracking/README.md) |
| [CASP 3] Password Reset Workflows | [02 section 8](02-authentication-attacks.md#8-password-reset-workflows) | [password-reset-workflow](labs/password-reset-workflow/README.md) |
| [CASP 3] Account Lockouts | [02 section 3](02-authentication-attacks.md#3-account-lockouts) | [weak-password-login](labs/weak-password-login/README.md) (lockout) |
| [CASP 3] Insecure OpenID Connect Configuration | [02 section 9](02-authentication-attacks.md#9-insecure-openid-connect-configuration) | [oidc-config-check](labs/oidc-config-check/README.md) |
| [CASP 3] Insecure JWTs Validation | [02 section 10](02-authentication-attacks.md#10-insecure-jwt-validation-and-abusing-jwt-tokens) | [jwt-attacks](labs/jwt-attacks/README.md) |
| [CASP 3] Authentication Defenses | [03 section 1](03-authentication-defenses-and-token-storage.md#1-authentication-defenses-and-secure-authentication-workflows) | secure versions in every lab |
| [CASP 3] Secure Authentication Workflows | [03 section 1](03-authentication-defenses-and-token-storage.md#1-authentication-defenses-and-secure-authentication-workflows) | [password-reset-workflow](labs/password-reset-workflow/README.md) (`SecureReset`) |
| [CASP 3] Strong Password and Key Validation | [03 section 2](03-authentication-defenses-and-token-storage.md#2-strong-password-and-key-validation) (NIST SP 800-63B-4) | [jwt-attacks](labs/jwt-attacks/README.md) (weak vs strong secret), [password-reset-workflow](labs/password-reset-workflow/README.md) (length rule) |
| [CASP 3] Multi-Factor Authentication | [03 section 3](03-authentication-defenses-and-token-storage.md#3-multi-factor-authentication) | n/a (concept) |
| [CASP 3] Securely Storing the Tokens | [03 section 4](03-authentication-defenses-and-token-storage.md#4-securely-storing-the-tokens) | [http-anatomy (ch08)](../08-api-fundamentals-and-architecture/labs/http-anatomy/README.md) (HttpOnly session cookie) |
| [CASP 3] Cookies | [03 cookies](03-authentication-defenses-and-token-storage.md#cookies) | cookie labs in [chapter 14](../14-api-defenses-data-security-and-headers/README.md) |
| [CASP 3] Local Storage and Session Storage | [03 local storage and session storage](03-authentication-defenses-and-token-storage.md#local-storage-and-session-storage) | n/a (concept) |
| [CASP 3] Token Storage and XSS | [03 token storage and XSS](03-authentication-defenses-and-token-storage.md#token-storage-and-xss); XSS labs in chapters [12](../12-input-validation-and-injection/README.md) and [13](../13-owasp-api-top-10-and-other-threats/README.md) | n/a here |
| [CASP 3] Rate Limiting | [03 section 5](03-authentication-defenses-and-token-storage.md#5-rate-limiting) | [weak-password-login](labs/weak-password-login/README.md) (token bucket) |
| [CASP 3] CAPTCHA | [03 section 6](03-authentication-defenses-and-token-storage.md#6-captcha) (design and trade-offs only, no bypass) | n/a (by design) |
| [CASP 3] Talking To An API Using OAuth and JWT | [01 section 11](01-authentication-types.md#11-talking-to-an-api-using-oauth-and-jwt); [real-tools/auth-testing-tools.md](real-tools/auth-testing-tools.md) | [auth-methods](labs/auth-methods/README.md) (`/oauth/token` + `/bearer`) |
| [CASP 3] Talking To An API Using HTTP Basic and API Keys | [01 section 10](01-authentication-types.md#10-talking-to-an-api-using-http-basic-and-api-keys) | [auth-methods](labs/auth-methods/README.md) (`/basic`, `/apikey`) |
| [CASP 3] Exploiting Broken Authentication With SQL Injection | [02 section 7](02-authentication-attacks.md#7-exploiting-broken-authentication-with-sql-injection) | [sqli-auth-bypass](labs/sqli-auth-bypass/README.md) |
| [CASP 3] Exploiting Broken Authentication With Weak Passwords | [02 section 2](02-authentication-attacks.md#2-brute-force) | [weak-password-login](labs/weak-password-login/README.md) |
| [CASP 3] Cracking Weak Password Hashes With Dictionaries | [02 section 5](02-authentication-attacks.md#5-cracking-weak-password-hashes-with-dictionaries) | [password-hash-cracking](labs/password-hash-cracking/README.md) |
| [CASP 3] Cracking Weak Password Hashes With Bruteforce And Combinations | [02 section 6](02-authentication-attacks.md#6-cracking-weak-password-hashes-with-brute-force-and-combinations) | [password-hash-cracking](labs/password-hash-cracking/README.md) (4-char cap) |
| [CASP 3] Abusing JWT Tokens | [02 section 10](02-authentication-attacks.md#10-insecure-jwt-validation-and-abusing-jwt-tokens); [real-tools/auth-testing-tools.md](real-tools/auth-testing-tools.md) | [jwt-attacks](labs/jwt-attacks/README.md) |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| Password rules with complexity and rotation | **NIST SP 800-63B-4** (final 2025): length over complexity (at least 15 characters when single-factor, 8 with MFA), no composition rules, no periodic rotation, breached-password blocklists. |
| Password hashing (MD5/SHA "with salt") | OWASP Password Storage Cheat Sheet: **Argon2id** first, then scrypt, bcrypt (72-byte limit), or PBKDF2-HMAC-SHA256 at about **600,000** iterations for FIPS. |
| OAuth 2.0 implicit and password grants as options | **RFC 9700** (OAuth 2.0 Security BCP, Jan 2025) and the **OAuth 2.1 draft** remove them; PKCE (S256) for every code flow; exact redirect-URI matching; no tokens in query strings. |
| JWT "best practice" from blog posts | **RFC 8725** (JWT BCP) and **RFC 9068** (JWT access-token profile). Sender-constrained tokens: **DPoP (RFC 9449)**, **mTLS (RFC 8705)**. |
| MFA = SMS OTP | **Passkeys / WebAuthn** are the phishing-resistant default; SMS is the weakest option; push needs number matching (push fatigue). |
| Tokens in `localStorage` for SPAs | Prefer a **BFF** with an `__Host-` HttpOnly, Secure, SameSite cookie, or in-memory tokens with short lifetimes. Chromium defaults cookies to `SameSite=Lax`. |
| CAPTCHA as a brute-force defense | reCAPTCHA v3, hCaptcha, Cloudflare Turnstile are friction signals; AI and solver farms defeat many; accessibility cost. Use with rate limits and risk scoring, never alone. |
| OWASP API2:2019 "Broken User Authentication" | **API2:2023 Broken Authentication.** |

## How the three courses overlap here

- **CASP 3 only** owns this chapter. The Security Champion course's OWASP Top 10 "Identification and Authentication Failures" (A07:2021, **A07:2025 Authentication Failures**) is introduced in [chapter 01](../01-security-champions-and-appsec-basics/README.md) and taught in depth here.
- OAuth **flows**, token types and JWT forging for **privilege escalation** belong to authorization ([chapter 11](../11-api-authorization-and-oauth/README.md)); this chapter covers tokens as **authentication** and points there.
- Password **storage** implementation (pepper, upgrade-on-login) and cookie/CSP labs are in [chapter 14](../14-api-defenses-data-security-and-headers/README.md); this chapter shows why weak storage fails.
- The repo's [MCP authentication lesson](../../04-mcp-security/authentication/README.md) applies the same OAuth 2.1 rules to MCP servers.

## Learning order

1. [Lesson 01](01-authentication-types.md), then the [auth-methods lab](labs/auth-methods/README.md). About 2.5 hours.
2. [Lesson 02 sections 1 to 7](02-authentication-attacks.md), then the [sqli-auth-bypass](labs/sqli-auth-bypass/README.md), [weak-password-login](labs/weak-password-login/README.md) and [password-hash-cracking](labs/password-hash-cracking/README.md) labs. About 3 hours.
3. [Lesson 02 sections 8 to 10](02-authentication-attacks.md#8-password-reset-workflows), then the [password-reset-workflow](labs/password-reset-workflow/README.md), [oidc-config-check](labs/oidc-config-check/README.md) and [jwt-attacks](labs/jwt-attacks/README.md) labs. About 3 hours.
4. [Lesson 03](03-authentication-defenses-and-token-storage.md) and the [real-tools guide](real-tools/auth-testing-tools.md). About 2 hours.

## Lab index

All labs run offline: `.venv/Scripts/python -m pytest appsec-course/10-api-authentication -q -p no:cacheprovider`.

| Lab | Course items | Tests |
|---|---|---|
| [auth-methods](labs/auth-methods/README.md) | Talking to an API using HTTP Basic and API keys; using OAuth and JWT; types of authentication (incl. simulated mTLS) | 9 |
| [jwt-attacks](labs/jwt-attacks/README.md) | Abusing JWT tokens; insecure JWT validation | 8 |
| [sqli-auth-bypass](labs/sqli-auth-bypass/README.md) | Exploiting broken authentication with SQL injection | 6 |
| [weak-password-login](labs/weak-password-login/README.md) | Exploiting broken authentication with weak passwords; brute force; account lockouts; rate limiting | 5 |
| [password-hash-cracking](labs/password-hash-cracking/README.md) | Cracking weak password hashes with dictionaries, brute force and combinations; weak password storage | 9 |
| [password-reset-workflow](labs/password-reset-workflow/README.md) | Password reset workflows; secure authentication workflows | 7 |
| [oidc-config-check](labs/oidc-config-check/README.md) | Insecure OpenID Connect configuration; OIDC authentication | 7 |

Hedged guide for real tools (curl, Postman OAuth, Burp JWT extensions, jwt_tool, sqlmap, ffuf, hashcat, John the Ripper): [real-tools/auth-testing-tools.md](real-tools/auth-testing-tools.md).

## Exam tips

- **Base64 is not encryption:** Basic auth and JWT payloads are readable by anyone.
- **API keys identify applications, not users;** keep them out of URLs.
- **JWT checklist:** allowlisted alg, verified signature, `exp`, `aud`, `iss`, `kid` from a fixed set, no `jku`/`x5u` trust.
- **ID token is for the client; access token is for the API.**
- **Lockout trade-off:** stops single-account guessing, enables DoS, misses spraying. Combine per-account, per-IP and global limits.
- **Salt defeats precomputation; slow hashes defeat guessing speed.** Name Argon2id, scrypt, bcrypt, PBKDF2 (about 600k iterations).
- **Reset tokens:** random, hashed at rest, short-lived, single use, link from config not from `Host`.
- **HttpOnly stops token theft, not XSS.** Prevent XSS too.
- **CAPTCHA is a friction signal,** never the only control.
- **NIST 800-63B-4:** length, blocklists, no forced rotation or composition rules.

## Interview / exam questions

<details>
<summary>1. Compare API keys, HTTP Basic and OAuth bearer tokens.</summary>

API keys are static secrets identifying an application, simple but long-lived and with no user context. Basic sends a username and password (base64) on every request, so it needs TLS and offers no expiry or MFA. OAuth bearer tokens are short-lived, scoped, issued by an authorization server, can carry user and client identity, and can be revoked or sender-constrained.
</details>

<details>
<summary>2. What are the three parts of a JWT, and is the payload confidential?</summary>

Header (alg, typ, kid), payload (claims such as iss, sub, aud, exp), signature; each base64url-encoded and joined with dots. The payload is only encoded, not encrypted, so anyone holding the token can read it. Use JWE if confidentiality is needed, and keep claims minimal.
</details>

<details>
<summary>3. List five JWT validation mistakes and their fixes.</summary>

Accepting `alg: none` (allowlist algorithms); weak HMAC secret (256-bit random or asymmetric keys); RS256-to-HS256 confusion (bind each key to one algorithm); `kid` traversal or injection (fixed key set); not checking `exp`/`aud`/`iss` (require them); trusting `jku`/`x5u` (ignore or pin); decoding without verifying (use the library's verify).
</details>

<details>
<summary>4. What is the difference between OAuth 2.0 and OpenID Connect?</summary>

OAuth 2.0 is delegated authorization: it lets a client obtain an access token to call an API on a user's behalf. OIDC is an identity layer on top that adds the ID token (a JWT about the authenticated user), the UserInfo endpoint and discovery, so a client can log users in.
</details>

<details>
<summary>5. Name four insecure OIDC configurations you can spot in a discovery document.</summary>

Implicit or hybrid response types; the password (ROPC) grant; no PKCE or only `plain`; `none` or HS* in ID-token algorithms; HTTP endpoints; issuer mismatch; a JWKS URI on an unexpected host.
</details>

<details>
<summary>6. How does mutual TLS authenticate a client, and what is the common deployment mistake?</summary>

The client presents a certificate in the TLS handshake and proves possession of the private key; the server validates it against a trusted CA. The common mistake is terminating TLS at a proxy that forwards the certificate in a header, while the back end also accepts that header directly from clients, letting anyone claim any identity.
</details>

<details>
<summary>7. What are the classic SAML vulnerabilities?</summary>

XML Signature Wrapping (the signed element differs from the one the app reads), XXE in the XML parser, comment injection in NameID, and missing checks of Audience, Recipient, validity window and InResponseTo (replay). Use a maintained library and strict validation.
</details>

<details>
<summary>8. Explain brute force, password spraying and credential stuffing, and one defense for each.</summary>

Brute force: many passwords on one account (per-account limits, MFA). Spraying: one common password on many accounts (global failure-rate detection, breached-password blocklists, MFA). Credential stuffing: leaked pairs from other sites (breached-credential checks, MFA, device/risk scoring, rate limits).
</details>

<details>
<summary>9. What are the downsides of account lockout and what do you use instead or alongside?</summary>

Attackers can lock out users deliberately (DoS), lockout messages can reveal accounts, and spraying stays below thresholds. Use progressive delays, temporary locks with self-service unlock, per-IP and global rate limits, MFA, risk scoring and alerting.
</details>

<details>
<summary>10. Why are unsalted MD5 password hashes dangerous, and what should be used?</summary>

They are extremely fast to compute, identical passwords share hashes, and precomputed tables work, so dictionaries, masks and combinations crack most of them quickly. Use Argon2id (or scrypt, bcrypt, PBKDF2-HMAC-SHA256 at about 600k iterations) with a unique salt per password and optionally a pepper.
</details>

<details>
<summary>11. List the security requirements for a password reset token.</summary>

Generated by a CSPRNG with enough entropy, stored only as a hash, short expiry, single use, revoking other outstanding tokens, sent only to the registered channel, with links built from configuration (not the Host header), uniform responses, rate limiting, and notification plus session invalidation after reset.
</details>

<details>
<summary>12. Where should a browser single-page app keep its tokens?</summary>

Preferably nowhere in the browser: use a backend-for-frontend that holds tokens server-side and gives the browser an `__Host-` HttpOnly, Secure, SameSite cookie. Otherwise keep a short-lived access token in memory and use rotating refresh tokens; avoid localStorage, which any XSS can read.
</details>

<details>
<summary>13. Does an HttpOnly cookie protect you from XSS?</summary>

Partly. It stops scripts from reading and exfiltrating the cookie, so the attacker cannot reuse it elsewhere. But injected script can still send requests from the victim's browser with the cookie attached while the page is open. You still need XSS prevention (encoding, CSP, Trusted Types) and CSRF protection for cookie-authenticated APIs.
</details>

<details>
<summary>14. What does NIST SP 800-63B-4 say about passwords and MFA?</summary>

Length matters most (at least 15 characters if single-factor, 8 with MFA; allow long passphrases), no composition rules, no periodic forced changes, check against breached/common lists, allow paste and password managers, limit failed attempts. Prefer phishing-resistant authenticators such as passkeys; SMS OTP is restricted. Verify the details at NIST.
</details>

<details>
<summary>15. When is a CAPTCHA appropriate and what are its limits?</summary>

As an adaptive friction step on public sign-up, login after several failures or reset requests. Limits: accessibility barriers, privacy and friction, AI solvers and solver farms, and it cannot protect pure machine APIs. Always verify it server-side and combine it with rate limits, risk scoring and MFA.
</details>

## References

- OWASP API Security Top 10 2023 (API2 Broken Authentication); OWASP Authentication, Password Storage, Forgot Password, JSON Web Token and Session Management Cheat Sheets.
- NIST SP 800-63B-4 (Digital Identity Guidelines: Authentication; verify final text).
- RFC 7617 (Basic), RFC 7519 (JWT), RFC 8725 (JWT BCP), RFC 9068 (JWT access tokens), RFC 9700 (OAuth 2.0 Security BCP), RFC 7636 (PKCE), RFC 8705 (OAuth mTLS), RFC 9449 (DPoP), OAuth 2.1 draft, OpenID Connect Core and Discovery.
- W3C WebAuthn and FIDO Alliance passkey documentation; OAuth 2.0 for Browser-Based Apps (IETF draft, BFF pattern).
- Repo: [MCP authentication](../../04-mcp-security/authentication/README.md), [cmcpse ch4 authentication and authorization](../../cmcpse-course/ch4-defending-and-hardening-mcp-servers/02-authentication-and-authorization.md), [cybersecurity-track web testing](../../cybersecurity-track/09-pentesting-fundamentals/03-web-app-testing-and-burp.md).

**Next chapter:** [Chapter 11: API authorization and OAuth](../11-api-authorization-and-oauth/README.md).
