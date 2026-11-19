# Chapter 14: API Defenses: Data Security and Security Headers

This chapter is the defensive toolbox for APIs. It covers best practices for GraphQL, SOAP and REST; data security (encoding, escaping, hashing, encryption, password storage, service credentials, TLS); browser security headers including CSP and CORS; and rate limiting at an API gateway. Six offline labs turn each topic into code you can test: checklists as code, a toy AEAD for data at rest, password storage with upgrade-on-login, a headers analyzer, a CSP-aware fake browser and a Kong-like gateway.

> **Safety.** Every lab is a simulation: JSON fixtures, in-memory sqlite, a fake browser that never runs JavaScript, and an in-process gateway. Secrets and API keys are FAKE and built at runtime. The toy cipher is labelled NOT FOR PRODUCTION. Only test systems you own or have written permission to test.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Tool status and version numbers are hedged: **verify at the source**.

## Syllabus coverage

Source: **[CASP 7]** API Security course, chapter 7 "Other API Security Defenses". Every line is listed verbatim and in source order.

| Syllabus item | Where to study | Lab |
|---|---|---|
| [CASP 7] GraphQL API Security Best Practices | [Lesson 01 section 2](01-api-style-best-practices.md#2-graphql-api-security-best-practices); attacks in [ch12](../12-input-validation-and-injection/README.md), [ch13](../13-owasp-api-top-10-and-other-threats/README.md) | [api-best-practice-checklists](labs/api-best-practice-checklists/README.md) |
| [CASP 7] SOAP API Security Best Practices | [Lesson 01 section 3](01-api-style-best-practices.md#3-soap-api-security-best-practices) | [api-best-practice-checklists](labs/api-best-practice-checklists/README.md) |
| [CASP 7] REST API Security Best Practices | [Lesson 01 section 4](01-api-style-best-practices.md#4-rest-api-security-best-practices) | [api-best-practice-checklists](labs/api-best-practice-checklists/README.md) |
| [CASP 7] Data Security | [Lesson 02 section 1](02-data-security-and-password-storage.md#1-data-security-in-one-table) (SVG) | [data-security-primitives](labs/data-security-primitives/README.md) |
| [CASP 7] Encoding and Decoding | [Lesson 02 section 2.1](02-data-security-and-password-storage.md#21-encoding-and-decoding) | [data-security-primitives](labs/data-security-primitives/README.md) |
| [CASP 7] Escaping | [Lesson 02 section 2.2](02-data-security-and-password-storage.md#22-escaping); per-context encoding in [ch12](../12-input-validation-and-injection/README.md) | [data-security-primitives](labs/data-security-primitives/README.md) |
| [CASP 7] Hashing | [Lesson 02 section 2.3](02-data-security-and-password-storage.md#23-hashing) | [data-security-primitives](labs/data-security-primitives/README.md) |
| [CASP 7] Encryption and Decryption | [Lesson 02 section 2.4](02-data-security-and-password-storage.md#24-encryption-and-decryption) (AES-GCM explained) | [data-security-primitives](labs/data-security-primitives/README.md) (toy AEAD, NOT FOR PRODUCTION) |
| [CASP 7] Securing Data at Rest Using Encryption | [Lesson 02 section 3](02-data-security-and-password-storage.md#3-securing-data-at-rest-using-encryption) | [data-security-primitives](labs/data-security-primitives/README.md) |
| [CASP 7] Storing Credentials for Service-to-Service Communication | [Lesson 02 section 5](02-data-security-and-password-storage.md#5-storing-credentials-for-service-to-service-communication); [devsecops ch13](../../devsecops-course/13-secrets-management/README.md) | [ch15 vault-secrets-for-apis](../15-implementing-api-security-mechanisms/labs/vault-secrets-for-apis/README.md) |
| [CASP 7] Password Storage and Its Considerations | [Lesson 02 section 4](02-data-security-and-password-storage.md#4-password-storage-and-picking-a-secure-algorithm) | [password-storage](labs/password-storage/README.md) |
| [CASP 7] Picking a Secure Algorithm | [Lesson 02 section 4](02-data-security-and-password-storage.md#4-password-storage-and-picking-a-secure-algorithm) | [password-storage](labs/password-storage/README.md) |
| [CASP 7] Securing Data in Transit Using TLS | [Lesson 02 section 6](02-data-security-and-password-storage.md#6-securing-data-in-transit-using-tls); [devsecops ch06 TLS lesson](../../devsecops-course/06-dynamic-analysis/03-tls-and-server-misconfiguration-testing.md) | [devsecops tls-misconfiguration-checks](../../devsecops-course/06-dynamic-analysis/labs/tls-misconfiguration-checks/README.md) |
| [CASP 7] Rate Limiting Best Practices | [Lesson 04 section 1](04-rate-limiting-and-api-gateways.md#1-rate-limiting-best-practices) | [api-gateway-rate-limiting](labs/api-gateway-rate-limiting/README.md) |
| [CASP 7] Security Headers | [Lesson 03 section 1](03-security-headers-csp-and-cors.md#1-security-headers-at-a-glance) | [security-headers-analyzer](labs/security-headers-analyzer/README.md) |
| [CASP 7] X-XSS-Protection | [Lesson 03 section 2](03-security-headers-csp-and-cors.md#2-x-xss-protection) (deprecated: send `0`) | [security-headers-analyzer](labs/security-headers-analyzer/README.md) |
| [CASP 7] HTTP Strict Transport Security (HSTS) | [Lesson 03 section 3](03-security-headers-csp-and-cors.md#3-http-strict-transport-security-hsts) | [security-headers-analyzer](labs/security-headers-analyzer/README.md) |
| [CASP 7] Cache-Control | [Lesson 03 section 4](03-security-headers-csp-and-cors.md#4-cache-control) | [security-headers-analyzer](labs/security-headers-analyzer/README.md) |
| [CASP 7] X-Frame-Options | [Lesson 03 section 5.1](03-security-headers-csp-and-cors.md#51-x-frame-options) | [security-headers-analyzer](labs/security-headers-analyzer/README.md) |
| [CASP 7] X-Frame-Options vs frame-ancestors | [Lesson 03 section 5.2](03-security-headers-csp-and-cors.md#52-x-frame-options-vs-frame-ancestors) | [security-headers-analyzer](labs/security-headers-analyzer/README.md) |
| [CASP 7] Content Security Policy | [Lesson 03 section 6](03-security-headers-csp-and-cors.md#6-content-security-policy) | [csp-xss-mitigation](labs/csp-xss-mitigation/README.md) |
| [CASP 7] Implementing CSP at Scale | [Lesson 03 section 7](03-security-headers-csp-and-cors.md#7-implementing-csp-at-scale) | [csp-xss-mitigation](labs/csp-xss-mitigation/README.md) (Report-Only build) |
| [CASP 7] Common Misconfigurations While Using CSP | [Lesson 03 section 8](03-security-headers-csp-and-cors.md#8-common-misconfigurations-while-using-csp) | [security-headers-analyzer](labs/security-headers-analyzer/README.md) (CSP evaluator) |
| [CASP 7] Cross-Origin Resource Sharing (CORS) | [Lesson 03 section 9](03-security-headers-csp-and-cors.md#9-cross-origin-resource-sharing-cors); attack lab in [ch13](../13-owasp-api-top-10-and-other-threats/README.md) | [security-headers-analyzer](labs/security-headers-analyzer/README.md) |
| [CASP 7] Cookie Based Implementations | [Lesson 03 section 10.1](03-security-headers-csp-and-cors.md#101-cookie-based-implementations) | [security-headers-analyzer](labs/security-headers-analyzer/README.md) (SameSite model) |
| [CASP 7] Token Based Implementations | [Lesson 03 section 10.2](03-security-headers-csp-and-cors.md#102-token-based-implementations); token storage in [ch10](../10-api-authentication/README.md) | [security-headers-analyzer](labs/security-headers-analyzer/README.md) |
| [CASP 7] Adding Content Security Policy To Mitigate Cross Site Scripting | [Lesson 03 sections 6–7](03-security-headers-csp-and-cors.md#6-content-security-policy) | [csp-xss-mitigation](labs/csp-xss-mitigation/README.md) |
| [CASP 7] Implementing Rate Limiting With API Gateway | [Lesson 04 section 2](04-rate-limiting-and-api-gateways.md#2-implementing-rate-limiting-with-an-api-gateway) (SVG); [real-tools/kong-gateway.md](real-tools/kong-gateway.md) | [api-gateway-rate-limiting](labs/api-gateway-rate-limiting/README.md) |
| [CASP 7] Securing HTTP Headers using Kong Gateway | [Lesson 04 section 4](04-rate-limiting-and-api-gateways.md#4-securing-http-headers-using-kong-gateway); [real-tools/kong-gateway.md](real-tools/kong-gateway.md) | [api-gateway-rate-limiting](labs/api-gateway-rate-limiting/README.md) (response-transformer) |
| [CASP 7] Implementing Rate Limiting using API Key | [Lesson 04 section 3](04-rate-limiting-and-api-gateways.md#3-implementing-rate-limiting-using-api-key) | [api-gateway-rate-limiting](labs/api-gateway-rate-limiting/README.md) (per-key buckets) |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| **X-XSS-Protection** as a header to enable | **Deprecated.** Browsers removed the XSS Auditor, and the filter could be abused. Send `X-XSS-Protection: 0` or omit it; rely on CSP and output encoding. |
| **X-Frame-Options** | Superseded by CSP **`frame-ancestors`**. `ALLOW-FROM` is obsolete. Keep `XFO: DENY` only for very old browsers. |
| CSP with host allowlists | Current guidance is **strict CSP**: nonces or hashes plus `'strict-dynamic'`, `object-src 'none'`, `base-uri 'none'`, and **Trusted Types** where supported. Reporting uses `report-to` and the Reporting API; `report-uri` is legacy. |
| Password hashing "pick a secure algorithm" | OWASP order: **Argon2id**, scrypt, bcrypt (72-byte limit), **PBKDF2-HMAC-SHA256 with about 600,000 iterations** for FIPS. NIST **SP 800-63B-4** (2025): length over complexity, blocklists, no forced rotation. |
| Token storage in localStorage | Prefer a **BFF** with `__Host-` HttpOnly SameSite cookies for SPAs; sender-constrained tokens (**DPoP**, RFC 9449) for public clients. |
| **Kong Gateway** OSS | Check Kong's current OSS/Enterprise packaging and licence before relying on an image. Alternatives: Apache APISIX, Envoy Gateway, NGINX, Tyk, cloud gateways. WAF: ModSecurity is now an OWASP project with the OWASP CRS; Coraza is a Go alternative. |
| Static service-to-service passwords | **Workload identity** (SPIFFE/SPIRE, cloud IAM roles, mTLS) and dynamic secrets beat stored credentials. Vault is BSL-licensed; **OpenBao** is the open-source fork. |
| TLS "SSL" | TLS 1.3 preferred, 1.2 minimum; SSLv3/TLS 1.0/1.1 disabled. |

## How the three courses overlap here

- **CASP 7 only** owns this chapter. Security Champion touches output encoding and ASVS in [chapter 02](../02-secure-code-review-and-asvs/README.md); this chapter does not repeat the review checklists.
- **Attack** views of the same topics are in [chapter 12](../12-input-validation-and-injection/README.md) (CSP and Trusted Types, GraphQL attacks) and [chapter 13](../13-owasp-api-top-10-and-other-threats/README.md) (CORS, caching, SOAP, XSS to privilege escalation). Token storage is in [chapter 10](../10-api-authentication/README.md).
- **Implementation** follow-ups (permissions, throttling at every layer, Vault, TLS, logging) are in [chapter 15](../15-implementing-api-security-mechanisms/README.md).
- The repo's [devsecops ch06](../../devsecops-course/06-dynamic-analysis/README.md) already teaches TLS testing, and [devsecops ch13](../../devsecops-course/13-secrets-management/README.md) teaches secret stores; this chapter links to them.

## Learning order

1. [Lesson 01](01-api-style-best-practices.md), then the [api-best-practice-checklists lab](labs/api-best-practice-checklists/README.md). About 2 hours.
2. [Lesson 02](02-data-security-and-password-storage.md), then the [data-security-primitives](labs/data-security-primitives/README.md) and [password-storage](labs/password-storage/README.md) labs. About 3.5 hours.
3. [Lesson 03](03-security-headers-csp-and-cors.md), then the [security-headers-analyzer](labs/security-headers-analyzer/README.md) and [csp-xss-mitigation](labs/csp-xss-mitigation/README.md) labs. About 3.5 hours.
4. [Lesson 04](04-rate-limiting-and-api-gateways.md), the [api-gateway-rate-limiting lab](labs/api-gateway-rate-limiting/README.md) and [real-tools/kong-gateway.md](real-tools/kong-gateway.md). About 2.5 hours.

## Lab index

All labs run offline: `.venv/Scripts/python -m pytest appsec-course/14-api-defenses-data-security-and-headers -q -p no:cacheprovider`.

| Lab | Course exercise | Tests |
|---|---|---|
| [api-best-practice-checklists](labs/api-best-practice-checklists/README.md) | GraphQL/SOAP/REST best practices as code | 8 |
| [data-security-primitives](labs/data-security-primitives/README.md) | Encoding, escaping, hashing, encryption; data at rest | 10 |
| [password-storage](labs/password-storage/README.md) | Password storage, picking a secure algorithm | 8 |
| [security-headers-analyzer](labs/security-headers-analyzer/README.md) | Security headers, CSP misconfigurations, CORS, cookies vs tokens | 10 |
| [csp-xss-mitigation](labs/csp-xss-mitigation/README.md) | Adding Content Security Policy To Mitigate Cross Site Scripting | 9 |
| [api-gateway-rate-limiting](labs/api-gateway-rate-limiting/README.md) | Rate limiting with an API gateway and per API key; securing headers with Kong | 10 |

Hedged real-tool guide: [Kong Gateway](real-tools/kong-gateway.md).

## Exam tips

- **Encoding ≠ encryption.** Base64 needs no key. Say it in the first sentence of your answer.
- **Escaping depends on the context;** for SQL say "prepared statements / bind variables".
- **Passwords:** "Argon2id, salt per user, optional pepper in a secret manager, self-describing format, upgrade on login".
- **X-XSS-Protection: 0.** If a question expects `1; mode=block`, explain the deprecation.
- **frame-ancestors beats X-Frame-Options;** it allows multiple origins and wins when both are present.
- **Strict CSP:** nonce per response + `'strict-dynamic'` + `object-src 'none'` + `base-uri 'none'`; roll out with Report-Only.
- **CORS is not CSRF protection.** Reflected origin + credentials = critical.
- **Gateway for coarse controls, app for business rules.** 429 + `Retry-After`; API keys identify apps, not users.

## Interview / exam questions

<details>
<summary>1. What is the difference between encoding, escaping, hashing and encryption?</summary>

Encoding changes the representation (base64, URL) and needs no key. Escaping makes data inert for one interpreter (HTML, JS). Hashing is a one-way fingerprint (with a key, HMAC gives authenticity). Encryption makes data confidential and is reversible only with the key; AEAD also detects tampering.
</details>

<details>
<summary>2. Name five GraphQL-specific security controls.</summary>

Introspection off in production, field suggestions off, depth and cost limits, alias and batching limits, per-resolver authorization, persisted queries, masked errors, timeouts.
</details>

<details>
<summary>3. What is XML Signature Wrapping and how do you prevent it?</summary>

The attacker moves the signed element elsewhere in the document and inserts an unsigned element where the application looks. The signature still verifies, but the app processes the unsigned copy. Prevent it by resolving the signed element by its ID and processing exactly that node, plus strict schema validation.
</details>

<details>
<summary>4. Why is a plain SHA-256 of a phone number not anonymization?</summary>

The input space is small (10^10), so an attacker hashes every possible number and matches. Use an HMAC with a secret key (pseudonymization) or tokenization.
</details>

<details>
<summary>5. What does AEAD give you, and what is the danger with AES-GCM nonces?</summary>

Confidentiality plus integrity and authenticity, including of associated data (for example the row id). Reusing a nonce with the same key breaks confidentiality and lets an attacker forge tags. Use random 96-bit nonces with limits on messages per key, or a library that manages nonces.
</details>

<details>
<summary>6. Rank the password hashing algorithms OWASP recommends.</summary>

Argon2id, then scrypt, then bcrypt (beware the 72-byte input limit), then PBKDF2-HMAC-SHA256 with about 600,000 iterations where FIPS is required. Never MD5, SHA-1 or a single fast hash.
</details>

<details>
<summary>7. What is a pepper, and where is it stored?</summary>

A secret key applied (usually by HMAC) before or after hashing, the same for all users. It is stored outside the database, in a secret manager or HSM, so a database-only leak cannot be cracked.
</details>

<details>
<summary>8. How do you migrate a database of MD5 password hashes?</summary>

Store hashes in a self-describing format. On each successful login, verify against MD5, then re-hash with the modern algorithm and replace the stored value. Optionally wrap all old hashes immediately (`argon2(md5(pw))`) and force resets for accounts that never log in.
</details>

<details>
<summary>9. How should one microservice authenticate to another?</summary>

Best: workload identity with short-lived credentials (mTLS with SPIFFE IDs, cloud IAM roles, OAuth client credentials). Next: dynamic secrets from a secret manager. At minimum: static secrets in a secret manager with least privilege and rotation. Never in code, images or CI logs.
</details>

<details>
<summary>10. Why should X-XSS-Protection be set to 0?</summary>

The XSS Auditor it controlled was removed from browsers, and while it existed it could be abused to disable legitimate scripts or leak information. CSP and output encoding are the real defenses.
</details>

<details>
<summary>11. Compare X-Frame-Options and CSP frame-ancestors.</summary>

Both stop framing (clickjacking). `frame-ancestors` supports multiple origins, is part of the CSP standard and takes precedence. XFO supports only DENY/SAMEORIGIN in practice; `ALLOW-FROM` is obsolete. Neither works from a `<meta>` tag.
</details>

<details>
<summary>12. Write a strict CSP and name three common CSP mistakes.</summary>

`script-src 'nonce-{random}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; report-to csp`. Mistakes: `'unsafe-inline'` without a nonce, wildcards or `https:` in script-src, allowlisting CDNs with JSONP/AngularJS gadgets, static nonces, missing `object-src`/`base-uri`, leaving it Report-Only forever.
</details>

<details>
<summary>13. What is the classic CORS misconfiguration and its impact?</summary>

Reflecting the request's `Origin` into `Access-Control-Allow-Origin` together with `Access-Control-Allow-Credentials: true` (or trusting `null` or an unanchored regex). Any website the victim visits can read authenticated API responses. Fix: an exact allowlist of full origins and `Vary: Origin`.
</details>

<details>
<summary>14. Cookie-based vs token-based sessions for a SPA: trade-offs?</summary>

Cookies (HttpOnly, Secure, SameSite, `__Host-`) cannot be read by XSS but are sent automatically, so CSRF must be handled. Bearer tokens are not sent automatically (no CSRF) but must be stored where JavaScript can reach them, so XSS can steal them. Current guidance favours a BFF that keeps tokens server-side and gives the browser only a hardened cookie.
</details>

<details>
<summary>15. What should rate limiting look like for a login endpoint behind a gateway?</summary>

A tight per-IP limit at the gateway, a per-account limit or progressive delay in the app, 429 with Retry-After, shared counters across nodes, alerts on 401/429 spikes, and MFA. A per-IP limit alone fails against botnets and password spraying.
</details>

## References

- OWASP cheat sheets: GraphQL, XXE Prevention, Web Service Security, REST Security, Cryptographic Storage, Password Storage, Secrets Management, TLS, HTTP Headers, Content Security Policy, Clickjacking Defense, CSRF Prevention.
- OWASP API Security Top 10 2023; OWASP ASVS 5.0 (verify chapter numbers).
- NIST SP 800-63B-4; NIST SP 800-38D; RFC 8446 (TLS 1.3); RFC 6797 (HSTS); RFC 9449 (DPoP); W3C CSP Level 3; MDN header pages.
- Kong Gateway docs (rate-limiting, key-auth, response-transformer, cors, decK).
- Repo: [devsecops ch06 TLS](../../devsecops-course/06-dynamic-analysis/03-tls-and-server-misconfiguration-testing.md), [devsecops ch13 secrets](../../devsecops-course/13-secrets-management/README.md), [secure AI gateway](../../09-enterprise-architecture/06-secure-llm-ai-gateway.md).

**Next chapter:** [Chapter 15: Implementing API Security Mechanisms](../15-implementing-api-security-mechanisms/README.md)
