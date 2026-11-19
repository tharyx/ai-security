# Lesson 02: Authentication Attacks

**Syllabus items covered:** "Authentication Attacks", "Brute Force", "Weak Password Storage", "Password Reset Workflows", "Account Lockouts", "Insecure OpenID Connect Configuration", "Insecure JWTs Validation", "Exploiting Broken Authentication With SQL Injection", "Exploiting Broken Authentication With Weak Passwords", "Cracking Weak Password Hashes With Dictionaries", "Cracking Weak Password Hashes With Bruteforce And Combinations", "Abusing JWT Tokens" ([CASP 3]).

**Time:** 3 hours with the labs. **Labs:** [sqli-auth-bypass](labs/sqli-auth-bypass/README.md), [weak-password-login](labs/weak-password-login/README.md), [password-hash-cracking](labs/password-hash-cracking/README.md), [password-reset-workflow](labs/password-reset-workflow/README.md), [oidc-config-check](labs/oidc-config-check/README.md), [jwt-attacks](labs/jwt-attacks/README.md).

> **Safety.** Every attack here runs against the lab's own toy code, with lab-generated hashes and tiny word lists. Only test systems you own or have written permission to test. Password guessing against real services, even "just to check", is illegal without authorization and can lock out real users.

## 1. Authentication attacks: the map

| Attack | Target | OWASP mapping (verify) |
|---|---|---|
| Online brute force, password spraying, credential stuffing | login, OTP, API key endpoints | API2:2023 Broken Authentication; API4 Unrestricted Resource Consumption |
| Offline cracking of stolen hashes | the password database | A04:2025 Cryptographic Failures (A02:2021) |
| Injection into the login query | the authentication code | A05:2025 Injection (A03:2021) |
| Password reset abuse | the recovery flow | API2:2023; A07:2025 Authentication Failures |
| Lockout abuse | availability of accounts | API2/API4 |
| OIDC/OAuth misconfiguration | the identity provider and clients | API2:2023; A07 |
| JWT validation flaws | every API that accepts tokens | API2:2023; A07; RFC 8725 |

## 2. Brute force

| Variant | What the attacker does | Why it works |
|---|---|---|
| **Classic brute force** | many passwords against one account | no throttle, short or common passwords |
| **Dictionary attack** | a list of likely passwords | people choose common passwords |
| **Password spraying** | one or two common passwords against **many** accounts | stays under per-account lockout thresholds |
| **Credential stuffing** | username/password pairs leaked from other sites | password reuse |
| **OTP brute force** | all 10⁶ codes of a 6-digit OTP | no attempt limit on the OTP endpoint |
| **API key / token guessing** | short or predictable keys | weak generation |

APIs make all of these easy: no CAPTCHA screen, simple JSON requests, sometimes batching (GraphQL aliases let one HTTP request try 100 passwords; see [chapter 12](../12-input-validation-and-injection/README.md)).

**Exploiting broken authentication with weak passwords.** The [weak-password-login lab](labs/weak-password-login/README.md) runs a 10-word dictionary against an account whose password is `p@ssw0rd`. With no throttle the password falls on try 10. With a lockout after 5 failures, or a per-IP token-bucket rate limit, the same run is stopped at try 5 or 4.

## 3. Account lockouts

Lockout (block an account after N failures) stops single-account guessing but has costs:

| Problem | Explanation | Better approach |
|---|---|---|
| **Denial of service** | an attacker locks out every user (or the CEO) on purpose | temporary, progressive delays (1s, 2s, 4s...) instead of hard locks; unlock by email |
| **Spraying bypasses it** | one guess per account stays below N | per-IP / per-device / global failure rate monitoring, breached-password checks, MFA |
| **Enumeration** | "account locked" reveals the account exists | same message for locked and wrong password |
| **Distributed attackers** | many IPs defeat per-IP limits | risk scoring, bot detection, MFA |

NIST SP 800-63B (rev. 4, final 2025; verify) requires limiting failed attempts (no more than 100 consecutive failures per account) and favours rate limiting and other risk-based controls over long hard lockouts.

## 4. Weak password storage

How passwords should **not** be stored, from worst to bad:

1. **Plaintext** or **reversible encryption**: one breach exposes everything.
2. **Unsalted fast hashes** (MD5, SHA-1, even SHA-256): identical passwords give identical hashes (reuse is visible), precomputed tables (rainbow tables) work, and GPUs try billions of guesses per second.
3. **Salted fast hashes**: salts defeat precomputation, but each guess is still cheap.

How they **should** be stored (OWASP Password Storage Cheat Sheet; verify parameters): **Argon2id** first; **scrypt**; **bcrypt** (72-byte input limit); **PBKDF2-HMAC-SHA256** with about **600,000 iterations** where FIPS is required. Each has a unique random salt per password, and optionally a **pepper** (a secret kept outside the database, in an HSM or vault). Details and an upgrade-on-login lab are in [chapter 14](../14-api-defenses-data-security-and-headers/README.md).

## 5. Cracking weak password hashes with dictionaries

Given a leaked table of **unsalted** hashes, the attacker hashes each word of a dictionary **once** and looks the result up against **all** users at the same time. The [password-hash-cracking lab](labs/password-hash-cracking/README.md) cracks `sunshine` and `dragon` from a six-word list. Real tools (hashcat, John the Ripper) add rules ("capitalise, add 1, swap a→@") to each word.

## 6. Cracking weak password hashes with brute force and combinations

- **Brute force (mask attack):** try every string from an alphabet up to a length. The keyspace grows exponentially: 26³ = 17,576 for three lowercase letters, 95⁸ ≈ 6.6 × 10¹⁵ for eight printable characters. The lab caps the keyspace at **4 lowercase characters** and cracks `abc` in 731 tries.
- **Combination / hybrid attacks:** word + word (`bluecat`), word + suffix (`summer2024`, `Password1!`). These match how people actually build "complex" passwords. The lab cracks `summer2024` in 4 tries and `bluecat` in 47.
- **Why length beats complexity:** each extra character multiplies the keyspace; forced symbol rules just produce predictable patterns. Hence NIST's guidance on length and blocklists ([lesson 03](03-authentication-defenses-and-token-storage.md#2-strong-password-and-key-validation)).
- **Why slow, salted hashes win:** on the author's laptop the lab measured about 425,000 MD5 guesses per second against about 2.4 PBKDF2-SHA256 (600k iterations) guesses per second: roughly a 175,000× slowdown, and the salt forces the work per user. (Your numbers will differ; GPUs change the absolute values, not the conclusion.)

## 7. Exploiting broken authentication with SQL injection

If the login builds SQL by concatenating input:

```sql
SELECT username, role FROM users WHERE username = '<input>' AND pw_hash = '<hash>'
```

then the username `admin' -- ` turns the rest of the line into a comment and logs in as admin without a password, and `' OR '1'='1' -- ` logs in as the first user in the table. The [sqli-auth-bypass lab](labs/sqli-auth-bypass/README.md) shows both on a real sqlite3 database, and that the **bound-parameter** version (Oracle bind variables: `WHERE username = :1`) treats the same input as plain data. Injection in depth, including automated tools such as sqlmap, is [chapter 12](../12-input-validation-and-injection/README.md).

## 8. Password reset workflows

The reset flow is a second login door, often weaker than the first:

| Flaw | Example | Fix |
|---|---|---|
| Predictable token | `md5(username + time)`, sequential numbers | 32 random bytes from a CSPRNG |
| No expiry / reusable token | the link works forever and many times | 15–60 minute expiry, single use, revoke others on success |
| Token stored in plaintext | DB leak = account takeover | store only a hash of the token |
| **Host header poisoning** | link built from the request's `Host`, so the victim's email points to the attacker's domain | build links from a configured base URL |
| Enumeration | "unknown email" vs "link sent" | one uniform message |
| Token in the response or URL leakage | the API returns the token; the reset page loads third-party scripts with the token in the URL (Referer) | send only by email; `Referrer-Policy: no-referrer`; move the token out of the URL after load |
| Weak security questions | "mother's maiden name" | do not use them; use email/SMS/passkey recovery plus notifications |
| No re-authentication / no notification | silent takeover | notify on reset, invalidate sessions, re-check MFA |

The [password-reset-workflow lab](labs/password-reset-workflow/README.md) demonstrates a predictable token, reuse ten days later, host-header poisoning and enumeration, then the fixed version.

## 9. Insecure OpenID Connect configuration

Common OIDC/OAuth problems you can spot in a discovery document or client config:

- **Implicit flow** (`response_type=token` / `id_token token`): tokens in the URL fragment, exposed to browser history, logs and scripts. Removed in OAuth 2.1 and discouraged by RFC 9700.
- **Resource Owner Password Credentials** grant: the app handles the user's password. Removed in OAuth 2.1.
- **No PKCE**, or only `plain`: authorization codes can be intercepted and redeemed. Require **S256**.
- **`none` or HS* in `id_token_signing_alg_values_supported`**.
- **Issuer mismatch**, **HTTP endpoints**, a **JWKS URI on another host** (verify ownership).
- Client-side mistakes: not checking `nonce` (replay), `aud` (a token for another app accepted), `iss`; loose **redirect URI** matching (open redirect → code theft); missing `state` (CSRF on login); using the ID token to call APIs.

The [oidc-config-check lab](labs/oidc-config-check/README.md) flags 11 issues in an insecure discovery JSON and zero in a hardened one, and validates ID-token claims. Flows and redirect-URI attacks are taught hands-on in [chapter 11](../11-api-authorization-and-oauth/README.md).

## 10. Insecure JWT validation and abusing JWT tokens

| Attack | How | Defense |
|---|---|---|
| **Signature not verified** | the API only base64-decodes the payload | always verify; use a maintained library's verify function, not "decode" |
| **`alg: none`** | attacker sets `alg` to `none` and drops the signature | allowlist the algorithm per key; reject `none` |
| **Weak HMAC secret** | crack `secret123` offline from one token, then forge any claims | ≥ 256-bit random secret, or asymmetric keys |
| **RS256 → HS256 key confusion** | attacker signs with HMAC using the server's **public** key as the secret; a naive library verifies with that same key | bind each key to one algorithm; never let the token pick |
| **`kid` injection / path traversal** | `kid: "../../public/known-file"` or SQL in `kid` selects an attacker-known key | look up `kid` only in a fixed key set |
| **`jku` / `x5u` abuse** | header points to an attacker-hosted JWKS | ignore these headers or pin allowed URLs |
| **Missing `exp`, `aud`, `iss` checks** | old tokens, tokens for another API, tokens from another issuer accepted | require and check them |
| **Sensitive data in claims** | the payload is readable by anyone | keep claims minimal |
| **Long-lived tokens, no revocation** | a stolen token works for days | short lifetime, refresh-token rotation, sender-constrained tokens (DPoP, mTLS) |

The [jwt-attacks lab](labs/jwt-attacks/README.md) implements HS256 from the standard library and demonstrates `alg: none`, weak-secret cracking from a six-word list, missing/expired `exp`, wrong `aud` and `kid` traversal against a naive verifier, then shows the hardened verifier rejecting each. Forging JWTs **for privilege escalation** (changing `role`) continues in [chapter 11](../11-api-authorization-and-oauth/README.md).

## 11. Scenario: three small bugs, one takeover

A fitness app's API: (1) the login says "no such email" for unknown users; (2) there is no rate limit on `/login`; (3) passwords are unsalted SHA-1. An attacker enumerates 40,000 valid emails from a leaked marketing list, sprays `Summer2024!` (one try per account) and gets 300 accounts. A later database leak lets them crack 60% of all hashes offline in a day. **Fixes in priority order:** rate limiting and spraying detection, MFA for sensitive actions, uniform responses, rehash on next login with Argon2id, breached-password checks, and forced resets for cracked accounts.

## 12. Self-check

1. Why does password spraying evade account lockout, and what detects it?
2. Why does a unique salt per password defeat a dictionary attack across all users at once?
3. Explain RS256 → HS256 key confusion in two sentences.

Next: [Lesson 03, authentication defenses and token storage](03-authentication-defenses-and-token-storage.md).
