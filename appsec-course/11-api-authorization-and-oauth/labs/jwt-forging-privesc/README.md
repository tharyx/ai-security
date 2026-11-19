# Lab: Forging JWT tokens for privilege escalation

**Course exercise:** "Forging JWT Tokens For Privilege Escalation". Lesson: [02 section 6](../../02-authorization-attacks-and-defenses.md#6-forging-jwts-for-privilege-escalation). JWT structure and the basic attacks are taught in [chapter 10](../../../10-api-authentication/README.md); this lab focuses on turning a forged token into **admin access**.

**Time:** 45 minutes. **Tests:** 8, all offline. **Safety:** a tiny HS256 helper written with `hmac`, `hashlib` and `base64` (no PyJWT). The weak key comes from an 8-word list of lab passwords; the strong key is random bytes made at runtime. Nothing is a real credential. Only test systems you own or have written permission to test.

## Goal

Take a normal user's token, become admin on the vulnerable API in two different ways, and show that the hardened API resists both and even ignores a correctly signed fake role.

## Concept

The vulnerable API makes four mistakes:

1. It reads `alg` from the token, so `"alg": "none"` (no signature) is accepted.
2. Its HMAC key is a dictionary word, so one captured token is enough to recover it offline.
3. It takes the user's **role from the token** and trusts it for authorization.
4. It never checks `exp`, `iss` or `aud`.

The secure API pins `alg` to HS256, uses a 256-bit random key, checks `iss`, `aud` and `exp` (RFC 8725 JWT BCP, RFC 9068 access-token profile) and looks the role up in **its own user table**. Even an insider who has the signing key cannot become admin by adding `"role": "admin"`.

## Steps

1. Run the demo. Note that `re-sign with sub=u-carol` fails on the vulnerable API: it reads the role from the token, not from the user. Which claim would you change instead?
2. In [jwt_privesc.py](jwt_privesc.py), change the vulnerable key to a 32-byte random value. Which attack still works?
3. Remove the `alg != "HS256"` check in `SecureAPI.verify`. Does a test fail? (The HMAC check still fails for `none`, but the explicit pin is defence in depth and stops RS256/HS256 key confusion when keys are asymmetric.)
4. Discuss: when is a role claim in a token acceptable? (When the issuer is trusted, the token is short-lived, and the API also checks scopes and object ownership.)

## Run

```text
.venv/Scripts/python appsec-course/11-api-authorization-and-oauth/labs/jwt-forging-privesc/demo.py
.venv/Scripts/python -m pytest appsec-course/11-api-authorization-and-oauth/labs/jwt-forging-privesc -q -p no:cacheprovider
```

## Expected output (real run)

`iat`/`exp` values change on every run.

```text
===== VULNERABLE API =====
alice's token header: {'alg': 'HS256', 'typ': 'JWT'} claims: {'sub': 'u-alice', 'role': 'user'}
alice GET /payouts with her own token -> (403, 'admin only')
attack 1: alg=none + role=admin -> (200, 'PAYOUT REPORT (FAKE): all driver bank payouts')
attack 2: crack the HMAC key with an 8-word list -> FOUND (FAKE lab secret)
          re-sign with role=admin -> (200, 'PAYOUT REPORT (FAKE): all driver bank payouts')
          re-sign with sub=u-carol -> (403, 'admin only')

===== SECURE API =====
alice's token header: {'alg': 'HS256', 'typ': 'at+jwt'} claims: {'sub': 'u-alice', 'iss': 'https://auth.lab.example', 'aud': 'payouts-api', 'iat': 1795089765, 'exp': 1795090065}
alice GET /payouts with her own token -> (403, 'admin only')
attack 1: alg=none + role=admin -> (401, 'invalid token')
attack 2: crack the HMAC key with an 8-word list -> not found
```

## Run the real tool (hedged)

Only against the course lab or your own systems:

- **jwt_tool** (Python): `python3 jwt_tool.py <token>` to decode; `-X a` tries alg=none variants; `-C -d wordlist.txt` cracks an HS256 key; `-T` lets you tamper claims interactively (verify flags with `-h`).
- **hashcat** mode `16500` cracks HS256 JWT keys: `hashcat -m 16500 token.txt wordlist.txt`.
- **Burp Suite**: the "JWT Editor" extension edits, re-signs and tests `alg`/`kid`/`jku` attacks (check the BApp Store).

## What you learned

- A signature only proves who **issued** a token, not that its claims are a good basis for authorization.
- Pin algorithms and keys on the server; never let the token choose.
- Weak HMAC keys are passwords: one captured token allows unlimited offline guessing.
- Look up roles and ownership server-side; use token claims for identity and scope.
