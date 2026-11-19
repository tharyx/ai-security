# Lab: Abusing JWT tokens (HS256 from scratch) and a hardened verifier

**Course items:** "Abusing JWT Tokens", "Insecure JWTs Validation", "JSON Web Tokens (JWTs)". **Lessons:** [01 section 6](../../01-authentication-types.md#6-json-web-tokens-jwts), [02 section 10](../../02-authentication-attacks.md#10-insecure-jwt-validation-and-abusing-jwt-tokens).

**Time:** 60 minutes. **Tests:** 8, offline. **Safety:** HS256 is implemented with `hmac`, `hashlib` and `base64` only (no PyJWT). The strong secret is FAKE and assembled at runtime; the "weak" secret is built from parts and appears in a **six-word** list. Only test systems you own or have written permission to test.

## Goal

Exploit four classic JWT validation mistakes against a naive verifier, and watch a strict verifier reject each one.

## Files

| File | Role |
|---|---|
| [jwtlab.py](jwtlab.py) | `encode_hs256`, `decode_unverified`, `verify_naive` (vulnerable), `verify_strict` (secure), `forge_alg_none`, `crack_hs256_secret`, `resolve_key_vulnerable`, `resolve_key_safe` |
| [demo.py](demo.py) | runs every attack |
| [test_aps_ch10_jwt_attacks.py](test_aps_ch10_jwt_attacks.py) | the tests |

`verify_strict` rejects any `alg` other than HS256, verifies the HMAC in constant time, requires `exp` and checks it, and checks `aud`.

## Run

```text
.venv/Scripts/python appsec-course/10-api-authentication/labs/jwt-attacks/demo.py
.venv/Scripts/python -m pytest appsec-course/10-api-authentication/labs/jwt-attacks -q
```

## Real output (token and `exp` change each run)

```text
=== A valid HS256 token ===
  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIs...(truncated in this README)
  strict verify: {'sub': 'alice', 'role': 'user', 'aud': 'shop-api', 'exp': 1795093016}

=== Attack: alg:none ===
  naive verifier -> {'sub': 'attacker', 'role': 'admin', 'aud': 'shop-api', 'exp': 1795093016}
  strict verifier -> REJECTED: unexpected alg 'none'; refusing

=== Attack: weak secret cracking ===
  wordlist: ['password', '123456', 'secret', 'changeme', 'secret123', 'admin']
  cracked secret -> secret123
  strong token crackable? -> None

=== Attack: missing/expired claims ===
  no exp   -> REJECTED: missing exp
  expired  -> REJECTED: token expired

=== Attack: kid path traversal ===
  vulnerable resolver(kid='../../public/keys/pub') -> 'public'
  safe resolver -> REJECTED: invalid kid
```

(The demo token is signed with a FAKE lab secret built at runtime and expires; it is truncated here so no complete token is stored in the repo.)

## Steps

1. Paste the valid token's first two parts into any base64url decoder: the claims are plain JSON. Signing is not encryption.
2. In `forge_alg_none`, try variants `"None"`, `"NONE"`, `"nOnE"`. Does `verify_naive` accept them? Does `verify_strict`? (Case variants have bypassed real libraries.)
3. After cracking `secret123`, forge `{"role":"admin"}` (the test does this). In chapter 11 this becomes privilege escalation.
4. Add an `iss` check to `verify_strict` and a test that a token from another issuer is rejected.
5. **Key confusion (thought exercise):** if a verifier took the key from configuration (an RSA **public** key in PEM text) and the algorithm from the token, an attacker could choose HS256 and use that public text as the HMAC secret. Write a `verify_confused(token, public_pem)` that has this bug, prove it, then fix it by binding the key to one algorithm.
6. Make the `kid` resolver read from a dict of known keys only (already done in `resolve_key_safe`). Why is `kid` also an SQL injection risk when keys live in a database?

## Run the real tool (hedged)

```bash
python3 jwt_tool.py "$TOKEN"                     # decode
python3 jwt_tool.py "$TOKEN" -X a                # alg:none variants
python3 jwt_tool.py "$TOKEN" -C -d small.txt     # crack HS256 with a small list
hashcat -m 16500 jwt.txt small.txt               # hashcat JWT mode (verify the mode number)
```

Only against your course lab. More in [real-tools/auth-testing-tools.md](../../real-tools/auth-testing-tools.md). Burp's JWT Editor extension does the same interactively.

## What you learned

- Never let the token choose the algorithm; reject `none`.
- HMAC secrets must be long and random; one captured token is enough to test a guess offline.
- Always check `exp`, `aud` and `iss`, and resolve `kid` only from a fixed key set.
