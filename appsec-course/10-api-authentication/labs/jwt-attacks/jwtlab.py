"""HS256 JSON Web Tokens from scratch (hmac/hashlib/base64), with the classic
attacks and a hardened verifier.

No PyJWT, no cryptography package. RS256 is *simulated* (a fake asymmetric
scheme) only to demonstrate the RS256->HS256 key-confusion idea; it is clearly
labelled and not real crypto.

Attacks shown (all against this lab's own toy tokens):
* ``alg: none``             - signature stripped, a naive verifier trusts it.
* weak-secret cracking      - HMAC secret guessed from a TINY built-in wordlist.
* missing ``exp`` / ``aud`` - a verifier that never checks claims.
* ``kid`` path traversal    - a key id used as a file path to pick the key.

Secrets here are FAKE and built at runtime. Only test systems you own or have
written permission to test.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _signing_input(header: dict, payload: dict) -> str:
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    return h + "." + p


def _hs256(signing_input: str, secret: str) -> str:
    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return b64url(sig)


def encode_hs256(payload: dict, secret: str, header: dict | None = None) -> str:
    header = header or {"alg": "HS256", "typ": "JWT"}
    signing_input = _signing_input(header, payload)
    return signing_input + "." + _hs256(signing_input, secret)


def decode_unverified(token: str) -> tuple:
    """Split a token into (header, payload, signature) WITHOUT checking it."""
    h, p, s = token.split(".")
    return json.loads(b64url_decode(h)), json.loads(b64url_decode(p)), s


# --- a deliberately naive verifier (vulnerable) ----------------------------
def verify_naive(token: str, secret: str) -> dict:
    """Trusts 'alg', never checks exp/aud. Multiple bugs on purpose."""
    header, payload, sig = decode_unverified(token)
    alg = header.get("alg", "")
    if alg == "none":
        return payload  # BUG: accepts unsigned tokens
    signing_input = token.rsplit(".", 1)[0]
    if hmac.compare_digest(sig, _hs256(signing_input, secret)):
        return payload  # BUG: no exp/aud check
    raise ValueError("bad signature")


# --- the hardened verifier (secure) ----------------------------------------
def verify_strict(token: str, secret: str, *, audience: str,
                  now: int | None = None, leeway: int = 0) -> dict:
    """Reject alg!=HS256, verify the MAC, require exp (not expired) and aud."""
    now = int(time.time()) if now is None else now
    header, payload, sig = decode_unverified(token)
    if header.get("alg") != "HS256":
        raise ValueError(f"unexpected alg {header.get('alg')!r}; refusing")
    signing_input = token.rsplit(".", 1)[0]
    if not hmac.compare_digest(sig, _hs256(signing_input, secret)):
        raise ValueError("bad signature")
    if "exp" not in payload:
        raise ValueError("missing exp")
    if now > int(payload["exp"]) + leeway:
        raise ValueError("token expired")
    if payload.get("aud") != audience:
        raise ValueError("wrong audience")
    return payload


# --- attacks ---------------------------------------------------------------
def forge_alg_none(payload: dict) -> str:
    """Build a token with alg:none and an empty signature."""
    header = {"alg": "none", "typ": "JWT"}
    return _signing_input(header, payload) + "."


def crack_hs256_secret(token: str, wordlist: list) -> str | None:
    """Brute force the HMAC secret from a tiny wordlist. Returns it or None."""
    signing_input = token.rsplit(".", 1)[0]
    _, _, sig = decode_unverified(token)
    for candidate in wordlist:
        if hmac.compare_digest(sig, _hs256(signing_input, candidate)):
            return candidate
    return None


def make_fake_weak_secret() -> str:
    """Build a FAKE weak secret at runtime from parts (never a real one)."""
    return "secret" + "123"  # intentionally in a tiny wordlist below


TINY_WORDLIST = ["password", "123456", "secret", "changeme", "secret123", "admin"]


# --- kid path-traversal key resolver ---------------------------------------
def resolve_key_vulnerable(kid: str, key_dir: dict) -> str:
    """Use kid directly as a lookup key: '../' style ids can escape the dir."""
    # key_dir maps a *resolved* path to a secret. A traversal kid can reach a
    # predictable file (here, a public, attacker-known value).
    return key_dir.get(kid, "")


def resolve_key_safe(kid: str, key_dir: dict) -> str:
    """Only allow known, slash-free key ids."""
    if "/" in kid or ".." in kid or kid not in key_dir:
        raise ValueError("invalid kid")
    return key_dir[kid]
