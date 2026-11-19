"""Delegated authorization tokens between agents (stdlib HMAC; RFC 8693-style ideas).

A token is ``base64url(payload).base64url(HMAC-SHA256)``. It is NOT a real JWT
library and the single shared key is a teaching shortcut: production should use a
token service with asymmetric signatures (and short-lived keys), e.g. OAuth 2.0
Token Exchange (RFC 8693) and/or workload identity. Claims used:

  iss  issuer (the token service)        sub  current holder (agent id)
  aud  the ONE resource/agent it is for  scope  list of permissions
  exp / iat  expiry and issue time       jti  unique id (for revocation)
  act  actor chain: who acted on whose behalf, newest outermost:
       {"sub": "agent-c", "act": {"sub": "agent-b", "act": {"sub": "agent-a"}}}
  user the original human principal

Rules enforced by ``TokenService.exchange`` on EVERY hop:
  * scope can only shrink (down-scoping),
  * expiry can only shrink (never outlive the parent),
  * audience is rebound to the next hop's target (no passthrough),
  * the act chain grows, and has a maximum depth.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass, field

MAX_DEPTH = 3


class TokenError(Exception):
    pass


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def act_chain(claims: dict) -> list[str]:
    """Flatten the nested act claim, oldest actor first."""
    out, node = [], claims.get("act")
    while node:
        out.append(node["sub"])
        node = node.get("act")
    return list(reversed(out))


@dataclass
class TokenService:
    key: bytes = b"FAKE-token-service-key"
    revoked: set[str] = field(default_factory=set)

    def _mint(self, claims: dict) -> str:
        payload = _b64(json.dumps(claims, sort_keys=True).encode())
        sig = _b64(hmac.new(self.key, payload.encode(), hashlib.sha256).digest())
        return f"{payload}.{sig}"

    def issue_root(self, user: str, agent: str, aud: str, scopes: list[str], ttl: int, now: float) -> str:
        claims = {
            "iss": "token-service",
            "user": user,
            "sub": agent,
            "aud": aud,
            "scope": sorted(scopes),
            "iat": now,
            "exp": now + ttl,
            "jti": secrets.token_hex(6),
            "act": {"sub": agent},
        }
        return self._mint(claims)

    def decode(self, token: str) -> dict:
        try:
            payload, sig = token.split(".")
        except ValueError:
            raise TokenError("malformed token") from None
        good = _b64(hmac.new(self.key, payload.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(good, sig):
            raise TokenError("bad signature")
        return json.loads(_unb64(payload))

    def verify(self, token: str, *, audience: str, scope: str, now: float) -> dict:
        c = self.decode(token)
        if c["jti"] in self.revoked:
            raise TokenError("revoked")
        if now >= c["exp"]:
            raise TokenError("expired")
        if c["aud"] != audience:
            raise TokenError(f"audience mismatch: token is for {c['aud']}, presented to {audience}")
        if scope not in c["scope"]:
            raise TokenError(f"scope {scope} not granted")
        return c

    def exchange(
        self, token: str, *, new_agent: str, aud: str, scopes: list[str], ttl: int, now: float
    ) -> str:
        """Token exchange: parent token -> narrower token for the next agent."""
        parent = self.decode(token)
        if parent["jti"] in self.revoked:
            raise TokenError("parent revoked")
        if now >= parent["exp"]:
            raise TokenError("parent expired")
        extra = set(scopes) - set(parent["scope"])
        if extra:
            raise TokenError(f"cannot widen scope: {sorted(extra)}")
        chain = act_chain(parent)
        if len(chain) >= MAX_DEPTH:
            raise TokenError("delegation chain too deep")
        claims = {
            "iss": "token-service",
            "user": parent["user"],
            "sub": new_agent,
            "aud": aud,
            "scope": sorted(scopes),
            "iat": now,
            "exp": min(now + ttl, parent["exp"]),
            "jti": secrets.token_hex(6),
            "act": {"sub": new_agent, "act": parent["act"]},
        }
        return self._mint(claims)

    def revoke(self, token: str) -> None:
        self.revoked.add(self.decode(token)["jti"])
