"""OAuth 2.0 / 2.1 flows simulated in-process: authorization code + PKCE,
refresh-token rotation, token types, and the classic insecure configurations.

No network, no browser, no identity provider. "Redirects" are just URL strings.
Tokens are random values (opaque) or HS256 JWTs built at runtime; all FAKE.

Two authorization servers share one class:
  AuthServer(secure=False)  - prefix redirect_uri match, PKCE optional, codes reusable,
                              implicit grant on, refresh tokens never rotate.
  AuthServer(secure=True)   - exact redirect_uri match, PKCE S256 required, single-use
                              codes bound to client+redirect, implicit off, refresh
                              rotation with reuse detection (RFC 9700 / OAuth 2.1 rules).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlencode, urlparse

API_AUDIENCE = "https://api.lab.example"
ISSUER = "https://as.lab.example"


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def pkce_pair() -> tuple[str, str]:
    """Client side: random verifier, S256 challenge = BASE64URL(SHA256(verifier))."""
    verifier = b64url(secrets.token_bytes(32))
    return verifier, b64url(hashlib.sha256(verifier.encode()).digest())


def _jwt(claims: dict, key: bytes, typ: str) -> str:
    h = b64url(json.dumps({"alg": "HS256", "typ": typ}).encode())
    p = b64url(json.dumps(claims).encode())
    return f"{h}.{p}.{b64url(hmac.new(key, f'{h}.{p}'.encode(), hashlib.sha256).digest())}"


def jwt_parts(token: str) -> tuple[dict, dict]:
    h, p, _ = token.split(".")
    return json.loads(b64url_decode(h)), json.loads(b64url_decode(p))


@dataclass
class Client:
    client_id: str
    redirect_uris: list[str]
    public: bool = True  # SPA / mobile app: cannot keep a secret


@dataclass
class AuthServer:
    secure: bool
    clients: dict[str, Client] = field(default_factory=dict)
    codes: dict[str, dict] = field(default_factory=dict)
    refresh: dict[str, dict] = field(default_factory=dict)
    revoked_families: set[str] = field(default_factory=set)
    key: bytes = field(default_factory=lambda: secrets.token_bytes(32))

    def register(self, client: Client) -> None:
        self.clients[client.client_id] = client

    # ---- /authorize
    def _redirect_ok(self, client: Client, uri: str) -> bool:
        if self.secure:
            return uri in client.redirect_uris  # exact string match
        return any(uri.startswith(r) for r in client.redirect_uris)  # prefix match: bypassable

    def authorize(self, user: str, params: dict) -> str:
        """Returns the URL the browser is redirected to (or raises ValueError)."""
        client = self.clients.get(params.get("client_id"))
        if client is None or not self._redirect_ok(client, params.get("redirect_uri", "")):
            raise ValueError("invalid_request: unknown client or redirect_uri")  # never redirect on this error
        rtype = params.get("response_type")
        state = params.get("state")
        extra = {"state": state} if state else {}
        if rtype == "token":
            if self.secure:
                raise ValueError("unsupported_response_type: implicit grant removed in OAuth 2.1")
            at = self._access_token(user, client.client_id, scope=params.get("scope", ""))
            return params["redirect_uri"] + "#" + urlencode({"access_token": at, **extra})
        if rtype != "code":
            raise ValueError("unsupported_response_type")
        challenge = params.get("code_challenge")
        if self.secure and (not challenge or params.get("code_challenge_method") != "S256"):
            raise ValueError("invalid_request: PKCE S256 required")
        code = secrets.token_urlsafe(16)
        self.codes[code] = {"user": user, "client_id": client.client_id, "redirect_uri": params["redirect_uri"],
                            "challenge": challenge, "scope": params.get("scope", ""),
                            "nonce": params.get("nonce"), "used": False}
        return params["redirect_uri"] + "?" + urlencode({"code": code, **extra})

    # ---- /token
    def token(self, params: dict) -> dict:
        grant = params.get("grant_type")
        if grant == "authorization_code":
            return self._code_grant(params)
        if grant == "refresh_token":
            return self._refresh_grant(params)
        if grant == "password" and not self.secure:
            return {"access_token": self._access_token(params["username"], params["client_id"], "")}
        raise ValueError("unsupported_grant_type")

    def _code_grant(self, params: dict) -> dict:
        rec = self.codes.get(params.get("code", ""))
        if rec is None:
            raise ValueError("invalid_grant")
        if self.secure:
            if rec["used"]:
                raise ValueError("invalid_grant: code already used")
            if rec["client_id"] != params.get("client_id") or rec["redirect_uri"] != params.get("redirect_uri"):
                raise ValueError("invalid_grant: client or redirect_uri mismatch")
            verifier = params.get("code_verifier", "")
            if b64url(hashlib.sha256(verifier.encode()).digest()) != rec["challenge"]:
                raise ValueError("invalid_grant: PKCE verification failed")
        rec["used"] = True
        family = secrets.token_hex(4)
        rt = self._new_refresh(rec["user"], rec["client_id"], rec["scope"], family)
        out = {"access_token": self._access_token(rec["user"], rec["client_id"], rec["scope"]),
               "token_type": "Bearer", "expires_in": 300, "refresh_token": rt}
        if "openid" in rec["scope"].split():
            out["id_token"] = _jwt({"iss": ISSUER, "sub": rec["user"], "aud": rec["client_id"],
                                    "nonce": rec["nonce"]}, self.key, "JWT")
        return out

    def _new_refresh(self, user, client_id, scope, family) -> str:
        rt = secrets.token_urlsafe(24)
        self.refresh[rt] = {"user": user, "client_id": client_id, "scope": scope, "family": family, "used": False}
        return rt

    def _refresh_grant(self, params: dict) -> dict:
        rec = self.refresh.get(params.get("refresh_token", ""))
        if rec is None or rec["family"] in self.revoked_families:
            raise ValueError("invalid_grant")
        if not self.secure:  # same refresh token works forever
            return {"access_token": self._access_token(rec["user"], rec["client_id"], rec["scope"]),
                    "refresh_token": params["refresh_token"]}
        if rec["used"]:  # a rotated token came back: someone has a copy -> kill the family
            self.revoked_families.add(rec["family"])
            raise ValueError("invalid_grant: refresh token reuse detected, family revoked")
        rec["used"] = True
        new_rt = self._new_refresh(rec["user"], rec["client_id"], rec["scope"], rec["family"])
        return {"access_token": self._access_token(rec["user"], rec["client_id"], rec["scope"]),
                "refresh_token": new_rt}

    def _access_token(self, user, client_id, scope) -> str:
        return _jwt({"iss": ISSUER, "sub": user, "aud": API_AUDIENCE, "client_id": client_id,
                     "scope": scope}, self.key, "at+jwt")


# ---- resource server (the API)


def api_accepts(token: str, key: bytes, secure: bool, needed_scope: str = "") -> bool:
    try:
        header, claims = jwt_parts(token)
        h, p, s = token.split(".")
    except Exception:
        return False
    if not hmac.compare_digest(hmac.new(key, f"{h}.{p}".encode(), hashlib.sha256).digest(), b64url_decode(s)):
        return False
    if not secure:
        return True  # any signed token from the AS works, including an ID token
    if header.get("typ") != "at+jwt" or claims.get("aud") != API_AUDIENCE:  # RFC 9068
        return False
    return needed_scope in claims.get("scope", "").split() if needed_scope else True


# ---- client side


def client_callback(redirect_url: str, expected_state: str | None) -> str:
    """The client must check state (CSRF on the login itself) before using the code."""
    q = parse_qs(urlparse(redirect_url).query)
    if expected_state is not None and q.get("state", [None])[0] != expected_state:
        raise ValueError("state mismatch: possible login CSRF")
    return q["code"][0]


# ---- configuration review

def audit_client_config(cfg: dict) -> list[str]:
    """Flag insecure OAuth client/AS settings (RFC 9700 and the OAuth 2.1 draft)."""
    f = []
    grants = set(cfg.get("grant_types", []))
    if "implicit" in grants:
        f.append("implicit grant enabled (removed in OAuth 2.1; tokens leak via URL fragment/history)")
    if "password" in grants:
        f.append("resource owner password grant enabled (removed in OAuth 2.1)")
    if "authorization_code" in grants and not cfg.get("require_pkce"):
        f.append("PKCE not required for the code flow")
    for uri in cfg.get("redirect_uris", []):
        p = urlparse(uri)
        if "*" in uri:
            f.append(f"wildcard redirect_uri {uri}")
        if p.scheme == "http" and p.hostname not in ("localhost", "127.0.0.1"):
            f.append(f"plain-http redirect_uri {uri}")
    if cfg.get("redirect_uri_matching", "exact") != "exact":
        f.append("redirect_uri matching is not exact")
    if cfg.get("access_token_ttl_seconds", 0) > 3600:
        f.append("access tokens live longer than 1 hour")
    if cfg.get("refresh_token_rotation") is False and cfg.get("public_client"):
        f.append("public client refresh tokens are neither rotated nor sender-constrained")
    if cfg.get("allow_token_in_query"):
        f.append("bearer token accepted in URL query string")
    if not cfg.get("require_state", True):
        f.append("state parameter not required")
    return f
