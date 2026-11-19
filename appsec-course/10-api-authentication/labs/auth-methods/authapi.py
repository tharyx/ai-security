"""One in-process API, five ways to authenticate to it.

Covers "Talking To An API Using HTTP Basic and API Keys" and "Talking To An
API Using OAuth and JWT", plus the "Types of Authentication" list:

  GET  /public             no authentication (public API)
  GET  /basic              HTTP Basic (Authorization: Basic base64(user:pass))
  GET  /apikey             API key in the X-API-Key header (never the query string)
  POST /oauth/token        OAuth 2.0 client_credentials grant -> short-lived HS256 JWT
  GET  /bearer             Authorization: Bearer <JWT>, verified strictly
  GET  /mtls               mutual TLS, SIMULATED: the TLS terminator passes the
                           verified client-certificate fingerprint out of band;
                           a client-sent header claiming a certificate is ignored

``handle(method, path, headers, body, tls_client_fp=None) -> (status, headers, body)``.
All credentials are FAKE and built at runtime. Only test systems you own or
have written permission to test.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from urllib.parse import parse_qs, urlsplit


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64url_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class AuthApi:
    def __init__(self):
        # FAKE credentials, generated per instance.
        self.basic_user = "svc-reader"
        self.basic_pass = "FAKE-" + secrets.token_hex(6)
        self.api_key = "FAKE-KEY-" + secrets.token_hex(8)
        self.client_id = "demo-client"
        self.client_secret = "FAKE-CS-" + secrets.token_hex(8)
        self._jwt_key = secrets.token_bytes(32)  # strong random HMAC key
        self.audience = "orders-api"
        self.trusted_client_fp = hashlib.sha256(b"FAKE lab client certificate").hexdigest()

    # --- helpers --------------------------------------------------------
    def _issue_jwt(self, sub: str, scope: str, ttl: int = 300) -> str:
        header = {"alg": "HS256", "typ": "JWT"}
        now = int(time.time())
        payload = {"iss": "lab-as", "sub": sub, "aud": self.audience,
                   "scope": scope, "iat": now, "exp": now + ttl}
        si = _b64url(json.dumps(header).encode()) + "." + _b64url(json.dumps(payload).encode())
        sig = hmac.new(self._jwt_key, si.encode(), hashlib.sha256).digest()
        return si + "." + _b64url(sig)

    def _verify_jwt(self, token: str):
        try:
            h, p, s = token.split(".")
            header = json.loads(_b64url_dec(h))
            payload = json.loads(_b64url_dec(p))
        except ValueError:
            return None
        if header.get("alg") != "HS256":
            return None
        expected = hmac.new(self._jwt_key, f"{h}.{p}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(_b64url(expected), s):
            return None
        if payload.get("aud") != self.audience or int(payload.get("exp", 0)) < time.time():
            return None
        return payload

    @staticmethod
    def _deny(scheme: str):
        return 401, {"WWW-Authenticate": scheme}, {"error": "unauthorized"}

    # --- router ---------------------------------------------------------
    def handle(self, method, path, headers=None, body=None, tls_client_fp=None):
        headers = {k.lower(): v for k, v in (headers or {}).items()}
        parts = urlsplit(path)
        route, query = parts.path, parse_qs(parts.query)

        if route == "/public" and method == "GET":
            return 200, {}, {"data": "anyone can read this"}

        if route == "/basic" and method == "GET":
            auth = headers.get("authorization", "")
            if not auth.startswith("Basic "):
                return self._deny('Basic realm="lab"')
            try:
                user, _, pw = base64.b64decode(auth[6:]).decode().partition(":")
            except ValueError:
                return self._deny('Basic realm="lab"')
            ok = hmac.compare_digest(user, self.basic_user) & hmac.compare_digest(pw, self.basic_pass)
            return (200, {}, {"data": f"hello {user}"}) if ok else self._deny('Basic realm="lab"')

        if route == "/apikey" and method == "GET":
            if "api_key" in query:
                # keys in URLs end up in logs, proxies and browser history
                return 400, {}, {"error": "send the API key in the X-API-Key header, not the URL"}
            key = headers.get("x-api-key", "")
            if key and hmac.compare_digest(key, self.api_key):
                return 200, {}, {"data": "api key accepted"}
            return self._deny("ApiKey")

        if route == "/oauth/token" and method == "POST":
            form = parse_qs(body or "")
            if form.get("grant_type") != ["client_credentials"]:
                return 400, {}, {"error": "unsupported_grant_type"}
            cid, csec = form.get("client_id", [""])[0], form.get("client_secret", [""])[0]
            if cid == self.client_id and hmac.compare_digest(csec, self.client_secret):
                tok = self._issue_jwt(cid, form.get("scope", ["orders:read"])[0])
                return 200, {"Cache-Control": "no-store"}, {
                    "access_token": tok, "token_type": "Bearer", "expires_in": 300}
            return 401, {}, {"error": "invalid_client"}

        if route == "/bearer" and method == "GET":
            auth = headers.get("authorization", "")
            claims = self._verify_jwt(auth[7:]) if auth.startswith("Bearer ") else None
            if claims:
                return 200, {}, {"data": f"token for {claims['sub']} scope={claims['scope']}"}
            return self._deny('Bearer error="invalid_token"')

        if route == "/mtls" and method == "GET":
            # Only the TLS layer's verified fingerprint counts. A header such as
            # X-Client-Cert sent by the client is attacker-controlled; ignore it.
            if tls_client_fp and hmac.compare_digest(tls_client_fp, self.trusted_client_fp):
                return 200, {}, {"data": "client certificate verified"}
            return 401, {}, {"error": "client certificate required"}

        return 404, {}, {"error": "not found"}


def basic_header(user: str, pw: str) -> dict:
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()}
