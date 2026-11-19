"""Abusing microservices and REST APIs through implicit internal trust.

Vulnerable design:
  - the gateway authenticates users but forwards client headers unchanged;
  - the orders service trusts X-User-Id from any caller ("it's internal");
  - the admin service allows requests whose X-Forwarded-For starts with 10.;
  - internal services are reachable directly (flat network).
Secure design:
  - the gateway strips identity headers from clients and adds a short-lived, signed
    internal token (HMAC here; JWT/mTLS/SPIFFE in real meshes) with audience;
  - services verify that token and ignore raw identity headers;
  - client IP comes from the right-most address added by a TRUSTED proxy.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import secrets
import time

ORDERS = {"o-1": {"owner": "alice", "total": 120}, "o-2": {"owner": "bob", "total": 9900}}
SESSIONS = {}
MESH_KEY = secrets.token_bytes(32)
IDENTITY_HEADERS = {"x-user-id", "x-user-role", "x-internal-token", "x-forwarded-for", "x-real-ip"}


def login(user):
    tok = "FAKE-sess-" + secrets.token_hex(6)
    SESSIONS[tok] = user
    return tok


# ---------------------------------------------------------------- internal identity token

def mint_internal(user: str, aud: str, ttl=30, now=None) -> str:
    claims = {"sub": user, "aud": aud, "exp": int((now or time.time()) + ttl)}
    raw = json.dumps(claims, sort_keys=True)
    return raw + "|" + hmac.new(MESH_KEY, raw.encode(), hashlib.sha256).hexdigest()


def verify_internal(token: str, aud: str, now=None):
    try:
        raw, mac = token.rsplit("|", 1)
    except (ValueError, AttributeError):
        return None
    if not hmac.compare_digest(mac, hmac.new(MESH_KEY, raw.encode(), hashlib.sha256).hexdigest()):
        return None
    c = json.loads(raw)
    return c["sub"] if c["aud"] == aud and c["exp"] > (now or time.time()) else None


# ---------------------------------------------------------------- services

def orders_service(headers: dict, order_id: str, secure: bool):
    h = {k.lower(): v for k, v in headers.items()}
    user = verify_internal(h.get("x-internal-token", ""), "orders") if secure else h.get("x-user-id")
    if not user:
        return 401, "unauthenticated"
    order = ORDERS.get(order_id)
    if order is None or order["owner"] != user:
        return 404, "not found"
    return 200, order


def client_ip(headers: dict, peer_ip: str, secure: bool, trusted_proxies=1) -> str:
    xff = [p.strip() for p in headers.get("X-Forwarded-For", "").split(",") if p.strip()]
    if not secure:
        return xff[0] if xff else peer_ip  # left-most = whatever the client wrote
    chain = xff + [peer_ip]
    return chain[-(trusted_proxies + 1)] if len(chain) > trusted_proxies else chain[0]


def admin_service(headers: dict, peer_ip: str, secure: bool):
    ip = ipaddress.ip_address(client_ip(headers, peer_ip, secure))
    if ip in ipaddress.ip_network("10.0.0.0/8"):
        return 200, "admin console"
    return 403, "forbidden"


def gateway(headers: dict, path: str, secure: bool, peer_ip="198.51.100.9"):
    """Edge gateway: authenticates the session cookie, then routes."""
    user = SESSIONS.get(headers.get("Cookie", ""))
    if user is None:
        return 401, "login required"
    if secure:
        fwd = {k: v for k, v in headers.items() if k.lower() not in IDENTITY_HEADERS}
        fwd["X-Internal-Token"] = mint_internal(user, "orders")
        fwd["X-Forwarded-For"] = peer_ip  # the gateway writes it; client value dropped
    else:
        fwd = dict(headers)
        fwd.setdefault("X-User-Id", user)
        fwd["X-Forwarded-For"] = (headers.get("X-Forwarded-For", "") + ", " + peer_ip).strip(", ")
    if path.startswith("/orders/"):
        return orders_service(fwd, path.split("/")[-1], secure)
    if path == "/admin":
        return admin_service(fwd, "172.16.0.2", secure)  # peer seen by admin = the gateway
    return 404, "no route"
