"""Attacking caching layers: web cache poisoning and web cache deception, plus a
Memcached exposure audit. Everything is in-process: an origin app and a cache dict.

Poisoning: the origin builds a script URL from the X-Forwarded-Host header, but the
           cache key ignores that header (it is "unkeyed"). One attacker request
           poisons the cached page for every later visitor.
Deception: the origin ignores extra path segments (/account/x.css returns the account
           page); the cache stores anything ending in .css as static, ignoring
           Cache-Control: private. The attacker tricks a victim into visiting the URL,
           then reads the victim's cached private page.
"""

from __future__ import annotations

STATIC_EXT = (".css", ".js", ".png", ".jpg", ".svg")


class Origin:
    def __init__(self, secure: bool):
        self.secure = secure
        self.sessions = {"FAKE-sess-victim": {"user": "victim", "card": "FAKE-CARD-4111"}}

    def handle(self, path: str, headers: dict):
        host = headers.get("X-Forwarded-Host", "shop.lab.example")
        if self.secure and host != "shop.lab.example":
            host = "shop.lab.example"  # do not trust forwarding headers from clients
        if path == "/":
            return 200, {"Cache-Control": "public, max-age=300"}, f'<script src="https://{host}/static/app.js"></script>'
        if path == "/account" or (not self.secure and path.startswith("/account/")):
            sess = self.sessions.get(headers.get("Cookie", ""))
            if not sess:
                return 302, {"Location": "/login", "Cache-Control": "no-store"}, ""
            return 200, {"Cache-Control": "private, no-store"}, f"user={sess['user']} card={sess['card']}"
        return 404, {"Cache-Control": "no-store"}, "not found"


class Cache:
    """A CDN/reverse proxy. Vulnerable: key = path only; caches static-looking paths
    regardless of Cache-Control. Secure: key includes relevant headers (Vary) and
    the origin's Cache-Control is respected."""

    def __init__(self, origin: Origin, secure: bool):
        self.origin, self.secure, self.store = origin, secure, {}

    def key(self, path, headers):
        if self.secure:
            return (path, headers.get("X-Forwarded-Host", ""))
        return (path,)

    def get(self, path, headers=None):
        headers = headers or {}
        k = self.key(path, headers)
        if k in self.store:
            return self.store[k] + ("HIT",)
        status, h, body = self.origin.handle(path, headers)
        cc = h.get("Cache-Control", "")
        if self.secure:
            cacheable = status == 200 and "public" in cc and "no-store" not in cc and "private" not in cc
        else:
            cacheable = status == 200 and ("public" in cc or path.endswith(STATIC_EXT))
        if cacheable:
            self.store[k] = (status, h, body)
        return status, h, body, "MISS"


def audit_memcached(cfg: dict) -> list[str]:
    """Memcached has no authentication by default. Exposed instances leak cached data
    (sessions, tokens, PII) and UDP was abused for huge DDoS amplification (2018)."""
    f = []
    if cfg.get("listen", "127.0.0.1") in ("0.0.0.0", "::"):
        f.append("listens on all interfaces: bind to localhost or a private interface")
    if cfg.get("udp_port", 0) != 0:
        f.append("UDP enabled: disable (-U 0) to prevent amplification attacks")
    if not cfg.get("sasl"):
        f.append("no SASL authentication")
    if not cfg.get("tls"):
        f.append("no TLS: cached values travel in clear text")
    if cfg.get("internet_facing"):
        f.append("reachable from the internet: restrict with security groups/firewall")
    return f
