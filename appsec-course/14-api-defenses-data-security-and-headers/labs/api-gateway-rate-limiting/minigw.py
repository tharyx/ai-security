"""A tiny Kong-like API gateway: services, routes, consumers and a plugin chain.

Plugins (names follow Kong's bundled plugins; behaviour is simplified, verify at docs.konghq.com):
  key-auth             : API key in the `apikey` header -> consumer; 401 when missing/unknown
  rate-limiting        : token bucket per consumer, per API key, or per client IP; 429 + Retry-After
  response-transformer : add security headers, remove Server/X-Powered-By
  cors                 : exact-match origin allowlist

Everything is in-process: `Gateway.handle(method, path, headers, body)` returns (status, headers, body).
The clock is injectable so tests do not sleep. API keys are FAKE and generated at runtime.
"""
from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

Response = tuple[int, dict[str, str], str]
Handler = Callable[[str, str, dict[str, str], str], Response]


class Clock:
    def __init__(self, t: float = 1_000.0):
        self.t = t

    def now(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


# ------------------------------------------------------------------ upstream API (the thing we protect)
class UpstreamAPI:
    """Login with a 4-digit PIN (brute-forceable) and an orders endpoint. Leaky headers on purpose."""

    def __init__(self, pin: str = "7342"):
        self._pin = pin
        self.calls = 0

    def __call__(self, method: str, path: str, headers: dict[str, str], body: str) -> Response:
        self.calls += 1
        base = {"Server": "orders-api/2.3.1", "X-Powered-By": "Express", "Content-Type": "application/json"}
        if path == "/login" and method == "POST":
            ok = json.loads(body or "{}").get("pin") == self._pin
            return (200 if ok else 401), base, json.dumps({"ok": ok})
        if path == "/orders" and method == "GET":
            who = headers.get("X-Consumer-Username", "anonymous")
            return 200, base, json.dumps({"orders": [], "for": who})
        return 404, base, "{}"


# ------------------------------------------------------------------ rate limiting
@dataclass
class TokenBucket:
    capacity: float
    refill_per_sec: float
    tokens: float
    updated: float

    def take(self, now: float) -> tuple[bool, float]:
        self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.refill_per_sec)
        self.updated = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True, 0.0
        return False, (1 - self.tokens) / self.refill_per_sec  # seconds until one token


# ------------------------------------------------------------------ plugins
@dataclass
class Ctx:
    method: str
    path: str
    headers: dict[str, str]
    body: str
    client_ip: str
    consumer: str | None = None
    extra_response_headers: dict[str, str] = field(default_factory=dict)


class Plugin:
    name = "base"
    priority = 0  # higher runs first, like Kong

    def access(self, ctx: Ctx) -> Response | None:
        return None

    def header_filter(self, ctx: Ctx, headers: dict[str, str]) -> None:
        pass


class KeyAuth(Plugin):
    name, priority = "key-auth", 1250

    def __init__(self, gw: "Gateway", config: dict):
        self.gw = gw
        self.header = config.get("key_names", ["apikey"])[0].lower()

    def access(self, ctx: Ctx) -> Response | None:
        key = {k.lower(): v for k, v in ctx.headers.items()}.get(self.header)
        consumer = self.gw.keys.get(key or "")
        if not consumer:
            return 401, {"Content-Type": "application/json", "WWW-Authenticate": 'Key realm="gateway"'}, '{"message":"No API key found in request"}' if not key else '{"message":"Invalid authentication credentials"}'
        ctx.consumer = consumer
        ctx.headers["X-Consumer-Username"] = consumer
        return None


class RateLimiting(Plugin):
    name, priority = "rate-limiting", 910

    def __init__(self, gw: "Gateway", config: dict):
        self.gw = gw
        self.limit_by = config.get("limit_by", "consumer")  # consumer | ip | header
        self.header_name = config.get("header_name", "apikey").lower()
        self.capacity = float(config["capacity"])
        self.refill = float(config["refill_per_sec"])
        self.buckets: dict[str, TokenBucket] = {}

    def _identity(self, ctx: Ctx) -> str:
        if self.limit_by == "consumer" and ctx.consumer:
            return "consumer:" + ctx.consumer
        if self.limit_by == "header":
            return "key:" + {k.lower(): v for k, v in ctx.headers.items()}.get(self.header_name, "-")
        return "ip:" + ctx.client_ip  # Kong falls back to IP when no consumer is identified

    def access(self, ctx: Ctx) -> Response | None:
        ident = self._identity(ctx)
        now = self.gw.clock.now()
        b = self.buckets.setdefault(ident, TokenBucket(self.capacity, self.refill, self.capacity, now))
        ok, wait = b.take(now)
        ctx.extra_response_headers.update({"RateLimit-Limit": str(int(self.capacity)),
                                           "RateLimit-Remaining": str(int(b.tokens))})
        if not ok:
            retry = max(1, int(wait + 0.999))
            return 429, {"Retry-After": str(retry), "Content-Type": "application/json",
                         **ctx.extra_response_headers}, '{"message":"API rate limit exceeded"}'
        return None


class ResponseTransformer(Plugin):
    name, priority = "response-transformer", 800

    def __init__(self, gw: "Gateway", config: dict):
        self.add = {k: v for k, v in (h.split(":", 1) for h in config.get("add", {}).get("headers", []))}
        self.remove = [h.lower() for h in config.get("remove", {}).get("headers", [])]

    def header_filter(self, ctx: Ctx, headers: dict[str, str]) -> None:
        for k in [k for k in headers if k.lower() in self.remove]:
            del headers[k]
        headers.update(self.add)


class Cors(Plugin):
    name, priority = "cors", 2000

    def __init__(self, gw: "Gateway", config: dict):
        self.origins = set(config.get("origins", []))
        self.credentials = bool(config.get("credentials", False))

    def header_filter(self, ctx: Ctx, headers: dict[str, str]) -> None:
        origin = {k.lower(): v for k, v in ctx.headers.items()}.get("origin")
        headers["Vary"] = "Origin"
        if origin and origin in self.origins:
            headers["Access-Control-Allow-Origin"] = origin
            if self.credentials:
                headers["Access-Control-Allow-Credentials"] = "true"


PLUGINS = {p.name: p for p in (KeyAuth, RateLimiting, ResponseTransformer, Cors)}


# ------------------------------------------------------------------ gateway
class Gateway:
    """Declarative config shaped like Kong's decK file (simplified)."""

    def __init__(self, config: dict, upstreams: dict[str, Handler], clock: Clock | None = None):
        self.clock = clock or Clock()
        self.upstreams = upstreams
        self.keys: dict[str, str] = {}
        for c in config.get("consumers", []):
            for k in c.get("keyauth_credentials", []):
                self.keys[k["key"]] = c["username"]
        self.routes = []
        for svc in config["services"]:
            for r in svc.get("routes", []):
                plugins = [PLUGINS[p["name"]](self, p.get("config", {}))
                           for p in config.get("plugins", []) + svc.get("plugins", []) + r.get("plugins", [])]
                plugins.sort(key=lambda p: -p.priority)
                self.routes.append((r["paths"], r.get("methods"), svc["name"], plugins))

    def handle(self, method: str, path: str, headers: dict[str, str] | None = None, body: str = "",
               client_ip: str = "198.51.100.7") -> Response:
        headers = dict(headers or {})
        for paths, methods, svc, plugins in self.routes:
            if any(path == p or path.startswith(p.rstrip("/") + "/") for p in paths) and (not methods or method in methods):
                ctx = Ctx(method, path, headers, body, client_ip)
                for p in plugins:
                    early = p.access(ctx)
                    if early:
                        status, h, b = early
                        h = dict(h)
                        for q in plugins:
                            q.header_filter(ctx, h)
                        return status, h, b
                status, h, b = self.upstreams[svc](method, path, ctx.headers, body)
                h = dict(h)
                h.update(ctx.extra_response_headers)
                for p in plugins:
                    p.header_filter(ctx, h)
                return status, h, b
        return 404, {"Content-Type": "application/json"}, '{"message":"no Route matched"}'


def new_fake_api_key() -> str:
    """FAKE key generated at runtime; never commit real keys."""
    return "FAKE-" + secrets.token_hex(12)


def load_config(path: str | Path, keys: dict[str, str]) -> dict:
    """Load the JSON config and substitute ${KEY_<consumer>} placeholders with runtime FAKE keys."""
    text = Path(path).read_text(encoding="utf-8")
    for consumer, key in keys.items():
        text = text.replace("${KEY_" + consumer + "}", key)
    return json.loads(text)
