"""Rate limiting algorithms, request throttling, and limits at different stages.

Algorithms (all take an explicit `now` so tests never sleep):
  FixedWindow         simple counter per window; allows a 2x burst at the window boundary
  SlidingWindowLog    exact: keeps a timestamp per request
  SlidingWindowCounter approximate: weighted previous + current window (what many gateways use)
  TokenBucket         average rate with a bounded burst

Throttler: instead of rejecting at once, delay (queue) requests up to a maximum wait, then 429.

LayeredEdge: one request passes reverse proxy -> load balancer -> API gateway + WAF -> application.
Each stage limits by a different identity, so each stops a different attack.
"""
from __future__ import annotations

import math
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field


class FixedWindow:
    def __init__(self, limit: int, window: float):
        self.limit, self.window = limit, window
        self.counts: dict[tuple[str, int], int] = defaultdict(int)

    def allow(self, key: str, now: float) -> tuple[bool, float]:
        w = int(now // self.window)
        if self.counts[(key, w)] < self.limit:
            self.counts[(key, w)] += 1
            return True, 0.0
        return False, (w + 1) * self.window - now


class SlidingWindowLog:
    def __init__(self, limit: int, window: float):
        self.limit, self.window = limit, window
        self.log: dict[str, deque] = defaultdict(deque)

    def allow(self, key: str, now: float) -> tuple[bool, float]:
        q = self.log[key]
        while q and q[0] <= now - self.window:
            q.popleft()
        if len(q) < self.limit:
            q.append(now)
            return True, 0.0
        return False, q[0] + self.window - now


class SlidingWindowCounter:
    def __init__(self, limit: int, window: float):
        self.limit, self.window = limit, window
        self.counts: dict[tuple[str, int], int] = defaultdict(int)

    def allow(self, key: str, now: float) -> tuple[bool, float]:
        w = int(now // self.window)
        elapsed = (now - w * self.window) / self.window
        estimate = self.counts[(key, w - 1)] * (1 - elapsed) + self.counts[(key, w)]
        if estimate < self.limit:
            self.counts[(key, w)] += 1
            return True, 0.0
        return False, max(1.0, (1 - elapsed) * self.window / 2)


class TokenBucket:
    def __init__(self, capacity: float, refill_per_sec: float):
        self.capacity, self.rate = capacity, refill_per_sec
        self.state: dict[str, tuple[float, float]] = {}

    def allow(self, key: str, now: float) -> tuple[bool, float]:
        tokens, last = self.state.get(key, (self.capacity, now))
        tokens = min(self.capacity, tokens + (now - last) * self.rate)
        if tokens >= 1:
            self.state[key] = (tokens - 1, now)
            return True, 0.0
        self.state[key] = (tokens, now)
        return False, (1 - tokens) / self.rate


def http_response(allowed: bool, retry_after: float, limit: int) -> tuple[int, dict[str, str]]:
    if allowed:
        return 200, {"RateLimit-Limit": str(limit)}
    return 429, {"Retry-After": str(max(1, math.ceil(retry_after))), "RateLimit-Limit": str(limit),
                 "RateLimit-Remaining": "0"}


def accepted_in(limiter, times: list[float], key: str = "k") -> int:
    return sum(limiter.allow(key, t)[0] for t in times)


# ------------------------------------------------------------------ throttling (delay instead of reject)
class Throttler:
    """Leaky-bucket style: requests are spaced `1/rate` apart. A request that would wait longer
    than `max_wait` is rejected with 429. Returns (status, delay_seconds)."""

    def __init__(self, rate_per_sec: float, max_wait: float):
        self.interval, self.max_wait = 1.0 / rate_per_sec, max_wait
        self.next_free: dict[str, float] = {}

    def submit(self, key: str, now: float) -> tuple[int, float]:
        start = max(now, self.next_free.get(key, now))
        delay = start - now
        if delay > self.max_wait:
            return 429, delay
        self.next_free[key] = start + self.interval
        return 200, delay


# ------------------------------------------------------------------ limits at different stages
SQLI_SIGNATURE = re.compile(r"('|%27)\s*(or|union)\b|--|;\s*drop\b", re.I)


@dataclass
class Request:
    ip: str
    path: str
    api_key: str | None = None
    account: str | None = None
    body: str = ""


@dataclass
class LayeredEdge:
    proxy_per_ip: SlidingWindowLog = field(default_factory=lambda: SlidingWindowLog(30, 60))
    lb_global: TokenBucket = field(default_factory=lambda: TokenBucket(200, 50))
    gw_per_key: TokenBucket = field(default_factory=lambda: TokenBucket(20, 1))
    app_per_account: SlidingWindowLog = field(default_factory=lambda: SlidingWindowLog(5, 900))
    stage_hits: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def handle(self, r: Request, now: float) -> tuple[int, str]:
        # 1. reverse proxy (NGINX limit_req style): per client IP, cheapest place to drop floods
        if not self.proxy_per_ip.allow(r.ip, now)[0]:
            self.stage_hits["reverse-proxy"] += 1
            return 429, "reverse-proxy: per-IP limit"
        # 2. load balancer: protects total capacity (connection/request budget for the whole pool)
        if not self.lb_global.allow("pool", now)[0]:
            self.stage_hits["load-balancer"] += 1
            return 503, "load-balancer: pool capacity"
        # 3. API gateway + WAF: identity-aware quotas and signatures
        if SQLI_SIGNATURE.search(r.body):
            self.stage_hits["waf"] += 1
            return 403, "waf: injection signature"
        if r.api_key is None:
            return 401, "gateway: no API key"
        if not self.gw_per_key.allow(r.api_key, now)[0]:
            self.stage_hits["api-gateway"] += 1
            return 429, "api-gateway: per-key quota"
        # 4. application: business-aware limit (per target account on login)
        if r.path == "/login" and r.account and not self.app_per_account.allow(r.account, now)[0]:
            self.stage_hits["application"] += 1
            return 429, "application: per-account login attempts"
        return 200, "ok"
