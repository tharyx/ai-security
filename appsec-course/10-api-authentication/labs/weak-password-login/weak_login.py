"""Exploiting weak passwords by online guessing, and stopping it with account
lockout and rate limiting.

Covers "Exploiting Broken Authentication With Weak Passwords", "Account
Lockouts" and "Rate Limiting". An attacker runs a small dictionary against a
login. ``OpenLogin`` has no throttle, so the weak password falls. ``GuardedLogin``
adds a per-account lockout after N failures and a per-IP token-bucket rate
limit, so the same dictionary run is stopped early.

All passwords are toy lab values. Only test systems you own or have written
permission to test.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field


class OpenLogin:
    """No throttle, no lockout. Weak passwords are easy to guess online."""

    def __init__(self, users: dict):
        self.users = dict(users)
        self.attempts = 0

    def attempt(self, username: str, password: str, ip: str = "1.1.1.1") -> str:
        self.attempts += 1
        if self.users.get(username) == password:
            return "ok"
        return "fail"


@dataclass
class _Bucket:
    tokens: float
    updated: float


class GuardedLogin:
    """Per-account lockout + per-IP token-bucket rate limit."""

    def __init__(self, users: dict, max_failures: int = 5,
                 rate_per_sec: float = 1.0, burst: int = 5):
        self.users = dict(users)
        self.max_failures = max_failures
        self.rate = rate_per_sec
        self.burst = burst
        self.failures: dict = {}
        self.locked: set = set()
        self.buckets: dict = {}
        self.attempts = 0

    def _rate_ok(self, ip: str, now: float) -> bool:
        b = self.buckets.get(ip)
        if b is None:
            self.buckets[ip] = _Bucket(tokens=self.burst - 1, updated=now)
            return True
        # refill
        b.tokens = min(self.burst, b.tokens + (now - b.updated) * self.rate)
        b.updated = now
        if b.tokens >= 1:
            b.tokens -= 1
            return True
        return False

    def attempt(self, username: str, password: str, ip: str = "9.9.9.9",
                now: float | None = None) -> str:
        now = time.time() if now is None else now
        self.attempts += 1
        if not self._rate_ok(ip, now):
            return "rate_limited"
        if username in self.locked:
            return "locked"
        if self.users.get(username) == password:
            self.failures.pop(username, None)
            return "ok"
        self.failures[username] = self.failures.get(username, 0) + 1
        if self.failures[username] >= self.max_failures:
            self.locked.add(username)
            return "locked"
        return "fail"


def dictionary_attack(login, username: str, wordlist: list,
                      ip: str = "6.6.6.6", clock=None) -> dict:
    """Try each password in order. Returns the outcome and how far it got."""
    now = 0.0
    for i, pw in enumerate(wordlist, start=1):
        kwargs = {}
        if isinstance(login, GuardedLogin):
            kwargs = {"now": now}
            now += 0.01  # attacker fires fast: 100 req/s
        result = login.attempt(username, pw, ip=ip, **kwargs)
        if result == "ok":
            return {"cracked": True, "password": pw, "tries": i}
        if result in ("locked", "rate_limited"):
            return {"cracked": False, "stopped_by": result, "tries": i}
    return {"cracked": False, "stopped_by": "exhausted", "tries": len(wordlist)}


# a tiny attacker dictionary; the real password sits near the end
ATTACK_WORDLIST = ["123456", "password", "qwerty", "letmein", "admin",
                   "welcome", "monkey", "dragon", "sunshine", "p@ssw0rd"]
