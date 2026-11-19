"""VULNERABLE password reset service (teaching code, in-process, fictional users).

Every flaw here is a real-world pattern:
predictable token, no expiry, reusable token, token stored and logged in clear,
user enumeration, reset link built from the Host header, sessions kept after reset,
no new-password policy, no rate limit.
"""
from __future__ import annotations

import hashlib
import time


def _pw_hash(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


class ResetService:
    name = "vulnerable"

    def __init__(self, clock=time.time, base_url: str = "https://shop.example"):
        self.clock = clock
        self.base_url = base_url
        self.users = {"alice@example.com": {"pw": _pw_hash("old-passphrase-alice-1"), "sessions": {"sess-a1"}},
                      "bob@example.com": {"pw": _pw_hash("old-passphrase-bob-22"), "sessions": {"sess-b1"}}}
        self.tokens: dict[str, dict] = {}  # what a database dump would show
        self.outbox: list[tuple[str, str]] = []
        self.log: list[str] = []

    def request_reset(self, email: str, host: str = "shop.example") -> tuple[int, str]:
        if email not in self.users:
            return 404, "No account with that email address"          # enumeration
        seed = f"{email}{int(self.clock())}"
        token = hashlib.md5(seed.encode()).hexdigest()[:16]             # predictable
        self.tokens[token] = {"email": email, "created": self.clock()}  # clear text, no expiry
        link = f"https://{host}/reset?token={token}"                    # Host header trusted
        self.outbox.append((email, link))
        self.log.append(f"sent reset link {link} to {email}")           # token in logs
        return 200, "Reset email sent"

    def reset(self, token: str, new_password: str) -> tuple[int, str]:
        rec = self.tokens.get(token)
        if rec is None:
            return 400, "Invalid token"
        user = self.users[rec["email"]]
        user["pw"] = _pw_hash(new_password)                              # no policy
        # token not deleted, sessions not revoked, no audit record
        return 200, "Password changed"

    def check_password(self, email: str, pw: str) -> bool:
        return self.users[email]["pw"] == _pw_hash(pw)

    def sessions(self, email: str) -> set[str]:
        return self.users[email]["sessions"]
