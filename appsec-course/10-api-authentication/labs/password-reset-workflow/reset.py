"""Password reset workflows: a flawed one and a safe one.

Covers "Password Reset Workflows" and "Secure Authentication Workflows".

VulnerableReset has four classic flaws:
  1. predictable token (derived from the username and a coarse timestamp),
  2. no expiry and reusable (not single-use),
  3. the reset link is built from the client-supplied Host header (host-header
     poisoning sends the victim's token to the attacker's domain),
  4. the response says whether the account exists (enumeration).

SecureReset: 32 random bytes from ``secrets``, only a SHA-256 of the token is
stored, 15-minute expiry, single use, all other tokens revoked on success,
link built from a configured base URL, and a uniform response.

Only test systems you own or have written permission to test.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets


class VulnerableReset:
    def __init__(self, users: dict):
        self.users = dict(users)  # username -> password
        self.tokens: dict = {}  # token -> username
        self.outbox: list = []  # emails "sent": (user, link)

    @staticmethod
    def make_token(username: str, now: int) -> str:
        # FLAW 1: md5(username + minute) is guessable
        return hashlib.md5(f"{username}{now // 60}".encode()).hexdigest()[:12]

    def request(self, username: str, host_header: str, now: int) -> str:
        if username not in self.users:
            return "unknown user"  # FLAW 4: enumeration
        tok = self.make_token(username, now)
        self.tokens[tok] = username  # FLAW 2: no expiry
        self.outbox.append((username, f"https://{host_header}/reset?token={tok}"))  # FLAW 3
        return "reset link sent"

    def confirm(self, token: str, new_pw: str, now: int) -> bool:
        user = self.tokens.get(token)  # FLAW 2: never deleted -> reusable
        if not user:
            return False
        self.users[user] = new_pw
        return True


class SecureReset:
    TTL = 15 * 60
    BASE_URL = "https://shop.lab.example"  # from config, never from the request

    def __init__(self, users: dict):
        self.users = dict(users)
        self.tokens: dict = {}  # sha256(token) -> (username, expires_at)
        self.outbox: list = []

    def request(self, username: str, host_header: str, now: int) -> str:
        if username in self.users:
            tok = secrets.token_urlsafe(32)
            digest = hashlib.sha256(tok.encode()).hexdigest()
            self.tokens[digest] = (username, now + self.TTL)
            self.outbox.append((username, f"{self.BASE_URL}/reset?token={tok}"))
        return "If that account exists, a reset link was sent"

    def confirm(self, token: str, new_pw: str, now: int) -> bool:
        digest = hashlib.sha256(token.encode()).hexdigest()
        match = next((d for d in self.tokens if hmac.compare_digest(d, digest)), None)
        if match is None:
            return False
        user, expires = self.tokens.pop(match)  # single use
        if now > expires:
            return False
        if len(new_pw) < 15:  # NIST 800-63B-4 style length rule when password is the only factor
            return False
        self.users[user] = new_pw
        # revoke every other outstanding token for this user
        self.tokens = {d: v for d, v in self.tokens.items() if v[0] != user}
        return True


def token_from_link(link: str) -> str:
    return link.split("token=", 1)[1]
