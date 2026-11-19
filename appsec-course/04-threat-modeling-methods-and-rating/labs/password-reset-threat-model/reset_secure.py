"""SECURE password reset service (teaching code, in-process, fictional users).

Controls: CSPRNG token (secrets), only a SHA-256 hash stored, 15-minute expiry, single use,
older tokens invalidated, uniform response, link from a configured base URL, no token in
logs, rate limit per account, new-password policy (length + blocklist), all sessions
revoked after reset, audit event recorded.
"""
from __future__ import annotations

import hashlib
import secrets
import time

TOKEN_TTL = 15 * 60
MAX_REQUESTS_PER_HOUR = 3
MIN_LENGTH = 15  # NIST SP 800-63B-4 guidance for single-factor passwords (verify at source)
BLOCKLIST = {"password", "passwordpassword", "123456789012345", "qwertyuiopasdfg", "letmeinletmein!"}
GENERIC = "If an account exists for that address, we have sent a reset link."


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _pw_hash(pw: str, salt: bytes) -> str:
    # Small iteration count keeps the lab fast. Production: Argon2id, or PBKDF2 ~600k iterations.
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 1000).hex()


class ResetService:
    name = "secure"

    def __init__(self, clock=time.time, base_url: str = "https://shop.example"):
        self.clock = clock
        self.base_url = base_url
        self.users: dict[str, dict] = {}
        for email, pw, sess in (("alice@example.com", "old-passphrase-alice-1", "sess-a1"),
                                ("bob@example.com", "old-passphrase-bob-22", "sess-b1")):
            salt = secrets.token_bytes(16)
            self.users[email] = {"salt": salt, "pw": _pw_hash(pw, salt), "sessions": {sess}}
        self.tokens: dict[str, dict] = {}  # key = SHA-256(token): a DB dump gives no usable token
        self.outbox: list[tuple[str, str]] = []
        self.log: list[str] = []
        self._requests: dict[str, list[float]] = {}

    def request_reset(self, email: str, host: str = "ignored") -> tuple[int, str]:
        now = self.clock()
        recent = [t for t in self._requests.get(email, []) if now - t < 3600]
        self._requests[email] = recent + [now]
        if email not in self.users or len(recent) >= MAX_REQUESTS_PER_HOUR:
            self.log.append("reset requested (no email sent)")
            return 202, GENERIC
        for k in [k for k, v in self.tokens.items() if v["email"] == email]:
            del self.tokens[k]  # only the newest token is valid
        token = secrets.token_urlsafe(32)
        self.tokens[_sha(token)] = {"email": email, "expires": now + TOKEN_TTL, "used": False}
        self.outbox.append((email, f"{self.base_url}/reset?token={token}"))
        self.log.append("reset requested (email sent)")
        return 202, GENERIC

    def reset(self, token: str, new_password: str) -> tuple[int, str]:
        rec = self.tokens.get(_sha(token))
        if rec is None or rec["used"] or self.clock() > rec["expires"]:
            return 400, "This link is invalid or has expired. Request a new one."
        if len(new_password) < MIN_LENGTH or new_password.lower() in BLOCKLIST:
            return 422, f"Choose a password of at least {MIN_LENGTH} characters that is not a common password."
        user = self.users[rec["email"]]
        user["salt"] = secrets.token_bytes(16)
        user["pw"] = _pw_hash(new_password, user["salt"])
        rec["used"] = True
        user["sessions"].clear()  # log out everywhere
        self.log.append(f"AUDIT password_reset user={_sha(rec['email'])[:12]} at={int(self.clock())}")
        return 200, "Password changed. Please sign in again."

    def check_password(self, email: str, pw: str) -> bool:
        u = self.users[email]
        return u["pw"] == _pw_hash(pw, u["salt"])

    def sessions(self, email: str) -> set[str]:
        return self.users[email]["sessions"]
