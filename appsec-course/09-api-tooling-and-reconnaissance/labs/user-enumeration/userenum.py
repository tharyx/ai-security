"""User-account enumeration from response differences, and the uniform-response fix.

Covers "Enumerating User Accounts From an AP[I]". Two login/registration/reset
endpoints are modelled in-process:

* ``VulnerableAuth`` leaks whether an account exists through the status code,
  the message body, and even response timing (a real password hash is only
  checked when the user exists, so present users answer more slowly).
* ``SecureAuth`` returns the SAME status, the SAME generic message, and does
  constant work whether or not the account exists, so enumeration fails.

The timing is simulated with a counted "work" value, not real sleeps, so tests
are fast and deterministic.

Only test systems you own or have written permission to test.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AuthResponse:
    status: int
    message: str
    work_units: int  # stand-in for response time; higher = slower


class VulnerableAuth:
    """Leaks account existence three different ways."""

    def __init__(self, users: dict):
        self.users = dict(users)  # username -> password

    def login(self, username: str, password: str) -> AuthResponse:
        if username not in self.users:
            # fast: no hash to check, and a specific message
            return AuthResponse(404, "No account with that username", work_units=1)
        # slow: we 'verify the password hash' (simulated work)
        work = 10
        if self.users[username] == password:
            return AuthResponse(200, "Welcome", work_units=work)
        return AuthResponse(401, "Wrong password", work_units=work)

    def register(self, username: str) -> AuthResponse:
        if username in self.users:
            return AuthResponse(409, "Username already taken", work_units=1)
        return AuthResponse(201, "Registered", work_units=1)

    def reset(self, username: str) -> AuthResponse:
        if username in self.users:
            return AuthResponse(200, "Reset link sent", work_units=1)
        return AuthResponse(404, "Unknown user", work_units=1)


class SecureAuth:
    """Uniform status, uniform message, constant work."""

    GENERIC = "If the credentials are valid you will be signed in"

    def __init__(self, users: dict):
        self.users = dict(users)

    def login(self, username: str, password: str) -> AuthResponse:
        # Always do the 'hash check' work, even for a missing user, against a
        # fixed dummy value, so timing is constant.
        exists = username in self.users
        _ = self.users.get(username, "dummy-value-of-fixed-length") == password
        if exists and self.users[username] == password:
            return AuthResponse(200, "Welcome", work_units=10)
        # Same status and message for "no such user" and "wrong password".
        return AuthResponse(401, self.GENERIC, work_units=10)

    def register(self, username: str) -> AuthResponse:
        # Do not confirm or deny; send a message to the address on file instead.
        return AuthResponse(202, "Check your email to finish signing up", work_units=1)

    def reset(self, username: str) -> AuthResponse:
        # Same answer whether or not the account exists.
        return AuthResponse(200, "If that account exists, a reset link was sent", work_units=1)


def enumerate_users(auth, candidates: list) -> list:
    """Try each candidate username with a wrong password and infer existence
    from the response status, message and work (timing). Return the usernames
    the attacker concludes exist.
    """
    # Learn the "missing user" fingerprint from an obviously-bogus name.
    baseline = auth.login("zzz-definitely-not-a-user-zzz", "x")
    found = []
    for name in candidates:
        r = auth.login(name, "wrong-password")
        differs = (r.status != baseline.status
                   or r.message != baseline.message
                   or r.work_units != baseline.work_units)
        if differs:
            found.append(name)
    return found
