"""Attacks against the lab's OWN toy reset services. Each returns True if the attack worked.

Only test systems you own or have written permission to test.
"""
from __future__ import annotations

import hashlib

VICTIM = "alice@example.com"
NEW_PW = "attacker-chosen-passphrase-9"  # FAKE value, long enough to pass any policy


class Clock:
    """A controllable clock so tests can travel in time."""

    def __init__(self, now: float = 1_800_000_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


def _token(link: str) -> str:
    return link.split("token=", 1)[1]


def predict_token(svc, clock: Clock) -> bool:
    """Trigger a reset for the victim, then guess md5(email + unix time) around 'now'."""
    svc.request_reset(VICTIM)
    for delta in range(-3, 4):
        guess = hashlib.md5(f"{VICTIM}{int(clock()) + delta}".encode()).hexdigest()[:16]
        if svc.reset(guess, NEW_PW)[0] == 200:
            return svc.check_password(VICTIM, NEW_PW)
    return False


def enumerate_users(svc, candidates: list[str]) -> set[str]:
    """Compare each answer with the answer for an address that surely does not exist."""
    baseline = svc.request_reset("no-such-user-zz@example.com")
    return {c for c in candidates if svc.request_reset(c) != baseline}


def host_header_poisoning(svc) -> bool:
    svc.request_reset(VICTIM, host="attacker.example")
    return svc.outbox[-1][1].startswith("https://attacker.example")


def replay_token(svc) -> bool:
    svc.request_reset(VICTIM)
    tok = _token(svc.outbox[-1][1])
    svc.reset(tok, "victim-new-passphrase-2026")  # the victim uses the link
    return svc.reset(tok, NEW_PW)[0] == 200        # an attacker who saw the link uses it again


def use_expired_token(svc, clock: Clock) -> bool:
    svc.request_reset(VICTIM)
    tok = _token(svc.outbox[-1][1])
    clock.now += 2 * 24 * 3600                     # two days later (old email in a breached mailbox)
    return svc.reset(tok, NEW_PW)[0] == 200


def token_from_db_dump(svc) -> bool:
    svc.request_reset(VICTIM)
    return any(svc.reset(stored_key, NEW_PW)[0] == 200 for stored_key in list(svc.tokens))


def token_in_logs(svc) -> bool:
    svc.request_reset(VICTIM)
    tok = _token(svc.outbox[-1][1])
    return any(tok in line for line in svc.log)


def session_survives_reset(svc) -> bool:
    svc.request_reset(VICTIM)
    before = set(svc.sessions(VICTIM))
    svc.reset(_token(svc.outbox[-1][1]), "victim-new-passphrase-2026")
    return bool(before & svc.sessions(VICTIM))


def weak_password_accepted(svc) -> bool:
    svc.request_reset(VICTIM)
    return svc.reset(_token(svc.outbox[-1][1]), "password")[0] == 200


def mailbox_flood(svc, n: int = 20) -> bool:
    for _ in range(n):
        svc.request_reset(VICTIM)
    return sum(1 for to, _ in svc.outbox if to == VICTIM) > 3


def no_audit_record(svc) -> bool:
    svc.request_reset(VICTIM)
    svc.reset(_token(svc.outbox[-1][1]), "victim-new-passphrase-2026")
    return not any(line.startswith("AUDIT") for line in svc.log)
