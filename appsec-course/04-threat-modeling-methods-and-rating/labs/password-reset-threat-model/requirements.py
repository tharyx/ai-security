"""Security requirements written FROM the password-reset threat model.

Each requirement names the STRIDE threat it answers and an executable check (an attack
from attacks.py that must FAIL). This is "threat -> requirement -> test" in code.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from aisec_lab import load_lab_module

A = load_lab_module(__file__, "attacks")  # sibling module, loaded by path


@dataclass
class Requirement:
    id: str
    stride: str
    threat: str
    text: str
    attack: Callable  # (svc, clock) -> bool, True = attack worked


REQUIREMENTS = [
    Requirement("SR-01", "S", "Attacker predicts the victim's reset token",
                "Generate reset tokens with a CSPRNG (at least 128 bits of entropy).",
                lambda s, c: A.predict_token(s, c)),
    Requirement("SR-02", "I", "Reset form reveals which emails have accounts",
                "Return the same status and message whether or not the account exists.",
                lambda s, c: bool(A.enumerate_users(s, ["alice@example.com", "carol@example.com"]))),
    Requirement("SR-03", "T", "Tampered Host header sends the link to the attacker's domain",
                "Build reset links from a configured base URL, never from request headers.",
                lambda s, c: A.host_header_poisoning(s)),
    Requirement("SR-04", "S", "A used reset link is replayed",
                "Reset tokens are single use and older tokens are invalidated.",
                lambda s, c: A.replay_token(s)),
    Requirement("SR-05", "S", "An old reset email in a breached mailbox still works",
                "Reset tokens expire after at most 15 minutes.",
                lambda s, c: A.use_expired_token(s, c)),
    Requirement("SR-06", "I", "A database dump yields usable tokens",
                "Store only a hash of the reset token.",
                lambda s, c: A.token_from_db_dump(s)),
    Requirement("SR-07", "I", "Tokens leak through application logs",
                "Never write reset tokens or links to logs.",
                lambda s, c: A.token_in_logs(s)),
    Requirement("SR-08", "E", "Attacker's existing session survives the victim's reset",
                "Revoke all sessions and refresh tokens after a password reset.",
                lambda s, c: A.session_survives_reset(s)),
    Requirement("SR-09", "S", "New password is trivially guessable",
                "Enforce minimum length (15 for single-factor) and a common-password blocklist.",
                lambda s, c: A.weak_password_accepted(s)),
    Requirement("SR-10", "D", "Reset emails flood a victim's mailbox (and cost money)",
                "Send at most 3 reset emails per account per hour.",
                lambda s, c: A.mailbox_flood(s)),
    Requirement("SR-11", "R", "Nobody can tell when or for whom a reset happened",
                "Write an audit event (no secrets) for every completed reset.",
                lambda s, c: A.no_audit_record(s)),
]


def verify(service_cls) -> dict[str, bool]:
    """Run every requirement against a FRESH service instance. True = requirement met."""
    results = {}
    for req in REQUIREMENTS:
        clock = A.Clock()
        svc = service_cls(clock=clock)
        results[req.id] = not req.attack(svc, clock)
    return results
