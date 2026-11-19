"""Mass assignment: the API binds every JSON field the client sends onto the model.

Vulnerable: user.__dict__.update(body). An attacker adds "is_admin": true,
"credit": 100000 or "account_id": 7 and the server stores them.
Secure: an explicit input schema (DTO) per operation: allowlisted fields, types,
lengths, and unknown fields rejected with 422 (not silently dropped, so tests notice).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass


@dataclass
class User:
    id: int
    email: str
    display_name: str
    is_admin: bool = False
    credit: int = 0
    email_verified: bool = False


class Store:
    def __init__(self):
        self.users = {1: User(1, "alice@lab.example", "Alice")}


def update_profile_vuln(store: Store, uid: int, raw: str):
    user = store.users[uid]
    user.__dict__.update(json.loads(raw))  # every field from the client
    return 200, asdict(user)


PROFILE_SCHEMA = {"display_name": (str, 1, 40), "email": (str, 5, 120)}


def update_profile_safe(store: Store, uid: int, raw: str):
    body = json.loads(raw)
    unknown = set(body) - set(PROFILE_SCHEMA)
    if unknown:
        return 422, {"error": f"unknown or read-only fields: {sorted(unknown)}"}
    for field, (typ, lo, hi) in PROFILE_SCHEMA.items():
        if field in body and not (isinstance(body[field], typ) and lo <= len(body[field]) <= hi):
            return 422, {"error": f"invalid {field}"}
    user = store.users[uid]
    if "email" in body and body["email"] != user.email:
        user.email_verified = False  # server-owned state follows a server rule
    for k in ("display_name", "email"):
        if k in body:
            setattr(user, k, body[k])
    out = asdict(user)
    return 200, {k: out[k] for k in ("id", "email", "display_name")}  # output schema too
