"""Insecure deserialization with Python pickle, made SAFE for a lab.

The "payload" only calls canary_hit(), a harmless function in this file that
appends to a list. It proves that unpickling attacker data runs a function of the
attacker's choice, which in real life would be os.system or similar. No shell, no
subprocess, no file system access happens here.

Defences shown:
  1. JSON + schema validation (data formats cannot carry code);
  2. a restricted Unpickler whose find_class() allowlists nothing dangerous;
  3. HMAC signing of blobs (integrity, defence in depth: useless if the key leaks).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import pickle
import secrets

CANARY: list[str] = []


def canary_hit(note: str) -> str:
    """Stand-in for 'attacker code'. Harmless: it only records that it ran."""
    CANARY.append(note)
    return "session-hijacked"


class CanaryPayload:
    """__reduce__ tells pickle: 'to rebuild me, call canary_hit("RCE...")'."""

    def __reduce__(self):
        return (canary_hit, ("RCE-CANARY: attacker-chosen function ran during unpickling",))


def make_malicious_cookie() -> str:
    return base64.b64encode(pickle.dumps({"user": "mallory", "prefs": CanaryPayload()})).decode()


def make_normal_cookie(user="alice") -> str:
    return base64.b64encode(pickle.dumps({"user": user, "prefs": {"theme": "dark"}})).decode()


# ---- vulnerable
def load_session_vuln(cookie: str):
    return pickle.loads(base64.b64decode(cookie))  # never do this with untrusted data


# ---- secure 1: JSON + schema
def dump_session_json(session: dict) -> str:
    return base64.b64encode(json.dumps(session).encode()).decode()


def load_session_json(cookie: str) -> dict:
    data = json.loads(base64.b64decode(cookie))
    if not isinstance(data, dict) or set(data) != {"user", "prefs"}:
        raise ValueError("bad session shape")
    if not isinstance(data["user"], str) or not isinstance(data["prefs"], dict):
        raise ValueError("bad session types")
    if any(k not in {"theme", "lang"} or not isinstance(v, str) for k, v in data["prefs"].items()):
        raise ValueError("bad prefs")
    return data


# ---- secure 2: restricted unpickler (if you truly cannot leave pickle yet)
class RestrictedUnpickler(pickle.Unpickler):
    ALLOWED: set[tuple[str, str]] = set()  # plain dict/list/str/int need no globals at all

    def find_class(self, module, name):
        if (module, name) in self.ALLOWED:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"global {module}.{name} is forbidden")


def load_session_restricted(cookie: str):
    return RestrictedUnpickler(io.BytesIO(base64.b64decode(cookie))).load()


# ---- defence in depth: signed blobs
KEY = secrets.token_bytes(32)


def sign(cookie: str) -> str:
    return cookie + "." + hmac.new(KEY, cookie.encode(), hashlib.sha256).hexdigest()


def verify_and_split(signed: str) -> str:
    cookie, _, mac = signed.rpartition(".")
    if not hmac.compare_digest(mac, hmac.new(KEY, cookie.encode(), hashlib.sha256).hexdigest()):
        raise ValueError("bad signature")
    return cookie
