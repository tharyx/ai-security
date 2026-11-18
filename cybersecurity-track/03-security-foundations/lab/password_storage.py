"""Password storage done wrong and right, plus a dictionary attack on synthetic hashes.

Three storage schemes:
  plain   - the password itself (worst)
  md5     - unsalted MD5: fast and identical for identical passwords (bad)
  pbkdf2  - salted PBKDF2-HMAC-SHA256 with many iterations (acceptable; Argon2id or
            bcrypt are better in production, but hashlib has PBKDF2 and scrypt built in)

All data is synthetic. Never use MD5 for passwords in real systems.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

DEFAULT_ITERATIONS = 50_000  # lab value, so the demo is quick. Real systems use far more.


@dataclass(frozen=True)
class Record:
    username: str
    scheme: str      # "plain" | "md5" | "pbkdf2"
    stored: str      # what the database holds
    salt: str = ""   # hex, only for pbkdf2
    iterations: int = 0


def store_plain(username: str, password: str) -> Record:
    return Record(username, "plain", password)


def store_md5(username: str, password: str) -> Record:
    return Record(username, "md5", hashlib.md5(password.encode()).hexdigest())


def store_pbkdf2(username: str, password: str, iterations: int = DEFAULT_ITERATIONS,
                 salt: bytes | None = None) -> Record:
    salt = salt if salt is not None else os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return Record(username, "pbkdf2", digest.hex(), salt.hex(), iterations)


def verify(record: Record, candidate: str) -> bool:
    """Check a candidate password against a record (constant-time compare)."""
    if record.scheme == "plain":
        return hmac.compare_digest(record.stored.encode(), candidate.encode())
    if record.scheme == "md5":
        return hmac.compare_digest(record.stored, hashlib.md5(candidate.encode()).hexdigest())
    if record.scheme == "pbkdf2":
        digest = hashlib.pbkdf2_hmac("sha256", candidate.encode(), bytes.fromhex(record.salt),
                                     record.iterations)
        return hmac.compare_digest(record.stored, digest.hex())
    raise ValueError(f"unknown scheme: {record.scheme}")


def dictionary_attack(records: list[Record], wordlist: list[str]) -> dict:
    """Try every word against every record. Returns cracked passwords and the work done.

    The attacker only needs the stolen table, not the application. The `hashes_computed`
    counter shows why salting and slow hashing matter: it is the attacker's real cost.
    """
    cracked: dict[str, str] = {}
    hashes_computed = 0
    for rec in records:
        for word in wordlist:
            if rec.scheme != "plain":
                hashes_computed += 1
            if verify(rec, word):
                cracked[rec.username] = word
                break
    return {"cracked": cracked, "hashes_computed": hashes_computed}


def md5_precomputed_attack(records: list[Record], wordlist: list[str]) -> dict:
    """Unsalted MD5 lets the attacker hash the wordlist ONCE and reuse it for every user."""
    table = {hashlib.md5(w.encode()).hexdigest(): w for w in wordlist}
    cracked = {r.username: table[r.stored] for r in records
               if r.scheme == "md5" and r.stored in table}
    return {"cracked": cracked, "hashes_computed": len(wordlist)}


def duplicate_hashes(records: list[Record]) -> list[list[str]]:
    """Group users whose stored value is identical (leaks 'same password' information)."""
    groups: dict[str, list[str]] = {}
    for r in records:
        groups.setdefault(r.stored, []).append(r.username)
    return [sorted(users) for users in groups.values() if len(users) > 1]


def load_wordlist(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
