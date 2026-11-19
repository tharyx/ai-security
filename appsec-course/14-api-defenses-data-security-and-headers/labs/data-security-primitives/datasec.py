"""Encoding vs escaping vs hashing vs encryption, with the standard library only.

!!! NOT FOR PRODUCTION !!!
`ToyAEAD` below is a TEACHING cipher: an HMAC-SHA256 keystream (counter mode) plus an
HMAC-SHA256 tag (encrypt-then-MAC). It exists so the lab can show nonces, tags, associated
data and key rotation without a third-party package. Real systems use a vetted AEAD such as
AES-256-GCM or ChaCha20-Poly1305 from a maintained library (for example `cryptography`),
or a KMS / Vault Transit, and never hand-rolled crypto.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import sqlite3
import urllib.parse
from dataclasses import dataclass, field


# ------------------------------------------------------------------ 1. encoding
def encode_all(value: str) -> dict[str, str]:
    """Encodings change REPRESENTATION. No key: anyone can reverse them."""
    raw = value.encode()
    return {
        "base64": base64.b64encode(raw).decode(),
        "base64url": base64.urlsafe_b64encode(raw).decode().rstrip("="),
        "hex": raw.hex(),
        "url": urllib.parse.quote(value, safe=""),
    }


def decode(kind: str, encoded: str) -> str:
    if kind == "base64":
        return base64.b64decode(encoded).decode()
    if kind == "base64url":
        return base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode()
    if kind == "hex":
        return bytes.fromhex(encoded).decode()
    if kind == "url":
        return urllib.parse.unquote(encoded)
    raise ValueError(kind)


# ------------------------------------------------------------------ 2. escaping
def escape_for(context: str, value: str) -> str:
    """Escaping makes data safe for ONE interpreter. The right escape depends on the context."""
    if context == "html":
        return html.escape(value, quote=True)
    if context == "js_string":
        # JSON string literal, then neutralize characters that can end a <script> block
        return json.dumps(value).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    if context == "url_param":
        return urllib.parse.quote(value, safe="")
    raise ValueError(context)


def sql_lookup(conn: sqlite3.Connection, name: str, safe: bool) -> list[tuple]:
    """For SQL, do not escape: use bind variables (like Oracle :name binds)."""
    if safe:
        return conn.execute("SELECT name, role FROM users WHERE name = ?", (name,)).fetchall()
    return conn.execute(f"SELECT name, role FROM users WHERE name = '{name}'").fetchall()  # VULNERABLE


# ------------------------------------------------------------------ 3. hashing
def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def reverse_low_entropy_hash(target_hex: str, digits: int = 4) -> str | None:
    """A plain hash of a small input space (PINs, phone numbers, last-4 of a card) is reversible
    by enumeration. Returns the input when found."""
    for n in range(10 ** digits):
        guess = f"{n:0{digits}d}"
        if sha256_hex(guess) == target_hex:
            return guess
    return None


def keyed_pseudonym(key: bytes, value: str) -> str:
    """HMAC with a secret key: same input -> same token (joins still work), but without the key
    you cannot enumerate. Good for pseudonymizing identifiers in analytics or logs."""
    return hmac.new(key, value.encode(), hashlib.sha256).hexdigest()


def integrity_tag(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def verify_tag(key: bytes, message: bytes, tag: str) -> bool:
    return hmac.compare_digest(integrity_tag(key, message), tag)


# ------------------------------------------------------------------ 4. encryption (TOY, NOT FOR PRODUCTION)
class IntegrityError(Exception):
    pass


class ToyAEAD:
    """NOT FOR PRODUCTION. Shape of an AEAD: encrypt(key, nonce, plaintext, aad) -> ciphertext||tag."""

    NONCE = 16
    TAG = 32

    def __init__(self, key: bytes):
        if len(key) < 32:
            raise ValueError("key must be at least 32 random bytes")
        self._enc = hmac.new(key, b"enc", hashlib.sha256).digest()
        self._mac = hmac.new(key, b"mac", hashlib.sha256).digest()

    def _stream(self, nonce: bytes, n: int) -> bytes:
        out, ctr = b"", 0
        while len(out) < n:
            out += hmac.new(self._enc, nonce + ctr.to_bytes(8, "big"), hashlib.sha256).digest()
            ctr += 1
        return out[:n]

    def encrypt(self, plaintext: bytes, aad: bytes = b"", nonce: bytes | None = None) -> bytes:
        nonce = nonce or os.urandom(self.NONCE)
        ct = bytes(a ^ b for a, b in zip(plaintext, self._stream(nonce, len(plaintext))))
        tag = hmac.new(self._mac, len(aad).to_bytes(8, "big") + aad + nonce + ct, hashlib.sha256).digest()
        return nonce + ct + tag

    def decrypt(self, blob: bytes, aad: bytes = b"") -> bytes:
        nonce, ct, tag = blob[: self.NONCE], blob[self.NONCE: -self.TAG], blob[-self.TAG:]
        want = hmac.new(self._mac, len(aad).to_bytes(8, "big") + aad + nonce + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, want):
            raise IntegrityError("tag mismatch: ciphertext, nonce or associated data was changed")
        return bytes(a ^ b for a, b in zip(ct, self._stream(nonce, len(ct))))


@dataclass
class KeyRing:
    """Envelope-style key versions: new data uses the active key; old data still decrypts;
    `rewrap` moves old records to the new key (like Vault Transit `rewrap`)."""

    keys: dict[str, bytes] = field(default_factory=dict)
    active: str = ""

    def rotate(self) -> str:
        kid = f"k{len(self.keys) + 1}"
        self.keys[kid] = os.urandom(32)
        self.active = kid
        return kid

    def seal(self, plaintext: str, aad: str) -> str:
        blob = ToyAEAD(self.keys[self.active]).encrypt(plaintext.encode(), aad.encode())
        return f"{self.active}:{base64.b64encode(blob).decode()}"

    def open(self, token: str, aad: str) -> str:
        kid, b64 = token.split(":", 1)
        return ToyAEAD(self.keys[kid]).decrypt(base64.b64decode(b64), aad.encode()).decode()

    def rewrap(self, token: str, aad: str) -> str:
        return self.seal(self.open(token, aad), aad)


# ------------------------------------------------------------------ 5. data at rest: a card table
class CardStore:
    """`encrypted=False` is the vulnerable design (plaintext PAN in the table and in backups).
    `encrypted=True` stores ciphertext bound to the row id (associated data), so a ciphertext copied
    to another customer's row fails to decrypt."""

    def __init__(self, encrypted: bool, keyring: KeyRing | None = None):
        self.encrypted = encrypted
        self.kr = keyring
        self.db = sqlite3.connect(":memory:")
        self.db.execute("CREATE TABLE cards (customer_id TEXT PRIMARY KEY, pan TEXT, last4 TEXT)")

    def add(self, customer_id: str, pan: str) -> None:
        stored = self.kr.seal(pan, aad=f"cards:{customer_id}") if self.encrypted else pan
        self.db.execute("INSERT INTO cards VALUES (?, ?, ?)", (customer_id, stored, pan[-4:]))

    def get_pan(self, customer_id: str) -> str:
        (stored,) = self.db.execute("SELECT pan FROM cards WHERE customer_id = ?", (customer_id,)).fetchone()
        return self.kr.open(stored, aad=f"cards:{customer_id}") if self.encrypted else stored

    def dump(self) -> str:
        """What a stolen backup / DBA SELECT * sees."""
        return "\n".join(" | ".join(r) for r in self.db.execute("SELECT * FROM cards ORDER BY customer_id"))

    def rotate_and_rewrap(self) -> int:
        self.kr.rotate()
        n = 0
        for cid, stored in self.db.execute("SELECT customer_id, pan FROM cards").fetchall():
            self.db.execute("UPDATE cards SET pan = ? WHERE customer_id = ?",
                            (self.kr.rewrap(stored, f"cards:{cid}"), cid))
            n += 1
        return n


def fake_pan(seed: int) -> str:
    """FAKE 16-digit test-style number built at runtime (not a real card)."""
    return "4000" + "0000" + f"{seed:08d}"
