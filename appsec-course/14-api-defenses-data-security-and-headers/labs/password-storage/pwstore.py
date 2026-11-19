"""Password storage: legacy fast hashes vs salted, slow, peppered hashes, with upgrade-on-login.

Standard library only (`hashlib.pbkdf2_hmac`, `hashlib.scrypt`, `hmac`). The OWASP Password
Storage Cheat Sheet prefers Argon2id, then scrypt, then bcrypt, then PBKDF2-HMAC-SHA256 with
about 600,000 iterations where FIPS is required (verify the current numbers at the source).
Argon2id and bcrypt need third-party packages, so this lab uses scrypt and PBKDF2.

All passwords here are lab passwords from a tiny built-in list. The pepper is FAKE and built at
runtime; in production it lives in a secret manager or HSM, never in the database.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
from dataclasses import dataclass, field

PBKDF2_POLICY_ITERATIONS = 600_000  # OWASP guidance for PBKDF2-HMAC-SHA256 (verify)
SCRYPT_POLICY = {"n": 2 ** 17, "r": 8, "p": 1}  # OWASP minimum example (verify); lab uses smaller n

LAB_WORDLIST = ["123456", "password", "qwerty", "monsoon2024", "letmein", "chennai@123", "dragon",
                "sunshine", "welcome1", "iloveyou"]
COMMON_BLOCKLIST = set(LAB_WORDLIST) | {"password123", "admin", "12345678", "qwertyuiop"}


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s + "=" * (-len(s) % 4))


# ------------------------------------------------------------------ hashing schemes
def md5_unsalted(pw: str) -> str:  # VULNERABLE: fast, unsalted
    return "$md5$" + hashlib.md5(pw.encode()).hexdigest()


def sha1_unsalted(pw: str) -> str:  # VULNERABLE: fast, unsalted
    return "$sha1$" + hashlib.sha1(pw.encode()).hexdigest()


def _peppered(pw: str, pepper: bytes | None) -> bytes:
    # Pre-hash with HMAC(pepper) so a stolen DB alone is not enough to start guessing.
    return hmac.new(pepper, pw.encode(), hashlib.sha256).digest() if pepper else pw.encode()


def pbkdf2_hash(pw: str, iterations: int = PBKDF2_POLICY_ITERATIONS, pepper: bytes | None = None,
                salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", _peppered(pw, pepper), salt, iterations)
    tag = "pbkdf2-sha256p" if pepper else "pbkdf2-sha256"
    return f"${tag}$i={iterations}${_b64(salt)}${_b64(dk)}"


def scrypt_hash(pw: str, n: int = 2 ** 14, r: int = 8, p: int = 1, pepper: bytes | None = None) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(_peppered(pw, pepper), salt=salt, n=n, r=r, p=p, maxmem=256 * 1024 * 1024, dklen=32)
    tag = "scryptp" if pepper else "scrypt"
    return f"${tag}$n={n},r={r},p={p}${_b64(salt)}${_b64(dk)}"


def verify(pw: str, stored: str, pepper: bytes | None = None) -> bool:
    parts = stored.split("$")
    scheme = parts[1]
    if scheme == "md5":
        return hmac.compare_digest(stored, md5_unsalted(pw))
    if scheme == "sha1":
        return hmac.compare_digest(stored, sha1_unsalted(pw))
    if scheme.startswith("pbkdf2-sha256"):
        iters = int(parts[2].split("=")[1])
        salt, want = _unb64(parts[3]), _unb64(parts[4])
        got = hashlib.pbkdf2_hmac("sha256", _peppered(pw, pepper if scheme.endswith("p") else None), salt, iters)
        return hmac.compare_digest(got, want)
    if scheme.startswith("scrypt"):
        params = dict(kv.split("=") for kv in parts[2].split(","))
        salt, want = _unb64(parts[3]), _unb64(parts[4])
        got = hashlib.scrypt(_peppered(pw, pepper if scheme.endswith("p") else None), salt=salt,
                             n=int(params["n"]), r=int(params["r"]), p=int(params["p"]),
                             maxmem=256 * 1024 * 1024, dklen=32)
        return hmac.compare_digest(got, want)
    raise ValueError(f"unknown scheme {scheme}")


def needs_rehash(stored: str, min_iterations: int) -> bool:
    scheme = stored.split("$")[1]
    if scheme in ("md5", "sha1"):
        return True
    if scheme.startswith("pbkdf2"):
        return int(stored.split("$")[2].split("=")[1]) < min_iterations
    return False


# ------------------------------------------------------------------ user store with upgrade-on-login
@dataclass
class UserStore:
    pepper: bytes | None = None
    iterations: int = PBKDF2_POLICY_ITERATIONS
    users: dict[str, str] = field(default_factory=dict)
    upgraded: list[str] = field(default_factory=list)

    def set_password(self, user: str, pw: str) -> None:
        self.users[user] = pbkdf2_hash(pw, self.iterations, self.pepper)

    def login(self, user: str, pw: str) -> bool:
        stored = self.users.get(user)
        if stored is None:
            pbkdf2_hash(pw, self.iterations, self.pepper)  # equal work for unknown users (no timing oracle)
            return False
        ok = verify(pw, stored, self.pepper)
        if ok and needs_rehash(stored, self.iterations):
            # The only moment we have the plaintext: upgrade the legacy hash transparently.
            self.users[user] = pbkdf2_hash(pw, self.iterations, self.pepper)
            self.upgraded.append(user)
        return ok


# ------------------------------------------------------------------ attacker view
def dictionary_attack(stored_by_user: dict[str, str], wordlist: list[str], pepper: bytes | None = None,
                      ) -> tuple[dict[str, str], int, float]:
    """Try each word against each stored hash. Returns (cracked, guesses, seconds)."""
    cracked, guesses, t0 = {}, 0, time.perf_counter()
    for user, stored in stored_by_user.items():
        for w in wordlist:
            guesses += 1
            try:
                if verify(w, stored, pepper):
                    cracked[user] = w
                    break
            except ValueError:
                break
    return cracked, guesses, time.perf_counter() - t0


def identical_hash_groups(stored_by_user: dict[str, str]) -> list[list[str]]:
    """Unsalted hashes reveal which users share a password, without cracking anything."""
    groups: dict[str, list[str]] = {}
    for u, h in stored_by_user.items():
        groups.setdefault(h, []).append(u)
    return [sorted(g) for g in groups.values() if len(g) > 1]


# ------------------------------------------------------------------ password policy (NIST SP 800-63B-4 style)
def check_password_policy(pw: str, mfa: bool = False) -> list[str]:
    """Length over complexity; blocklist; no composition rules; allow long passphrases.
    15 characters minimum when the password is the only factor, 8 with MFA (verify the final text)."""
    problems = []
    minimum = 8 if mfa else 15
    if len(pw) < minimum:
        problems.append(f"too short: {len(pw)} < {minimum}")
    if len(pw) > 128:
        problems.append("longer than this service's 128-character cap (must allow at least 64)")
    if pw.lower() in COMMON_BLOCKLIST:
        problems.append("on the common/breached-password blocklist")
    return problems


def make_fake_pepper() -> bytes:
    """FAKE pepper built at runtime. Real peppers live in a secret manager or HSM."""
    return hashlib.sha256(b"FAKE-" + b"lab-pepper-" + os.urandom(8)).digest()
