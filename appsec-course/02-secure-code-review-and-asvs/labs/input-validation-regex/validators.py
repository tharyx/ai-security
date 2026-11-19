"""Input validation with regex: weak patterns a reviewer should catch, and the fixes.

Rules of thumb taught here:
1. Allowlist, not blocklist: describe what IS allowed.
2. Match the WHOLE string: re.fullmatch (or \\A...\\Z). re.match only anchors the start, and
   '$' also matches before a trailing newline.
3. Bound lengths, normalize Unicode first (NFKC), convert to the real type (int, date) and check
   the range or calendar; a regex cannot tell that 2026-02-30 is not a date.
4. Avoid nested quantifiers such as (a+)+ that can backtrack exponentially (ReDoS).
5. Validation reduces attack surface; it does NOT replace parameterized queries or output encoding.
"""

from __future__ import annotations

import re
import time
import unicodedata
from datetime import date

# ---------------------------------------------------------------- weak versions (review findings)


def weak_username(s: str) -> bool:
    return bool(re.match(r"[a-z0-9_]{3,20}", s))  # only the START must match


def weak_username_dollar(s: str) -> bool:
    return bool(re.match(r"^[a-z0-9_]{3,20}$", s))  # '$' accepts a trailing '\n'


def weak_comment_blocklist(s: str) -> bool:
    return "<script" not in s.lower()  # blocklists miss other vectors (<img onerror=...>)


def weak_pin(s: str) -> bool:
    return bool(re.search(r"\d{6}", s))  # search finds digits anywhere


# ---------------------------------------------------------------- strong versions

USERNAME = re.compile(r"[a-z0-9_]{3,20}")
PIN_IN = re.compile(r"[1-9][0-9]{5}")             # Indian postal PIN code
PHONE_E164 = re.compile(r"\+[1-9][0-9]{6,14}")
SKU = re.compile(r"[A-Z]{3}-[0-9]{4}")
ISO_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}")
RESERVED = {"admin", "root", "support", "security"}


def normalize(s: str) -> str:
    return unicodedata.normalize("NFKC", s)


def strong_username(s: str) -> bool:
    s = normalize(s)
    return bool(USERNAME.fullmatch(s)) and s not in RESERVED


def strong_pin(s: str) -> bool:
    return bool(PIN_IN.fullmatch(s))


def strong_phone(s: str) -> bool:
    return bool(PHONE_E164.fullmatch(s))


def strong_email(s: str) -> bool:
    # Pragmatic shape check only. The real proof is a confirmation email.
    return len(s) <= 254 and bool(EMAIL.fullmatch(s))


def strong_date(s: str) -> bool:
    if not ISO_DATE.fullmatch(s):
        return False
    try:
        date.fromisoformat(s)
    except ValueError:
        return False
    return True


def strong_quantity(s: str, lo: int = 1, hi: int = 10) -> bool:
    return s.isascii() and s.isdigit() and lo <= int(s) <= hi


# ---------------------------------------------------------------- schema validation

SCHEMA = {
    "username": strong_username,
    "email": strong_email,
    "pin": strong_pin,
    "quantity": strong_quantity,
}


def validate_form(data: dict, schema: dict = SCHEMA) -> tuple:
    """Return (clean, errors). Unknown fields are errors (blocks mass assignment like role=admin)."""
    errors = [f"unknown field: {k}" for k in data if k not in schema]
    errors += [f"missing field: {k}" for k in schema if k not in data]
    clean = {}
    for k, check in schema.items():
        if k in data:
            v = data[k]
            if not isinstance(v, str) or len(v) > 256 or not check(v):
                errors.append(f"invalid {k}")
            else:
                clean[k] = normalize(v)
    return (clean if not errors else {}), errors


# ---------------------------------------------------------------- ReDoS awareness

NESTED_QUANT = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*{]")


def has_nested_quantifier(pattern: str) -> bool:
    """Heuristic: a group that contains + or * and is itself repeated, e.g. (a+)+ or (\\w+\\s?)*.

    Real tools (e.g. a ReDoS checker or a linear-time engine such as RE2) do better; this flags the
    classic shape for a reviewer.
    """
    return bool(NESTED_QUANT.search(pattern))


def time_match(pattern: str, text: str) -> float:
    start = time.perf_counter()
    re.fullmatch(pattern, text)
    return time.perf_counter() - start
