"""Validating input with regular expressions, done right (and the classic mistakes).

- Use re.fullmatch (or \\A ... \\Z). re.match only anchors the start, and "$" also
  matches before a trailing newline.
- Allowlist (what IS allowed) beats denylist (what is NOT allowed).
- Cap length BEFORE running a regex, and avoid nested quantifiers (ReDoS).
- Client-side validation is UX only: the server must validate again.
- Sanitization (changing input) is different from validation (accept/reject).
"""

from __future__ import annotations

import re
import time
import unicodedata

USERNAME = re.compile(r"[a-z0-9_]{3,20}")
POSTCODE_IN = re.compile(r"[1-9][0-9]{5}")  # Indian PIN code
ISO_DATE = re.compile(r"\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])")
EMAIL_SIMPLE = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}")


def validate(pattern: re.Pattern, value, max_len: int = 254) -> bool:
    if not isinstance(value, str) or len(value) > max_len:
        return False
    return pattern.fullmatch(value) is not None


# ---- the classic mistakes
def weak_match(value: str) -> bool:
    return re.match(r"[a-z0-9_]{3,20}", value) is not None  # prefix only


def weak_dollar(value: str) -> bool:
    return re.search(r"^[a-z0-9_]{3,20}$", value) is not None  # allows trailing "\n"


# ---- allowlist vs denylist for a "comment" field
def denylist_filter(text: str) -> bool:
    """Returns True if 'safe'. Blocks only lower-case <script>: trivially bypassed."""
    return "<script>" not in text


SAFE_COMMENT = re.compile(r"[\w\s.,!?'()-]{1,500}")


def allowlist_comment(text: str) -> bool:
    return validate(SAFE_COMMENT, text, 500)


# ---- ReDoS
NESTED_QUANTIFIER = re.compile(r"\((?:[^()\\]|\\.)*[+*]\)[+*{]")


def looks_redos_prone(pattern: str) -> bool:
    """Heuristic: a quantified group that itself contains a quantifier, e.g. (a+)+ or (\\w*)*."""
    return NESTED_QUANTIFIER.search(pattern) is not None


def time_regex(pattern: str, n: int) -> float:
    s = "a" * n + "!"
    t0 = time.perf_counter()
    re.match(pattern, s)
    return time.perf_counter() - t0


# ---- client-side vs server-side
def client_side_form_check(value: str) -> bool:
    """What the browser JavaScript checks. An attacker skips it with curl or a proxy."""
    return validate(USERNAME, value)


def server_create_user(value, validate_on_server: bool) -> tuple[int, str]:
    if validate_on_server and not validate(USERNAME, value):
        return 422, "invalid username"
    return 201, f"created {value!r}"


# ---- sanitization
def sanitize_display_name(text: str) -> str:
    """Normalize, drop control and bidi-override characters, collapse spaces, trim length."""
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text if unicodedata.category(ch)[0] != "C")
    return re.sub(r"\s+", " ", text).strip()[:40]
