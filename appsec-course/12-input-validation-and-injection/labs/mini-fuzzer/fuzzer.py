"""A mini API fuzzer plus an ffuf/wfuzz-style FUZZ-keyword runner, against an in-process API.

Fuzzing   = send malformed or unexpected input to find BUGS (crashes, errors, leaks).
Brute force = try many VALID-looking candidates to find a SECRET or a hidden resource
              (a path, a coupon, a password). Same engine, different goal and oracle.

The target has three planted bugs that only fuzzing finds:
  1. an unhandled exception (500 + stack trace) on non-numeric quantity;
  2. negative quantity accepted (business logic: a refund instead of a charge);
  3. the "note" field is reflected unencoded (XSS candidate).
Everything is deterministic (seeded random), and no network is used.
"""

from __future__ import annotations

import html
import json
import random

# ----------------------------------------------------------------- target API

HIDDEN_PATHS = {"/api/v1/orders", "/api/v1/health", "/api/v1/internal/debug", "/api/v1/backup"}


def target(method: str, path: str, body: str = "", secure: bool = False):
    if path not in HIDDEN_PATHS:
        return 404, "not found"
    if path != "/api/v1/orders":
        return 200, f"ok {path}"
    try:
        data = json.loads(body or "{}")
    except ValueError:
        return 400, "invalid JSON"
    if not isinstance(data, dict):
        return 400, "body must be an object"
    if secure:
        q = data.get("qty")
        if not isinstance(q, int) or isinstance(q, bool) or not 1 <= q <= 100:
            return 422, "qty must be an integer 1-100"
        note = data.get("note", "")
        if not isinstance(note, str) or len(note) > 200:
            return 422, "note must be a string up to 200 chars"
        return 201, f"order for {q} item(s); note: {html.escape(note)}"
    try:
        qty = int(data.get("qty", 1))  # bug 1: int("abc") raises
    except Exception as e:  # simulate a framework with debug mode on
        return 500, f"Traceback (most recent call last): ValueError: {e}"
    total = qty * 250  # bug 2: negative qty -> negative total
    return 201, f"order for {qty} item(s), total {total}; note: {data.get('note', '')}"  # bug 3


# ----------------------------------------------------------------- mutation fuzzer

INTERESTING = [0, -1, -2147483648, 2147483648, 10**20, "", "abc", "1e9", None, True, [], {}, "A" * 5000,
               "<script>alert(1)</script>", "' OR '1'='1", "../../etc/passwd", "%00", "‮", "{{7*7}}"]


def mutations(seed_value, rng: random.Random, n: int):
    yield from INTERESTING
    for _ in range(n):
        s = str(seed_value)
        choice = rng.randrange(4)
        if choice == 0:
            yield s * rng.randint(2, 50)
        elif choice == 1:
            i = rng.randrange(len(s) or 1)
            yield s[:i] + chr(rng.randrange(32, 0x2FF)) + s[i + 1:]
        elif choice == 2:
            yield -abs(int(seed_value)) if isinstance(seed_value, int) else s[::-1]
        else:
            yield rng.choice(INTERESTING)


def oracle(status: int, body: str, payload) -> list[str]:
    issues = []
    if status >= 500:
        issues.append("server error")
    if "Traceback" in body:
        issues.append("stack trace leaked")
    if isinstance(payload, str) and "<script>" in payload and "<script>" in body:
        issues.append("unencoded reflection")
    if "total -" in body:
        issues.append("negative total accepted")
    return issues


def fuzz(secure: bool, seed: int = 1337, rounds: int = 60) -> dict[str, list]:
    rng = random.Random(seed)
    base = {"qty": 2, "note": "gift"}
    findings: dict[str, list] = {}
    for field in base:
        for value in mutations(base[field], rng, rounds):
            body = json.dumps({**base, field: value})
            status, resp = target("POST", "/api/v1/orders", body, secure)
            for issue in oracle(status, resp, value):
                findings.setdefault(issue, []).append((field, repr(value)[:40]))
    return findings


# ----------------------------------------------------------------- ffuf/wfuzz-style runner


def fuzz_keyword(url_template: str, wordlist, filter_codes=(404,), method="GET"):
    """Replace FUZZ with each word, like `ffuf -u https://host/api/v1/FUZZ -w words.txt -fc 404`."""
    hits = []
    for word in wordlist:
        path = url_template.replace("FUZZ", word)
        status, body = target(method, path)
        if status not in filter_codes:
            hits.append((word, status, len(body)))
    return hits


WORDLIST = ["admin", "users", "orders", "health", "login", "internal/debug", "backup", "v2", "metrics"]
