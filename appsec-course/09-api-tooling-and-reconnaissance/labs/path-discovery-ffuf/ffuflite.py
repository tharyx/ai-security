"""A tiny ffuf-style path/directory fuzzer against an in-process router.

Covers "Path And Directory Discovery Using FFUF". No network: the "target" is
a Python router function that maps known paths to status codes. The fuzzer
walks a wordlist, requests ``/FUZZ`` for each word, and reports the responses,
filtering by status the way ``ffuf -mc`` / ``-fc`` do. It demonstrates how an
API's own 404-vs-401-vs-200 pattern leaks which endpoints exist, and how a
uniform 404 for unknown paths slows discovery.

Only test systems you own or have written permission to test.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Hit:
    word: str
    path: str
    status: int
    length: int


def make_router(known: dict, hide_unknown: bool = False):
    """Return a router ``handle(path) -> (status, body)``.

    ``known`` maps a path to a (status, body). Unknown paths return 404, unless
    ``hide_unknown`` also returns 404 for *protected* paths so existence cannot
    be told apart (not usually desirable, but shows the defensive extreme).
    """
    def handle(path: str):
        if path in known:
            status, body = known[path]
            if hide_unknown and status == 401:
                # pretend protected endpoints do not exist
                return 404, "not found"
            return status, body
        return 404, "not found"

    return handle


def fuzz(base_path: str, wordlist: list, handle,
         match_codes: set | None = None, filter_codes: set | None = None) -> list:
    """Request base_path with FUZZ replaced by each word; return filtered hits.

    ``base_path`` must contain the token ``FUZZ``.
    ``match_codes`` keeps only those status codes (like ffuf -mc).
    ``filter_codes`` drops those status codes (like ffuf -fc). Default: drop 404.
    """
    if "FUZZ" not in base_path:
        raise ValueError("base_path must contain the FUZZ token")
    if match_codes is None and filter_codes is None:
        filter_codes = {404}
    hits = []
    for word in wordlist:
        path = base_path.replace("FUZZ", word)
        status, body = handle(path)
        if match_codes is not None and status not in match_codes:
            continue
        if filter_codes is not None and status in filter_codes:
            continue
        hits.append(Hit(word=word, path=path, status=status, length=len(body)))
    return hits


DEFAULT_WORDLIST = [
    "login", "products", "orders", "admin", "debug", "users",
    "health", "metrics", "backup", "v1", "v2", ".git", "swagger",
]
