"""GraphQL, part 2 (the part-1 lab is in chapter 12): field suggestions that leak the
schema when introspection is off, Clairvoyance-style schema recovery, array batching,
and persisted (allowlisted) queries as a defence.

To stay small, a "query" here is a list of top-level field names (chapter 12 has a parser).
"""

from __future__ import annotations

import difflib
import hashlib

SCHEMA_FIELDS = ["me", "products", "orders", "adminExportAllUsers", "internalPricingRules", "resetPassword"]


class Server:
    def __init__(self, suggestions: bool, persisted_only: bool = False, max_batch: int | None = None):
        self.suggestions, self.persisted_only, self.max_batch = suggestions, persisted_only, max_batch
        self.allowlist: dict[str, list[str]] = {}
        self.operations_executed = 0

    # ---- persisted queries: the client sends only a hash the server already knows
    def register(self, fields: list[str]) -> str:
        h = hashlib.sha256(" ".join(fields).encode()).hexdigest()
        self.allowlist[h] = fields
        return h

    def execute(self, fields: list[str] | None = None, query_hash: str | None = None) -> dict:
        if self.persisted_only:
            if query_hash not in self.allowlist:
                return {"errors": ["PersistedQueryNotFound: only registered queries are accepted"]}
            fields = self.allowlist[query_hash]
        errors, data = [], {}
        for f in fields or []:
            if f in SCHEMA_FIELDS:
                data[f] = f"<{f} data>"
                continue
            msg = f"Cannot query field '{f}' on type 'Query'."
            if self.suggestions:
                close = difflib.get_close_matches(f, SCHEMA_FIELDS, n=2, cutoff=0.6)
                if close:
                    msg += " Did you mean " + " or ".join(f"'{c}'" for c in close) + "?"
            errors.append(msg)
        self.operations_executed += 1
        return {"data": data, "errors": errors} if errors else {"data": data}

    def execute_batch(self, batch: list[list[str]]) -> list[dict] | dict:
        if self.max_batch is not None and len(batch) > self.max_batch:
            return {"errors": [f"batch of {len(batch)} exceeds limit {self.max_batch}"]}
        return [self.execute(b) for b in batch]


def recover_schema(server: Server, wordlist: list[str]) -> set[str]:
    """Clairvoyance idea: send near-miss field names, harvest 'Did you mean' hints."""
    found = set()
    for word in wordlist:
        r = server.execute([word])
        if word in r.get("data", {}):
            found.add(word)
        for e in r.get("errors", []):
            if "Did you mean" in e:
                found |= {part.strip("'?. ") for part in e.split("Did you mean", 1)[1].split(" or ")}
    return found


WORDLIST = ["me", "product", "order", "adminExport", "internalPricing", "resetPasswd", "user", "admin"]
