import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gql_extra as g  # noqa: E402

print("== Introspection is off, but suggestions are on ==")
s = g.Server(suggestions=True)
print("query { adminExport } ->", s.execute(["adminExport"])["errors"][0])
print("schema recovered from an 8-word list:", sorted(g.recover_schema(s, g.WORDLIST)))

print("\n== Suggestions off ==")
s = g.Server(suggestions=False)
print("query { adminExport } ->", s.execute(["adminExport"])["errors"][0])
print("schema recovered:", sorted(g.recover_schema(s, g.WORDLIST)))

print("\n== Array batching: 500 operations in one HTTP POST ==")
s = g.Server(suggestions=False)
s.execute_batch([["resetPassword"]] * 500)
print("operations executed without a batch limit:", s.operations_executed)
print("with max_batch=10:", g.Server(False, max_batch=10).execute_batch([["me"]] * 500))

print("\n== Persisted queries (allowlist) ==")
s = g.Server(suggestions=False, persisted_only=True)
h = s.register(["me", "orders"])
print("registered hash", h[:16], "->", s.execute(query_hash=h))
print("ad-hoc attacker query ->", s.execute(["adminExportAllUsers"]))
