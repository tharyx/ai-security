import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import graphql_lab as g  # noqa: E402

for secure in (False, True):
    s = g.Server(secure)
    print(f"===== {'HARDENED' if secure else 'VULNERABLE'} GraphQL server, viewer = alice (id 1) =====")
    r = s.execute("{ __schema }", 1)
    print("1 introspection     :", r.get("data", r)["__schema"] if "data" in r else r["errors"])
    r = s.execute('{ user(id: 3) { name email ssn } }', 1)
    print("2 BOLA user(id: 3)  :", r.get("data", r.get("errors")))
    s.http_requests = 0
    r = s.execute(g.alias_bruteforce_query("admin", [f"{i:02d}" for i in range(100)]), None)
    if "data" in r:
        hit = [k for k, v in r["data"].items() if v["ok"]]
        print(f"3 alias brute force : 100 PIN guesses in {s.http_requests} HTTP request -> PIN found: {hit}")
    else:
        print("3 alias brute force :", r["errors"])
    s.resolver_calls = 0
    r = s.execute(g.deep_friends_query(12), 1)
    print("4 depth-12 query    :", f"{s.resolver_calls} resolver calls" if "data" in r else r["errors"])
    r = s.execute("{ me { name friends { name } } }", 1)
    print("5 normal query      :", r["data"])
    print()
