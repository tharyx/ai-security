"""A tiny GraphQL-like server to practise GraphQL attacks and defences offline.

Supported query subset (enough for the attacks):
    query Name { alias: field(arg: "x", n: 3) { sub { ... } } other }
Strings, integers and booleans as argument values. No variables, fragments or mutations.

Attacks:   introspection on in production, BOLA in a resolver, alias batching to
           brute force a login in ONE HTTP request, deep nested query DoS.
Defences:  introspection off, per-resolver authorization, alias/operation limits,
           depth limit and a cost (complexity) budget.
"""

from __future__ import annotations

import re
import secrets

# ------------------------------------------------------------------ parser

TOKEN = re.compile(r'\s*(?:(\.\.\.)|([{}():,])|("(?:[^"\\]|\\.)*")|(-?\d+)|([A-Za-z_][A-Za-z0-9_]*))')


def tokenize(q: str) -> list[str]:
    out, pos = [], 0
    q = q.strip()
    while pos < len(q):
        m = TOKEN.match(q, pos)
        if not m or m.end() == pos:
            raise SyntaxError(f"unexpected input at {pos}")
        out.append(next(g for g in m.groups() if g is not None))
        pos = m.end()
    return out


def parse(q: str) -> list[dict]:
    toks = tokenize(q)
    i = 0

    def sel_set():
        nonlocal i
        assert toks[i] == "{", "expected {"
        i += 1
        fields = []
        while toks[i] != "}":
            name = toks[i]
            i += 1
            alias = None
            if toks[i] == ":":
                alias, name = name, toks[i + 1]
                i += 2
            args = {}
            if toks[i] == "(":
                i += 1
                while toks[i] != ")":
                    key, val = toks[i], toks[i + 2]
                    i += 3
                    args[key] = val[1:-1] if val.startswith('"') else (val == "true" if val in ("true", "false") else int(val))
                    if toks[i] == ",":
                        i += 1
                i += 1
            sub = sel_set() if toks[i] == "{" else None
            fields.append({"name": name, "alias": alias or name, "args": args, "sub": sub})
            if i < len(toks) and toks[i] == ",":
                i += 1
        i += 1
        return fields

    if toks[0] == "query":
        i = 2 if toks[1] != "{" else 1
    return sel_set()


def depth(fields, d=1) -> int:
    return max((depth(f["sub"], d + 1) if f["sub"] else d) for f in fields) if fields else d


def count_fields(fields) -> int:
    return sum(1 + (count_fields(f["sub"]) if f["sub"] else 0) for f in fields)


# ------------------------------------------------------------------ data + schema

PASSWORD = "FAKE-" + secrets.token_hex(2)
USERS = {
    1: {"id": 1, "name": "alice", "email": "alice@lab.example", "ssn": "FAKE-SSN-111", "friends": [2, 3]},
    2: {"id": 2, "name": "bob", "email": "bob@lab.example", "ssn": "FAKE-SSN-222", "friends": [1, 3]},
    3: {"id": 3, "name": "admin", "email": "root@lab.example", "ssn": "FAKE-SSN-333", "friends": [1, 2]},
}
PINS = {"admin": f"{secrets.randbelow(100):02d}"}  # 2-digit PIN: tiny keyspace for the lab
SCHEMA = {
    "Query": ["me", "user(id: Int)", "login(username: String, pin: String)", "adminResetAllPasswords"],
    "User": ["id", "name", "email", "ssn", "friends"],
}


class Server:
    def __init__(self, secure: bool, max_depth=5, max_cost=50, max_aliases=5):
        self.secure = secure
        self.max_depth, self.max_cost, self.max_aliases = max_depth, max_cost, max_aliases
        self.http_requests = 0
        self.resolver_calls = 0

    def execute(self, query: str, viewer_id: int | None):
        """One call = one HTTP request (a naive rate limiter counts only these)."""
        self.http_requests += 1
        try:
            ast = parse(query)
        except Exception as e:
            return {"errors": [f"syntax error: {e}"]}
        if self.secure:
            if any(f["name"].startswith("__") for f in ast):
                return {"errors": ["introspection is disabled"]}
            if depth(ast) > self.max_depth:
                return {"errors": [f"query depth {depth(ast)} exceeds {self.max_depth}"]}
            if count_fields(ast) > self.max_cost:
                return {"errors": [f"query cost {count_fields(ast)} exceeds {self.max_cost}"]}
            if sum(1 for f in ast if f["name"] == "login") > 1 or len(ast) > self.max_aliases:
                return {"errors": ["too many operations/aliases in one request"]}
        data = {}
        for f in ast:
            data[f["alias"]] = self._resolve_root(f, viewer_id)
        return {"data": data}

    def _resolve_root(self, f, viewer_id):
        self.resolver_calls += 1
        name, args = f["name"], f["args"]
        if name == "__schema":
            return SCHEMA
        if name == "me":
            return self._user(USERS.get(viewer_id), f["sub"], viewer_id)
        if name == "user":
            target = USERS.get(args.get("id"))
            if self.secure and target and target["id"] != viewer_id:
                return {"error": "not authorized"}  # per-resolver object check
            return self._user(target, f["sub"], viewer_id)
        if name == "login":
            return {"ok": PINS.get(args.get("username")) == args.get("pin")}
        return None

    def _user(self, u, sub, viewer_id):
        if u is None:
            return None
        out = {}
        for s in sub or []:
            self.resolver_calls += 1
            if s["name"] == "friends":
                out[s["alias"]] = [self._user(USERS[i], s["sub"], viewer_id) for i in u["friends"]]
            elif s["name"] == "ssn" and self.secure and u["id"] != viewer_id:
                out[s["alias"]] = None  # field-level authorization
            else:
                out[s["alias"]] = u.get(s["name"])
        return out


def alias_bruteforce_query(username: str, pins) -> str:
    return "{ " + " ".join(f'p{p}: login(username: "{username}", pin: "{p}")' for p in pins) + " }"


def deep_friends_query(levels: int) -> str:
    q = "name"
    for _ in range(levels):
        q = f"name friends {{ {q} }}"
    return "{ me { " + q + " } }"
