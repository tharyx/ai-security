# Lab: Attacking GraphQL APIs

**Course exercise:** "Attacking GraphQL APIs" ([CASP 5], and again in [CASP 6], whose extra lab is [graphql-suggestions-and-persisted-queries](../../../13-owasp-api-top-10-and-other-threats/labs/graphql-suggestions-and-persisted-queries/README.md)). Lesson: [05 section 2](../../05-post-exploitation-and-graphql.md#2-attacking-graphql-apis).

**Time:** 60 minutes. **Tests:** 8, all offline. **Safety:** a tiny GraphQL-like parser and executor in Python; no server. PINs and "SSNs" are FAKE. Only test systems you own or have written permission to test.

## Goal

Attack a GraphQL endpoint four ways (introspection, BOLA in a resolver, alias batching brute force, deep-query DoS) and see each hardening control stop its attack.

## Concept

GraphQL has **one endpoint** and lets the **client shape the query**. That moves security decisions:

| Attack | Why it works in GraphQL | Defence |
|---|---|---|
| Introspection | `__schema` returns every type and field, including hidden admin ones | Disable in production; publish only what clients need |
| BOLA in resolvers | Each resolver fetches by ID; authorization is per resolver, not per URL | Authorization in every resolver (or a shared data layer) |
| Alias batching | 100 `login` calls as aliases in **one** HTTP request bypass per-request rate limits | Limit aliases/operations; rate-limit per operation |
| Deep/circular queries | `friends { friends { friends ... } }` grows exponentially | Depth limit, cost/complexity budget, timeouts, pagination |

## Steps

1. Run the demo. Note the resolver call count for a depth-12 query.
2. Raise `max_depth` to 15. Which control now stops the query? (The cost budget.)
3. Add a `posts(first: Int)` field and charge `first` into the cost (that is how cost analysis handles lists).
4. Write a test that a user can read their **own** `ssn` but not a friend's on the hardened server (already there: find it).

## Run

```text
.venv/Scripts/python appsec-course/12-input-validation-and-injection/labs/graphql-attacks/demo.py
.venv/Scripts/python -m pytest appsec-course/12-input-validation-and-injection/labs/graphql-attacks -q -p no:cacheprovider
```

## Expected output (real run)

The admin PIN is random per run.

```text
===== VULNERABLE GraphQL server, viewer = alice (id 1) =====
1 introspection     : {'Query': ['me', 'user(id: Int)', 'login(username: String, pin: String)', 'adminResetAllPasswords'], 'User': ['id', 'name', 'email', 'ssn', 'friends']}
2 BOLA user(id: 3)  : {'user': {'name': 'admin', 'email': 'root@lab.example', 'ssn': 'FAKE-SSN-333'}}
3 alias brute force : 100 PIN guesses in 1 HTTP request -> PIN found: ['p83']
4 depth-12 query    : 12287 resolver calls
5 normal query      : {'me': {'name': 'alice', 'friends': [{'name': 'bob'}, {'name': 'admin'}]}}

===== HARDENED GraphQL server, viewer = alice (id 1) =====
1 introspection     : ['introspection is disabled']
2 BOLA user(id: 3)  : {'user': {'error': 'not authorized'}}
3 alias brute force : ['query cost 100 exceeds 50']
4 depth-12 query    : ['query depth 14 exceeds 5']
5 normal query      : {'me': {'name': 'alice', 'friends': [{'name': 'bob'}, {'name': 'admin'}]}}
```

## Run the real tool (hedged)

Against the course lab only: **InQL** (Burp extension) for schema extraction and query generation; **graphql-cop** for a quick misconfiguration audit; **Clairvoyance** to rebuild a schema from field suggestions when introspection is off; **GraphQL Voyager** to visualise a schema (check current maintenance of each).

## What you learned

- GraphQL needs authorization per resolver and cost controls per query, not per URL.
- Rate limits must count operations, not HTTP requests.
