# Lab: GraphQL part 2: field suggestions, batching and persisted queries

**Course topic:** "Attacking GraphQL APIs" ([CASP 6]). Part 1 (introspection, resolver BOLA, alias brute force, depth DoS) is the [chapter 12 graphql-attacks lab](../../../12-input-validation-and-injection/labs/graphql-attacks/README.md). Lesson: [02 section 2](../../02-caching-graphql-soap-and-microservices.md#2-attacking-graphql-apis-part-2).

**Time:** 30 minutes. **Tests:** 6, all offline. **Safety:** an in-process toy server; a "query" is a list of field names. Only test systems you own or have written permission to test.

## Goal

Show that disabling introspection is not enough when error messages suggest field names, abuse array batching, and lock the API down with persisted (allowlisted) queries.

## Concept

- **Field suggestions:** many servers answer an unknown field with "Did you mean `adminExportAllUsers`?". Tools such as **Clairvoyance** send near-miss words and rebuild the schema from those hints. Disable suggestions in production.
- **Array batching:** some servers accept a JSON array of operations in one POST; rate limits that count HTTP requests miss it. Cap or disable batching.
- **Persisted queries:** first-party clients register their queries at build time; at runtime they send only a hash. The server rejects anything else, which removes most GraphQL attack surface for public clients (third-party APIs may still need ad-hoc queries plus cost limits).

## Steps

1. Run the demo; compare the recovered schema with and without suggestions.
2. Add `"adminExportAllUser"` to the wordlist and watch the exact hit.
3. Discuss: what still protects a persisted-query API if an attacker learns a registered hash? (Authorization in resolvers: the hash only fixes the query shape.)

## Run

```text
.venv/Scripts/python appsec-course/13-owasp-api-top-10-and-other-threats/labs/graphql-suggestions-and-persisted-queries/demo.py
.venv/Scripts/python -m pytest appsec-course/13-owasp-api-top-10-and-other-threats/labs/graphql-suggestions-and-persisted-queries -q -p no:cacheprovider
```

## Expected output (real run)

```text
== Introspection is off, but suggestions are on ==
query { adminExport } -> Cannot query field 'adminExport' on type 'Query'. Did you mean 'adminExportAllUsers'?
schema recovered from an 8-word list: ['adminExportAllUsers', 'internalPricingRules', 'me', 'orders', 'products', 'resetPassword']

== Suggestions off ==
query { adminExport } -> Cannot query field 'adminExport' on type 'Query'.
schema recovered: ['me']

== Array batching: 500 operations in one HTTP POST ==
operations executed without a batch limit: 500
with max_batch=10: {'errors': ['batch of 500 exceeds limit 10']}

== Persisted queries (allowlist) ==
registered hash 05d1f8887d94acf9 -> {'data': {'me': '<me data>', 'orders': '<orders data>'}}
ad-hoc attacker query -> {'errors': ['PersistedQueryNotFound: only registered queries are accepted']}
```

## Run the real tool (hedged)

In the course lab: **graphql-cop** (`graphql-cop -t https://lab/graphql`) checks introspection, suggestions, batching, GET-based queries and more; **Clairvoyance** rebuilds schemas from suggestions; **InQL** in Burp generates queries. Apollo, GraphQL Yoga and others have options to disable suggestions and enforce persisted queries (check your server's docs).

## What you learned

- Turning off introspection is necessary but not sufficient.
- Persisted queries plus per-resolver authorization and cost limits make GraphQL as predictable as REST.
