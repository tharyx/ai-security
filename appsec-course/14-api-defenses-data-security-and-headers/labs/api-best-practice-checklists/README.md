# Lab: GraphQL, SOAP and REST best practices as code

**Course items:** "GraphQL API Security Best Practices", "SOAP API Security Best Practices", "REST API Security Best Practices". Lesson: [01 API style best practices](../../01-api-style-best-practices.md).

**Time:** 45 minutes. **Tests:** 8, all offline. **Safety:** JSON config fixtures and string queries only; nothing is attacked. Only test systems you own or have written permission to test.

## Goal

Turn three best-practice lists into **rules that run in CI**. A checklist in a wiki is read once; a checklist as code fails the build when someone turns introspection back on.

## Concept

[bp_checklists.py](bp_checklists.py) has 10 GraphQL rules (`GQL-*`), 10 SOAP rules (`SOAP-*`) and 12 REST rules (`REST-*`). Each rule reads a deployment config (the settings you would find in Apollo Server, graphql-java, a SOAP stack such as CXF or WCF, or a REST framework plus gateway) and returns a finding with a severity. `gate()` returns exit code 1 when anything HIGH or worse is found.

Two runtime helpers prove that the GraphQL limits are real controls: `graphql_query_depth()` and `count_aliases()` measure a query, and `enforce_graphql_limits()` rejects a deep query or an alias-based brute force.

| Fixture | What it models |
|---|---|
| `graphql_weak.json` / `graphql_hardened.json` | Introspection, suggestions, depth/cost/alias/batch limits, per-resolver authorization, persisted queries |
| `soap_weak.json` / `soap_hardened.json` | DTDs, external entities, XSD validation, WSDL exposure, WS-Security signature + timestamp, XML Signature Wrapping, SOAPAction |
| `rest_weak.json` / `rest_hardened.json` | Auth on every route, object-level authorization, schema validation, response allowlist, rate limit, CORS, methods, versions (inventory) |

## Run

```text
.venv/Scripts/python appsec-course/14-api-defenses-data-security-and-headers/labs/api-best-practice-checklists/demo.py
.venv/Scripts/python -m pytest appsec-course/14-api-defenses-data-security-and-headers/labs/api-best-practice-checklists -v
```

## Expected output (real run)

```text
== shop-graphql (as found): 10 finding(s), gate exit 1
  [CRITICAL] GQL-07 Authorization in every resolver: authorization only at the HTTP layer: nested resolvers expose other users' objects (BOLA)
  [HIGH] GQL-01 Introspection disabled in production: introspection is on in production: the whole schema (including admin mutations) is public
  [HIGH] GQL-03 Query depth limit: deep or circular queries can exhaust the server (not set: unlimited)
  [HIGH] GQL-04 Query cost/complexity limit: no cost limit: one query can fetch millions of nodes (not set: unlimited)
  [HIGH] GQL-05 Alias limit: aliases allow hundreds of login/OTP guesses in one request (not set: unlimited)
  [MEDIUM] GQL-02 Field suggestions disabled: 'Did you mean ...?' suggestions leak schema even with introspection off
  [MEDIUM] GQL-06 Batching limit: array batching multiplies every other limit (is 100, want <= 5)
  [MEDIUM] GQL-08 Persisted queries / operation allowlist: arbitrary queries accepted from any client
  [MEDIUM] GQL-09 Errors masked: stack traces and resolver errors reach the client
  [MEDIUM] GQL-10 Execution timeout: no execution timeout (not set: unlimited)
== shop-graphql (hardened): 0 finding(s), gate exit 0

== payments-soap (as found): 9 finding(s), gate exit 1
  [CRITICAL] SOAP-01 DTD processing disabled: DTDs enabled: XXE file read/SSRF and billion-laughs entity expansion
  [CRITICAL] SOAP-02 External entities disabled: external entities resolved: XXE
  [CRITICAL] SOAP-07 Process only the signed element (anti XML Signature Wrapping): the app may process an unsigned copy of the body (XML Signature Wrapping)
  [HIGH] SOAP-03 Schema (XSD) validation on: messages not validated against the XSD
  [HIGH] SOAP-06 WS-Security signature and timestamp required: unsigned or replayable messages accepted
  [MEDIUM] SOAP-04 Message size limit: no message size limit (not set: unlimited)
  [MEDIUM] SOAP-05 WSDL not public in production: WSDL published in production: full operation map for attackers
  [MEDIUM] SOAP-08 SOAPAction must match the body operation: SOAPAction header trusted for routing: operation spoofing
  [MEDIUM] SOAP-10 Faults do not leak internals: SOAP faults include stack traces
== payments-soap (hardened): 0 finding(s), gate exit 0

== orders-rest (as found): 12 finding(s), gate exit 1
  [CRITICAL] REST-02 Every non-public route authenticated: routes without authentication: /v2/admin/export
  [CRITICAL] REST-03 Object-level authorization on routes with ids: id routes without an owner check (BOLA): /v2/orders/{id}
  [HIGH] REST-01 HTTPS only (and HSTS): plain HTTP allowed
  [HIGH] REST-04 Request schema validation: request bodies not validated against a schema
  [HIGH] REST-05 Response field allowlist (no excessive data exposure): whole objects serialized to the client (BOPLA / excessive data exposure)
  [HIGH] REST-06 Rate limiting configured: no rate limit
  [HIGH] REST-08 CORS allowlist, never '*' with credentials: CORS allows any origin
  [MEDIUM] REST-07 Page size capped: unbounded page size (not set: unlimited)
  [MEDIUM] REST-09 Only needed HTTP methods: risky methods enabled: TRACE
  [MEDIUM] REST-10 Generic error bodies: verbose errors (SQL, stack traces) in responses
  [MEDIUM] REST-11 Strict Content-Type checking: any Content-Type accepted
  [MEDIUM] REST-12 API inventory: deprecated versions retired: old versions still live: v1
== orders-rest (hardened): 0 finding(s), gate exit 0

Deep query      weak: accepted (depth 8, aliases 0) | hardened: rejected: depth 8 > 7
50-alias brute  weak: accepted (depth 1, aliases 50) | hardened: rejected: 50 aliases > 10
```

## Steps

1. Run the demo. For every finding on the weak configs, name the OWASP API Top 10 2023 item it maps to. For example, GQL-07 and REST-03 are API1 BOLA; REST-05 is API3 BOPLA; GQL-03/04/05 are API4 Unrestricted Resource Consumption; REST-12 is API9 Improper Inventory Management.
2. In `graphql_hardened.json` set `"introspection": true`. Which rule fires? Now set `"environment": "staging"`. Why is it allowed there? Is that a good idea for a staging API that the internet can reach?
3. Write a query with 12 aliases and run `enforce_graphql_limits()` against the hardened config.
4. Add a REST rule `REST-13` that fails when a route with `"method": "DELETE"` has no `"scope"`. Add a test.
5. Map each rule id to an ASVS 5.0 requirement in a comment (verify the ids at the source, because 5.0 renumbered them).

## What you learned

- Each API style has its own failure modes: GraphQL (one endpoint, client-shaped queries), SOAP (XML parser and signature handling), REST (many routes, object ids in paths).
- Limits only matter if they are **enforced at runtime**. The config check proves they are set; the runtime helper proves they work.
- Best practices last when they are a failing test, not a page.

## Run the real tool (hedged)

- **GraphQL:** `graphql-cop -t https://YOUR-LAB-API/graphql` checks introspection, suggestions, batching and aliases. **InQL** (a Burp extension) analyses schemas. **Clairvoyance** shows how field suggestions rebuild a schema when introspection is off. Verify flags with `--help`.
- **SOAP:** ZAP's SOAP add-on imports a WSDL; SoapUI/ReadyAPI run functional tests. Test XXE only on your lab service.
- **REST:** run the ZAP API scan with your OpenAPI file (see the [devsecops ch06 OpenAPI lab](../../../../devsecops-course/06-dynamic-analysis/labs/openapi-zap-api-scan/README.md)). **Spectral** with an OWASP ruleset lints OpenAPI files for many of these rules.
