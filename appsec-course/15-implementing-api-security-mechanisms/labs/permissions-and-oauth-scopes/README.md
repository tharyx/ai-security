# Lab: Designing API permissions and OAuth scopes (scope → endpoint matrix)

**Course items:** "Designing API Permissions", "Designing OAuth Scopes", "Authorization Implementation", "Authentication Implementation". Lesson: [01 API security design](../../01-api-security-design-authn-authz.md). OAuth flows and token types: [chapter 11](../../../11-api-authorization-and-oauth/README.md).

**Time:** 50 minutes. **Tests:** 8, all offline. **Safety:** JSON specs and claim dictionaries; no real tokens. Only test systems you own or have written permission to test.

## Goal

Review an API's permission design **before** it ships, and then enforce it correctly at request time.

## Concept

[scopes.py](scopes.py):

| Part | What it does |
|---|---|
| `lint_spec(spec, clients)` | Finds design flaws: `SCOPE-01` endpoint with no scope; `SCOPE-02` write method guarded by a read scope; `SCOPE-03` admin function with a non-admin scope (BFLA); `SCOPE-04` over-broad scope (`api`, `*`); `SCOPE-05` client granted scopes it never uses; `SCOPE-06` naming not `resource:action`; `SCOPE-07` public write; `SCOPE-08` undefined scope; `SCOPE-09` `{id}` route without owner check (BOLA) |
| `matrix(spec)` | The scope → endpoint table that reviewers sign off |
| `authorize_vulnerable()` | "Any valid token is enough", the most common real bug |
| `authorize_secure()` | Deny unknown routes; require the endpoint's scopes in the token; require the same permissions in the **user's roles** (the scope is a ceiling the user delegated, never a grant); check the object owner |

## Run

```text
.venv/Scripts/python appsec-course/15-implementing-api-security-mechanisms/labs/permissions-and-oauth-scopes/demo.py
.venv/Scripts/python -m pytest appsec-course/15-implementing-api-security-mechanisms/labs/permissions-and-oauth-scopes -v
```

## Expected output (real run)

```text
== orders API (first draft): 7 finding(s)
  [HIGH] SCOPE-04 over-broad scope 'api' defined: one token can do everything
  [LOW] SCOPE-06 scope 'ordersWrite' does not follow resource:action naming
  [CRITICAL] SCOPE-09 GET /orders/{id}: object id in path but no owner check (BOLA)
  [HIGH] SCOPE-02 DELETE /orders/{id}: write method guarded only by a read scope
  [CRITICAL] SCOPE-09 DELETE /orders/{id}: object id in path but no owner check (BOLA)
  [CRITICAL] SCOPE-01 POST /orders: no scope required (any valid token works)
  [HIGH] SCOPE-03 POST /admin/refunds: admin function reachable with a non-admin scope (BFLA)

== orders API (reviewed): 1 finding(s)
  [MEDIUM] SCOPE-05 client 'reporting-job' granted unused scopes: orders:write, refunds:admin

Scope -> endpoint matrix (reviewed spec):
| Endpoint | orders:delete | orders:read | orders:write | refunds:admin |
|---|---|---|---|---|
| GET /health | public |  |  |  |
| GET /orders |  | X |  |  |
| GET /orders/{id} |  | X |  |  |
| DELETE /orders/{id} | X |  |  |  |
| POST /orders |  |  | X |  |
| POST /admin/refunds |  |  |  | X |

Enforcement: vulnerable vs secure
  asha, read-only token, DELETE her order    vulnerable=ALLOW secure=deny  (token lacks scope ['orders:delete'])
  asha, full token, reads ravi's order       vulnerable=ALLOW secure=deny  (object 1002 belongs to ravi, not asha)
  support agent asks for refunds:admin       vulnerable=ALLOW secure=deny  (user role lacks permission ['refunds:admin'] (scope is a ceiling, not a grant))
  finance user issues refund                 vulnerable=ALLOW secure=ALLOW (scope, role and ownership checks passed)
  undocumented route                         vulnerable=ALLOW secure=deny  (unknown route: deny by default)
```

## Steps

1. Fix `spec_weak.json` until `lint_spec` reports nothing. Compare with `spec_secure.json`.
2. Remove `refunds:admin` and `orders:write` from `reporting-job` in `clients.json`. The `SCOPE-05` finding disappears: that is least privilege for client registrations.
3. Give a support agent a token containing `refunds:admin`. Why does the secure check still deny it? (OAuth scopes limit what a **client** may do on the user's behalf; they do not give the user new rights.)
4. Add a `PATCH /orders/{id}` endpoint with `orders:write` and an owner check, then add tests for it.
5. Write the same rules as an OPA/Rego or Cedar policy (see chapter 11's policy-as-code lab).

## What you learned

- Scopes describe **what a client app may do**, roles/permissions describe **what a user may do**. Effective rights = their intersection, plus object ownership.
- Name scopes `resource:action`, keep them coarse enough to understand and fine enough for least privilege, and never define a "do everything" scope for third parties.
- Deny by default: unknown routes and endpoints without a declared scope must fail closed.

## Run the real tool (hedged)

- Keycloak or another IdP: define client scopes and map them to clients; inspect issued tokens at a lab endpoint. Verify the admin console paths for your version.
- OpenAPI: declare `securitySchemes` with OAuth2 flows and per-operation `security: [{oauth2: [orders:read]}]`; **Spectral** rules can check every operation declares a scope.
- Gateways: Kong `openid-connect` (Enterprise) or `jwt` plugins, Envoy `jwt_authn` with `requires` per route, AWS API Gateway authorizer scopes. Check current plugin availability.
