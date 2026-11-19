# Lesson 01: API Security Design, Authentication and Authorization Implementation, Permissions and OAuth Scopes

**Syllabus items covered:** "API Security Design Best Practices", "Authentication Implementation", "Authorization Implementation", "Designing API Permissions", "Designing OAuth Scopes" ([CASP 8]).

**Time:** 90 minutes. **Lab:** [permissions-and-oauth-scopes](labs/permissions-and-oauth-scopes/README.md). Attacks and theory: [chapter 10 authentication](../10-api-authentication/README.md), [chapter 11 authorization and OAuth](../11-api-authorization-and-oauth/README.md). This lesson is about **building** it right.

> **DBA analogy.** You never gave an application schema `DBA`. You created roles (`ORDERS_READ`, `ORDERS_WRITE`), granted object privileges to roles, roles to users, and used VPD for row-level rules. API permissions are the same design problem: roles → permissions, and object-level policies on top.

## 1. API security design best practices

Design-time decisions are the cheapest to get right. A short list to use in design reviews:

1. **Threat model the API first** (chapters 03–05): data flows, trust boundaries, what each endpoint exposes.
2. **Contract first:** write the OpenAPI/AsyncAPI/GraphQL schema before code. It becomes the source for validation, docs, tests and the inventory.
3. **Deny by default:** every route needs an explicit authentication and authorization decision; unknown routes return 404/403.
4. **Separate public, partner, internal and admin APIs** (different hosts, gateways or at least different auth). Do not hide admin endpoints in the public API.
5. **Least data:** return only fields the client needs (DTOs), never internal ids or flags; avoid sequential ids where enumeration matters (use UUIDs, but still check ownership).
6. **Idempotency and replay protection** for money-moving operations (`Idempotency-Key` header, nonces, short-lived signatures).
7. **Limits everywhere:** sizes, page sizes, timeouts, quotas (lesson 02).
8. **Secure defaults in shared libraries:** one authentication middleware, one authorization helper, one logger with redaction. Teams should have to work hard to bypass them.
9. **Versioning and deprecation plan** so old versions are actually retired (API9 inventory).
10. **Observability by design:** request ids, audit events for security-relevant actions (lesson 04).

## 2. Authentication implementation

| Client type | Recommended | Avoid |
|---|---|---|
| Browser SPA (first party) | OIDC authorization code + PKCE through a **BFF**; session in a `__Host-` HttpOnly cookie | Tokens in `localStorage`; implicit flow |
| Mobile app | Authorization code + PKCE with the system browser; short access tokens; refresh-token rotation | Embedded webviews; password grant |
| Service to service | OAuth client credentials with private-key JWT or mTLS; or workload identity (SPIFFE, cloud IAM) | Shared static API keys for user data |
| Partner B2B | mTLS + OAuth client credentials; per-partner keys and quotas | One key shared by all partners |
| Public read-only data | API key for **identification and quotas** only | Treating an API key as user authentication |

Implementation rules:

- **Validate tokens fully** at every service (or a trusted gateway plus a network guarantee): signature with an allowlisted algorithm, `iss`, `aud`, `exp`, `nbf`, and for access tokens the RFC 9068 `typ: at+jwt` profile where used. Cache JWKS with rotation; never accept `alg: none`. Chapter 10 has the JWT attack lab.
- **Short lifetimes:** access tokens minutes, refresh tokens rotated and bound to the client; consider **DPoP** (RFC 9449) or mTLS-bound tokens (RFC 8705).
- **Centralize** authentication in middleware or the gateway, but **propagate identity** securely (a signed internal token, not an `X-User-Id` header that anyone inside the network can set).
- **Account protections:** MFA (passkeys preferred), lockout or progressive delays, breached-password checks (NIST SP 800-63B-4), generic error messages.

## 3. Authorization implementation

- **Where:** in the service that owns the data, close to the data access, in **one shared policy point** (a library or a policy engine such as OPA, Cedar, OpenFGA). The gateway can do coarse checks (scope present), not object checks.
- **Three levels on every request:** function (may this user call this endpoint?), object (may they touch **this** order?), property (may they read or write **this** field?). These map to BFLA, BOLA and BOPLA.
- **Pattern:** `authorize(subject, action, resource)` returns allow/deny with a reason; log denials. Query with the owner in the `WHERE` clause (`WHERE id = :id AND owner_id = :me`) so a missed check returns nothing.
- **Decouple decisions** with policy as code when rules grow (chapter 11's policy-engine lab); keep tests for every rule.
- **Fail closed:** errors in the authorization path mean deny.

## 4. Designing API permissions

1. List **resources** (orders, refunds, users) and **actions** (read, create, update, delete, approve, export).
2. Define **permissions** as `resource:action`.
3. Group permissions into **roles** that match real jobs (customer, support, finance, admin). Keep roles small; avoid a "super user" role used by automation.
4. Add **object rules** (owner, tenant, team) and **attribute rules** (amount < 10,000, business hours) where needed: RBAC + ABAC/ReBAC.
5. Separate **duties** for sensitive flows: the person who creates a refund cannot approve it.
6. Review the matrix (the lab's `matrix()`) with the product owner; keep it in the repo; test it.

## 5. Designing OAuth scopes

**Scopes** limit what a **client application** may do on the user's behalf (delegation). They are not roles.

- Name them `resource:action` (`orders:read`, `orders:write`, `refunds:admin`); document them for consent screens.
- **Not too coarse** (`api`, `full_access`: one stolen token does everything) and **not too fine** (hundreds of scopes nobody understands).
- Separate **read** from **write** and **admin**; destructive actions (`orders:delete`) can be their own scope.
- Grant clients only the scopes they need (the lab's `SCOPE-05`), and let users consent to less.
- **Effective permission = token scopes ∩ user's permissions**, then object checks. A scope never gives a user rights they did not have (the lab's support-agent case).
- For fine-grained needs (amount, account) use **Rich Authorization Requests** (RFC 9396) rather than inventing scopes like `payments:write:under-1000`.
- Use resource indicators / `aud` so a token for the orders API is rejected by the payments API.

## 6. Scenario: the reporting integration

A finance SaaS integrates with the orders API. To "save time", the integration team requests `orders:read orders:write refunds:admin` because "we might need refunds later". Eight months later the SaaS vendor is breached and its stored refresh tokens are stolen. With `refunds:admin` granted, the attacker issues refunds to mule accounts.

**Design fixes:** grant only `orders:read` (the client never used the others; the lab flags it); require `refunds:admin` to be approved per client by security; bind refresh tokens to the client (DPoP/mTLS); alert on refunds created by integration clients; separation of duties for refunds.

## 7. Checklist

- [ ] I can list ten API design best practices.
- [ ] I can pick the right authentication method for SPA, mobile, service and partner clients.
- [ ] I can explain function, object and property-level authorization and where each is enforced.
- [ ] I can design permissions as `resource:action`, roles, and object rules.
- [ ] I can explain why scopes are a ceiling, and the problems with over-broad scopes.

## References

- OWASP API Security Top 10 2023; OWASP Authentication, Authorization, REST Security and OAuth 2.0 cheat sheets.
- RFC 9700 (OAuth 2.0 Security BCP); RFC 9068 (JWT access tokens); RFC 8725 (JWT BCP); RFC 9396 (RAR); RFC 8707 (resource indicators); RFC 9449 (DPoP).
- OpenID AuthZEN (authorization API; verify status); OPA, Cedar and OpenFGA docs.
