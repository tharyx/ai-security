# Lesson 02: Authorization Attacks and Defenses

**Syllabus items covered:** [CASP 4] "Authorization Attacks", "Misconfigured Permissions", "Broken Object Level Authorization", "Broken Function Level Authorization", "Horizontal Privilege Escalation", "Vertical Privilege Escalation", "Authorization Defenses", "Defending Object & Function Level Access", "Forging JWT Tokens For Privilege Escalation", "Finding Another Users Location Using BOLA".

**Time:** 90 minutes. **Labs:** [bola-user-location](labs/bola-user-location/README.md), [jwt-forging-privesc](labs/jwt-forging-privesc/README.md).

> Only test systems you own or have written permission to test.

## 1. Why authorization attacks top the lists

Broken Object Level Authorization is **API1** in both the 2019 and 2023 OWASP API Security Top 10, and Broken Access Control is **A01** in the OWASP Top 10 (2021 and 2025). Scanners find these bugs poorly because the request is perfectly valid: only the *business meaning* (this is not your object) is wrong. You find them by **thinking like two users**.

## 2. Misconfigured permissions

Permissions that are wrong in **configuration** rather than code:

- An admin route marked public in a route table or gateway config (the lab's `/admin/export`).
- A cloud storage bucket or API gateway stage with "allow anonymous".
- A role that accidentally includes `*` permissions; a default service account with admin rights.
- CORS that lets any origin read authenticated responses ([chapter 13](../13-owasp-api-top-10-and-other-threats/README.md)).
- A permission checked on `GET` but not on `PUT` for the same path.

**Defense:** deny by default; route tables and gateway configs reviewed as code; an automated audit that fails CI when an `/admin` route is public (the lab's `find_misconfigured_routes`).

## 3. Broken Object Level Authorization (BOLA)

The API takes an object ID from the client (`/users/102/location`, `?order=5002`, a JSON field) and returns or changes the object **without checking that the caller may access it**. Older name: **IDOR** (insecure direct object reference), taught in [chapter 01](../01-security-champions-and-appsec-basics/README.md).

```python
# vulnerable                                     # fixed
loc = db.get_location(user_id)                    loc = db.get_location(user_id)
return loc                                        if loc.user_id != me.id and not me.is_admin:
                                                      return 404
                                                  return loc
```

**DBA view:** the vulnerable query is `SELECT * FROM locations WHERE user_id = :id`. The secure one adds `AND user_id = :me`, or a VPD policy adds it for every query automatically.

**Where IDs hide:** path, query string, JSON body (`{"account_id": 7}`), headers (`X-Account-Id`), GraphQL arguments, batch endpoints (`/orders?ids=1,2,3`), and file names (`/invoices/7.pdf`).

**Scenario (the lab).** A ride-hailing app exposes `GET /api/v1/users/{id}/location` so riders can see their saved home pin. User IDs are sequential. A stalker with an ordinary account loops from 1 to 100,000 and builds a map of every user's home. This exact class of bug has hit real fitness, scooter and car-sharing apps.

## 4. Broken Function Level Authorization (BFLA)

The API exposes a **function** (usually admin or staff) and checks only that the caller is logged in, not that the caller has the right role. Attackers find these functions by guessing (`/admin`, `/internal`, `/v1/users/{id}` with `DELETE` instead of `GET`), reading JavaScript bundles and API docs ([chapter 09 recon](../09-api-tooling-and-reconnaissance/README.md)), or switching HTTP methods.

**Defense:** a function-level check in one place (router, middleware, gateway, or PDP) with **deny by default**: a new route has no access until someone grants it.

## 5. Horizontal and vertical privilege escalation

| | Horizontal | Vertical |
|---|---|---|
| Meaning | Same privilege level, **another user's** data or actions | **Higher** privilege level than you have |
| Example | Rider alice reads rider bob's trip | Rider alice becomes admin |
| Typical cause | BOLA | BFLA, mass assignment of `role`, forged token claims |
| Oracle analogy | User A reads user B's schema | User runs `GRANT DBA TO me` successfully |

Common vertical escalation paths in APIs:

- **Mass assignment:** `PUT /users/me {"role": "admin"}` binds the field straight into the model ([chapter 12 lab](../12-input-validation-and-injection/labs/mass-assignment/README.md)).
- **Trusted claims:** the API trusts `role` or `is_admin` from a token, cookie or header the client can change (section 6).
- **Hidden parameters:** `?debug=true`, `?admin=1`, `X-Original-URL` header overrides.
- **Workflow skipping:** calling step 3 (approve) without step 2 (review).

## 6. Forging JWTs for privilege escalation

A JWT is base64-encoded JSON plus a signature (basics in [chapter 10](../10-api-authentication/README.md)). If the API makes authorization decisions from claims inside the token, then **any way to forge a token is a way to become admin**:

| Forgery path | How | Defense |
|---|---|---|
| `alg: none` | Strip the signature, set `"alg": "none"` | Pin the algorithm server-side |
| Weak HMAC key | Crack it offline from one token (hashcat `-m 16500`) | 256-bit random key from a vault; rotate |
| RS256 → HS256 key confusion | Sign with HS256 using the server's **public** key as the HMAC key | Pin algorithm per key; separate key types |
| `kid` injection | `kid: "../../dev/null"` or SQL in `kid` selects a key the attacker knows | Treat `kid` as a lookup in a fixed allowlist |
| `jku` / `x5u` abuse | Point the header at the attacker's own key set | Ignore or allowlist these headers |
| Signature not verified | Library `decode()` used instead of `verify()` | Tests that a tampered token is rejected |
| Missing `exp`/`aud` checks | Old or other-service tokens accepted | Validate `exp`, `nbf`, `iss`, `aud` (RFC 8725) |

**Even with perfect signatures,** prefer to look up roles and ownership on the server. A token claim is a snapshot from login time: if an admin is demoted, a long-lived token keeps the old role.

**Scenario.** A payments API puts `"role": "user"` in an HS256 token signed with the key `changeme` from a tutorial. A tester captures her own token, cracks the key in under a second with a small wordlist, changes the role to `admin`, re-signs, and downloads the payout report. The fix needs three changes: a strong random key, algorithm pinning, and server-side role lookup.

## 7. Authorization defenses

### 7.1 Defending object and function level access

1. **Deny by default** at both function and object level.
2. **Central enforcement:** one authorization layer (middleware + PDP, or a data-access layer that always adds the owner filter). Do not trust each developer to remember.
3. **Object check on every access path:** read, update, delete, export, search, batch, file download, GraphQL resolver, websocket message.
4. **Take identity from the session or token, never from the request body** (`user_id` in the URL is a *target*, not the caller).
5. **Allowlist writable fields** per role (no `role`, `is_admin`, `owner_id` from clients).
6. **Return 404 for objects the caller may not see**, so attackers cannot tell "exists" from "forbidden" (optional, but helps against probing).
7. **Unpredictable IDs (UUIDv4) are defence in depth only.** They slow enumeration; they do not replace the check.
8. **Tests with two users** for every endpoint (user A's token on user B's object must fail), run in CI. Tools: Burp Autorize/AuthMatrix ([real-tools guide](real-tools/authorization-testing-tools.md)).
9. **Log and alert** on many 403/404s on sequential IDs from one user (an enumeration signal).

### 7.2 Policy and model choices

Use the models in [lesson 01](01-authorization-models-and-policy-as-code.md): RBAC for functions, ABAC/ReBAC for objects, a PDP to keep it testable. For OAuth scopes as coarse function-level permissions, see [lesson 03](03-oauth-and-token-types.md).

## Check yourself

1. Why does a scanner rarely find BOLA, and how do you test for it?
2. Give two ways to reach vertical escalation without any authentication bug.
3. The token is correctly signed with a strong key. Why might trusting its `role` claim still be a problem?
