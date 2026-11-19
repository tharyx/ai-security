# Chapter 11: API Authorization and OAuth

Authentication tells an API **who** is calling; authorization decides **what that caller may do to which object**. This chapter covers the authorization models (RBAC, DAC, ABAC, ReBAC), the attacks that dominate real API breaches (BOLA, BFLA, privilege escalation, forged JWTs), policy as code, and OAuth: its flows, insecure configurations, OAuth 2.0 vs 2.1, and the three token types. Five offline labs let you attack and fix each one.

> **Safety.** Every lab is a simulation: in-process toy APIs and an in-process OAuth server, no sockets and no real identity provider. Tokens and keys are random values made at runtime and labelled FAKE. Only test systems you own or have written permission to test.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Tool status and version numbers are hedged: **verify at the source**.

## Syllabus coverage

| Syllabus item | Where to study | Lab |
|---|---|---|
| [CASP 4] Overview of API Authorization | [01 section 1](01-authorization-models-and-policy-as-code.md#1-overview-of-api-authorization) (SVG) | [authz-models](labs/authz-models/README.md) |
| [CASP 4] Types of Authorization | [01 section 2](01-authorization-models-and-policy-as-code.md#2-types-of-authorization) | [authz-models](labs/authz-models/README.md) |
| [CASP 4] No Authorization | [01 section 2.1](01-authorization-models-and-policy-as-code.md#21-no-authorization) | [authz-models](labs/authz-models/README.md) (`no_authz`) |
| [CASP 4] Role-Based Access Control (RBAC) | [01 section 2.2](01-authorization-models-and-policy-as-code.md#22-role-based-access-control-rbac) | [authz-models](labs/authz-models/README.md) |
| [CASP 4] Discretionary Access Control (DAC) | [01 section 2.3](01-authorization-models-and-policy-as-code.md#23-discretionary-access-control-dac) | [authz-models](labs/authz-models/README.md) |
| [CASP 4] Attribute-Based Access Control (ABAC) | [01 section 2.4](01-authorization-models-and-policy-as-code.md#24-attribute-based-access-control-abac) | [authz-models](labs/authz-models/README.md) |
| [CASP 4] Relationship-Based Access Control (ReBAC) | [01 section 2.5](01-authorization-models-and-policy-as-code.md#25-relationship-based-access-control-rebac) | [authz-models](labs/authz-models/README.md) |
| [CASP 4] Authorization Attacks | [02 section 1](02-authorization-attacks-and-defenses.md#1-why-authorization-attacks-top-the-lists) | [bola-user-location](labs/bola-user-location/README.md) |
| [CASP 4] Misconfigured Permissions | [02 section 2](02-authorization-attacks-and-defenses.md#2-misconfigured-permissions) | [bola-user-location](labs/bola-user-location/README.md) (route audit) |
| [CASP 4] Broken Object Level Authorization | [02 section 3](02-authorization-attacks-and-defenses.md#3-broken-object-level-authorization-bola); OWASP API1 in [chapter 13](../13-owasp-api-top-10-and-other-threats/01-owasp-api-top-10-2019-and-2023.md) | [bola-user-location](labs/bola-user-location/README.md) |
| [CASP 4] Broken Function Level Authorization | [02 section 4](02-authorization-attacks-and-defenses.md#4-broken-function-level-authorization-bfla) | [bola-user-location](labs/bola-user-location/README.md) |
| [CASP 4] Horizontal Privilege Escalation | [02 section 5](02-authorization-attacks-and-defenses.md#5-horizontal-and-vertical-privilege-escalation) | [bola-user-location](labs/bola-user-location/README.md) |
| [CASP 4] Vertical Privilege Escalation | [02 section 5](02-authorization-attacks-and-defenses.md#5-horizontal-and-vertical-privilege-escalation) | [bola-user-location](labs/bola-user-location/README.md), [jwt-forging-privesc](labs/jwt-forging-privesc/README.md) |
| [CASP 4] Authorization Defenses | [02 section 7](02-authorization-attacks-and-defenses.md#7-authorization-defenses) | all labs (secure versions) |
| [CASP 4] Defending Object & Function Level Access | [02 section 7.1](02-authorization-attacks-and-defenses.md#71-defending-object-and-function-level-access) | [bola-user-location](labs/bola-user-location/README.md) |
| [CASP 4] Attribute-Based Access Control (ABAC) with Roles, and Relations | [01 section 2.6](01-authorization-models-and-policy-as-code.md#26-abac-with-roles-and-relations-combining-models) | [policy-as-code-pdp](labs/policy-as-code-pdp/README.md), [authz-models](labs/authz-models/README.md) |
| [CASP 4] Decoupling Authorization Decisions With Policy As Code | [01 section 4](01-authorization-models-and-policy-as-code.md#4-decoupling-authorization-decisions-with-policy-as-code); [real-tools](real-tools/authorization-testing-tools.md#policy-engines) | [policy-as-code-pdp](labs/policy-as-code-pdp/README.md) |
| [CASP 4] Authorizing with OAuth Framework | [03 section 1](03-oauth-and-token-types.md#1-authorizing-with-the-oauth-framework); repo [MCP authentication](../../04-mcp-security/authentication/README.md) | [oauth-flows](labs/oauth-flows/README.md) |
| [CASP 4] OAuth Specification | [03 section 2](03-oauth-and-token-types.md#2-the-oauth-specification-what-to-read) | n/a |
| [CASP 4] Different Authorization Workflows | [03 section 3](03-oauth-and-token-types.md#3-different-authorization-workflows-grant-types) (SVG) | [oauth-flows](labs/oauth-flows/README.md) |
| [CASP 4] Insecure OAuth Configurations | [03 section 4](03-oauth-and-token-types.md#4-insecure-oauth-configurations) | [oauth-flows](labs/oauth-flows/README.md) (attacks + config audit) |
| [CASP 4] OAuth 2.0 vs OAuth 2.1 | [03 section 5](03-oauth-and-token-types.md#5-oauth-20-vs-oauth-21) | [oauth-flows](labs/oauth-flows/README.md) (vulnerable = 2.0-era, secure = 2.1 rules) |
| [CASP 4] Different Types of Tokens | [03 section 6](03-oauth-and-token-types.md#6-different-types-of-tokens) | [oauth-flows](labs/oauth-flows/README.md) |
| [CASP 4] Access Token | [03 section 6.1](03-oauth-and-token-types.md#61-access-token) | [oauth-flows](labs/oauth-flows/README.md) |
| [CASP 4] Refresh Token | [03 section 6.2](03-oauth-and-token-types.md#62-refresh-token) | [oauth-flows](labs/oauth-flows/README.md) (rotation + reuse detection) |
| [CASP 4] ID Token | [03 section 6.3](03-oauth-and-token-types.md#63-id-token) | [oauth-flows](labs/oauth-flows/README.md) (ID token rejected at the API) |
| [CASP 4] Forging JWT Tokens For Privilege Escalation | [02 section 6](02-authorization-attacks-and-defenses.md#6-forging-jwts-for-privilege-escalation); JWT basics in [chapter 10](../10-api-authentication/README.md) | [jwt-forging-privesc](labs/jwt-forging-privesc/README.md) |
| [CASP 4] Finding Another Users Location Using BOLA | [02 section 3](02-authorization-attacks-and-defenses.md#3-broken-object-level-authorization-bola); [real-tools](real-tools/authorization-testing-tools.md) | [bola-user-location](labs/bola-user-location/README.md) |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| **OAuth 2.1** taught as a finished standard | Still an IETF **draft**. Its rules (PKCE for all code flows, no implicit or password grant, exact redirect URIs, no tokens in query strings, rotated or sender-constrained refresh tokens) are already required by **RFC 9700, the OAuth 2.0 Security BCP (Jan 2025)**. |
| OAuth for SPAs with the implicit flow | Use code + PKCE, and preferably a **backend-for-frontend** so the browser never holds tokens. |
| JWT access tokens without a profile | **RFC 9068** (`typ: at+jwt`, required claims) and the **JWT BCP RFC 8725**. |
| Bearer tokens only | **DPoP (RFC 9449)** and **mTLS (RFC 8705)** bind tokens to a key so a stolen token is not enough. |
| Authorization "frameworks" without names | Current policy engines: **OPA/Rego**, **Cedar**, **OpenFGA/SpiceDB** (ReBAC), **Casbin**; the OpenID **AuthZEN** working group standardises the PEP-to-PDP API (check status). |
| OWASP API Top 10 names for BOLA/BFLA | Same ids in **2019 and 2023** (API1 BOLA, API5 BFLA). Excessive Data Exposure and Mass Assignment are now **API3 BOPLA** ([chapter 13](../13-owasp-api-top-10-and-other-threats/README.md)). |

## How the three courses overlap here

- **CASP 4 only** owns this chapter. The Security Champion course teaches **IDOR** and **broken access control** as web-app basics in [chapter 01](../01-security-champions-and-appsec-basics/README.md) and "Defending Authorization" as a code-review item in [chapter 02](../02-secure-code-review-and-asvs/README.md); this chapter is the deeper API version.
- **Elevation of privilege** (the "E" in STRIDE, [chapter 04](../04-threat-modeling-methods-and-rating/README.md)) is the threat; BOLA, BFLA and forged tokens are how it happens in APIs.
- JWT basics and token storage live in [chapter 10](../10-api-authentication/README.md); OAuth scope design is revisited in [chapter 15](../15-implementing-api-security-mechanisms/README.md).

## Learning order

1. [Lesson 01](01-authorization-models-and-policy-as-code.md), then the [authz-models lab](labs/authz-models/README.md). About 2 hours.
2. The [policy-as-code-pdp lab](labs/policy-as-code-pdp/README.md). About 45 minutes.
3. [Lesson 02](02-authorization-attacks-and-defenses.md), then the [bola-user-location lab](labs/bola-user-location/README.md) and the [jwt-forging-privesc lab](labs/jwt-forging-privesc/README.md). About 3 hours.
4. [Lesson 03](03-oauth-and-token-types.md), then the [oauth-flows lab](labs/oauth-flows/README.md). About 2.5 hours.
5. Optional: the [real-tools guide](real-tools/authorization-testing-tools.md) in your course lab environment. About 1 hour.

## Lab index

All labs run offline: `.venv/Scripts/python -m pytest appsec-course/11-api-authorization-and-oauth -q -p no:cacheprovider`.

| Lab | Course exercise | Tests |
|---|---|---|
| [authz-models](labs/authz-models/README.md) | Types of authorization (none, RBAC, DAC, ABAC, ReBAC) | 8 |
| [policy-as-code-pdp](labs/policy-as-code-pdp/README.md) | Decoupling Authorization Decisions With Policy As Code | 8 |
| [bola-user-location](labs/bola-user-location/README.md) | Finding Another Users Location Using BOLA (+ BFLA, privilege escalation) | 8 |
| [jwt-forging-privesc](labs/jwt-forging-privesc/README.md) | Forging JWT Tokens For Privilege Escalation | 8 |
| [oauth-flows](labs/oauth-flows/README.md) | OAuth workflows, insecure configurations, token types | 10 |

Hedged guide for real tools: [authorization-testing-tools.md](real-tools/authorization-testing-tools.md) (Burp Autorize/AuthMatrix/JWT Editor, jwt_tool, hashcat, Keycloak, OPA).

## Exam tips

- **BOLA = object, BFLA = function, BOPLA = property.** Say which check is missing.
- **Horizontal = same level, other user; vertical = higher level.**
- **Test with two users.** Swap IDs and swap tokens; that is the BOLA/BFLA methodology.
- **Unpredictable IDs are not a fix** for BOLA, only a speed bump.
- **Take identity from the token or session, never from the body or URL.**
- **Never trust a role claim you did not verify, and prefer server-side role lookup.**
- **OAuth is authorization; OIDC adds authentication** with the ID token.
- **ID token audience = the client; access token audience = the API.** Never send an ID token to an API.
- **OAuth 2.1 removes implicit and password grants and requires PKCE;** say "still a draft; RFC 9700 already requires most of it".
- **Refresh token rotation + reuse detection** turns a stolen refresh token into an alarm.

## Interview / exam questions

<details>
<summary>1. What is the difference between authentication and authorization in an API?</summary>

Authentication proves who the caller is (password, token, certificate). Authorization decides, on every request, whether that caller may perform this action on this object. A valid token says nothing about which objects the caller may touch.
</details>

<details>
<summary>2. Compare RBAC, ABAC and ReBAC with one use case each.</summary>

RBAC: permissions via roles; good for function-level access ("only support can issue refunds"). ABAC: rules over subject/resource/environment attributes; good for context ("agents read tickets in their own region during shift"). ReBAC: relationships in a graph; good for sharing and organisations ("members of a team can view the team's folders and their documents").
</details>

<details>
<summary>3. What is DAC and what is its main weakness?</summary>

Discretionary access control: the owner of an object decides who may access it (file permissions, document sharing, SQL GRANT). Its weakness is that rights can spread through re-grants beyond the owner's view, and there is no central policy.
</details>

<details>
<summary>4. Explain BOLA with an example and the fix.</summary>

`GET /api/users/102/location` returns user 102's location to any logged-in user because the handler never checks that 102 is the caller (or that the caller is admin). Fix: an object-level check on every access path, ideally enforced centrally (a PDP or a data-layer filter), with two-user tests in CI.
</details>

<details>
<summary>5. How is BFLA different from BOLA?</summary>

BFLA is about functions: a normal user can call an admin or staff operation (`DELETE /admin/users/7`) because there is no role check. BOLA is about objects: the user calls a legitimate function on someone else's object.
</details>

<details>
<summary>6. Give three ways to achieve vertical privilege escalation in an API.</summary>

Mass assignment of a `role` or `is_admin` field; calling an unprotected admin endpoint (BFLA); forging or tampering a token claim the API trusts (alg none, weak HMAC key, key confusion); hidden debug parameters; skipping a workflow step.
</details>

<details>
<summary>7. Why do unpredictable IDs (UUIDs) not fix BOLA?</summary>

IDs leak through URLs, logs, shared links, other API responses and referrers. Once an attacker has an ID, the missing authorization check still lets them in. UUIDs only slow down enumeration.
</details>

<details>
<summary>8. How does policy as code help authorization, and what can it not do?</summary>

It centralises decisions in a PDP with version-controlled, reviewed, unit-tested policies and decision logs, so rules can change without code changes. It cannot help a handler that never calls the PDP, and policies still need tests for both allow and deny cases.
</details>

<details>
<summary>9. Describe the authorization code flow with PKCE.</summary>

The client creates a random code_verifier and sends its SHA-256 (code_challenge, S256) in the authorize request with state. After login the AS redirects back with a code. The client checks state and exchanges the code plus the verifier at the token endpoint. The AS checks that the code is unused, bound to the client and redirect URI, and that the verifier hashes to the challenge, then issues tokens.
</details>

<details>
<summary>10. List five insecure OAuth configurations.</summary>

Non-exact redirect URI matching; PKCE not required; state not checked; implicit or password grant enabled; reusable or long-lived codes; long-lived access tokens; non-rotating refresh tokens for public clients; tokens in query strings; APIs not checking aud; client secrets in mobile apps or SPAs.
</details>

<details>
<summary>11. What changes in OAuth 2.1 compared with 2.0?</summary>

PKCE required for the code flow; implicit and resource owner password grants removed; exact redirect URI matching; no bearer tokens in query strings; refresh tokens for public clients must be sender-constrained or rotated. It is still an IETF draft; RFC 9700 (the security BCP) already requires most of these.
</details>

<details>
<summary>12. Compare access, refresh and ID tokens.</summary>

Access token: for the API (aud = API), short-lived, carries scopes. Refresh token: for the authorization server only, longer-lived, used to get new access tokens, should rotate. ID token: OIDC JWT for the client (aud = client_id) describing the login; never sent to APIs.
</details>

<details>
<summary>13. Why is accepting an ID token at an API dangerous?</summary>

Any client the user logged into receives an ID token whose audience is that client. If the API accepts it, a malicious or compromised client can call the API as the user. APIs must require access tokens with their own audience (and typ at+jwt for JWT access tokens).
</details>

<details>
<summary>14. How does refresh token rotation with reuse detection work?</summary>

Each refresh returns a new refresh token and invalidates the old one. If an old token is presented again, someone has a copy, so the AS revokes the whole token family, forcing a new login for both the attacker and the user.
</details>

<details>
<summary>15. A JWT is signed with a strong key and the API verifies it. Is it safe to authorize from its role claim?</summary>

Not fully. The claim is a snapshot from login time (a demoted admin keeps the role until expiry), and anyone who controls issuance or the key can set it. Prefer short lifetimes, scopes for coarse access, and server-side lookups of roles and ownership for sensitive actions; always add object-level checks.
</details>

## References

- OWASP API Security Top 10 2023 (API1 BOLA, API3 BOPLA, API5 BFLA); OWASP Authorization Cheat Sheet; OWASP Testing Guide (authorization testing).
- NIST SP 800-162 (ABAC); Google Zanzibar paper (2019); OpenFGA, SpiceDB, OPA, Cedar, Casbin documentation; OpenID AuthZEN.
- RFC 6749, 6750, 7636, 8628, 8693, 8705, 8707, 8725, 9068, 9449, **9700**; the OAuth 2.1 draft; OpenID Connect Core 1.0; IETF "OAuth 2.0 for Browser-Based Applications" draft.
- Repo: [MCP authentication](../../04-mcp-security/authentication/README.md), [cybersecurity-track database security](../../cybersecurity-track/11-database-security/README.md) (Oracle VPD and privileges).

**Next chapter:** [Chapter 12: Input Validation and Injection](../12-input-validation-and-injection/README.md)
