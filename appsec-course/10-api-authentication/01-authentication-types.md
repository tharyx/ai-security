# Lesson 01: API Authentication and Its Types

**Syllabus items covered:** "Overview of API Authentication", "Types of Authentication", "No Authentication (Public APIs)", "HTTP Basic Authentication", "API Token Authentication", "OIDC Authentication", "JSON Web Tokens (JWTs)", "SAML Tokens", "Mutual TLS", "Talking To An API Using OAuth and JWT", "Talking To An API Using HTTP Basic and API Keys" ([CASP 3]).

**Time:** 2 hours. **Labs:** [auth-methods](labs/auth-methods/README.md), [jwt-attacks](labs/jwt-attacks/README.md). OAuth **flows** and token types in depth are in [chapter 11](../11-api-authorization-and-oauth/README.md); OAuth for MCP servers is in [04-mcp-security/authentication](../../04-mcp-security/authentication/README.md).

> **DBA analogy.** Oracle gives you password authentication, OS authentication, Kerberos, and wallet/certificate (SSL) authentication. Each answers "who is connecting, and how do they prove it?" API authentication is the same question per HTTP request, and like `CREATE USER ... IDENTIFIED EXTERNALLY`, the method you pick decides what can go wrong.

![API authentication types](../../images/aps-ch10-auth-types.svg)

## 1. Overview of API authentication

Authentication answers **"who is calling, and is the proof valid?"** Authorization (chapter 11) answers "what may they do?". For APIs:

- **Every request** must carry proof, because HTTP is stateless (or a session cookie that points to server-side proof).
- **Callers are often programs**: a mobile app acting for a user, a back-end service acting for itself, a partner's server, a CI job, an AI agent.
- **Two identities may be present:** the **user** (resource owner) and the **client application**. OAuth separates them; API keys usually identify only the application.
- The OWASP API Top 10 calls failures here **API2:2023 Broken Authentication**.

## 2. Types of authentication

| Type | Proof on the wire | Identifies | Typical use | Main weaknesses |
|---|---|---|---|---|
| None | nothing | nobody | public data | abuse, scraping, data that should not be public |
| HTTP Basic | `Authorization: Basic base64(user:pass)` | user or service account | internal tools, legacy | password on every request; base64 is not encryption |
| API key / token | `X-API-Key: ...` or `Authorization: Bearer <opaque>` | the application | server-to-server, partner access, metering | long-lived, shared, leaked in code and URLs, no user context |
| JWT bearer | `Authorization: Bearer <header.payload.sig>` | user and/or client, plus claims | OAuth access tokens, service tokens | validation mistakes (alg, secret, exp, aud) |
| OAuth 2.0 / OIDC | access token from an authorization server; ID token for login | user + client | modern apps, SSO, third-party access | flow misconfiguration, token leakage |
| SAML | signed XML assertion | user | enterprise SSO (browser-based) | XML signature wrapping, XXE, replay |
| Mutual TLS | client certificate in the TLS handshake | the client machine/service | service-to-service, banking/open-banking APIs | certificate lifecycle; trusting a header instead of the handshake |

## 3. No authentication (public APIs)

Some data really is public (product catalogue, exchange rates, public transport times). "No authentication" still needs:

- a **conscious decision** recorded in the spec (`security: []`) and threat model;
- **rate limiting and quotas** by IP or anonymous key, and caching;
- **minimal responses** (no internal IDs, no personal data);
- a check that write operations are **never** public.

Many breaches are "public" endpoints that were never meant to be: a debug route, an export, an old version. Discovery of those is [chapter 09](../09-api-tooling-and-reconnaissance/README.md).

## 4. HTTP Basic authentication

```http
GET /basic HTTP/1.1
Authorization: Basic c3ZjLXJlYWRlcjpGQUtFLXB3       (base64 of "svc-reader:FAKE-pw")
```

- Defined in RFC 7617. The server answers 401 with `WWW-Authenticate: Basic realm="..."` when credentials are missing or wrong.
- **Base64 is encoding, not encryption**: anyone who sees the header has the password. Use only over TLS.
- The password travels on **every** request, so it ends up in more places (proxies, logs, memory dumps). No built-in expiry, logout or MFA.
- Acceptable for simple machine accounts behind TLS with a strong random secret and rotation; otherwise prefer tokens.
- Compare credentials in **constant time** (`hmac.compare_digest`) and rate limit to stop guessing.

## 5. API token authentication

An **API key** is a long random string issued to a client application.

Good practice:

- Send it in a **header** (`X-API-Key` or `Authorization`), **never in the URL**: query strings land in server logs, proxy logs, browser history and `Referer` headers. The auth-methods lab returns 400 for `?api_key=`.
- Generate with a CSPRNG (≥ 128 bits), store only a **hash** server-side (like a password), show it once.
- Give each client its own key with **scopes**, an owner, an expiry and a rotation process; support two active keys during rotation.
- Prefix keys with a recognisable tag so secret scanners can find leaks (many providers do this).
- Remember a key identifies the **application, not the user**: it is not a substitute for user authentication or object-level authorization.

**Opaque bearer tokens** (random strings looked up by the server, or checked with OAuth token introspection, RFC 7662) are similar but short-lived and issued by an authorization server.

## 6. JSON Web Tokens (JWTs)

![JWT anatomy](../../images/aps-ch10-jwt-anatomy.svg)

A JWT (RFC 7519) is `base64url(header).base64url(payload).base64url(signature)`.

| Part | Example | Notes |
|---|---|---|
| Header | `{"alg":"HS256","typ":"JWT","kid":"main"}` | `alg` = signing algorithm; `kid` = key id |
| Payload (claims) | `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `scope`, custom claims | **readable by anyone**: never put secrets or sensitive personal data in it |
| Signature | HMAC-SHA256 with a shared secret (HS256) or RSA/ECDSA private key (RS256, ES256, PS256), or EdDSA | proves integrity and issuer |

Key facts:

- **Signed ≠ encrypted.** JWS (signed) is the common case. JWE (encrypted) exists but is rarer.
- **HS256** uses one shared secret for signing and verifying, so every verifier can also forge tokens; the secret must be long and random. **RS256/ES256** sign with a private key and verify with a public key published as a **JWKS** (JSON Web Key Set), which is better when many services verify.
- **Self-contained:** a verifier does not call the issuer, which is fast but makes **revocation hard**: keep access tokens short-lived (minutes) and use refresh tokens.
- Profiles and best practice: **RFC 8725** (JWT Best Current Practices), **RFC 9068** (JWT profile for OAuth access tokens). Verify the current status at the source.

Validation checklist (every request): parse safely; **allowlist the algorithm** for that key (never trust the header's `alg` blindly); verify the signature with the right key; check `exp` (and `nbf`) with small clock skew; check `iss` and `aud`; then authorize based on claims. The [jwt-attacks lab](labs/jwt-attacks/README.md) builds HS256 from `hmac`/`hashlib`/`base64` and shows each missed check being exploited.

## 7. OIDC authentication

**OpenID Connect** is an identity layer on OAuth 2.0. OAuth alone is about **delegated authorization** ("this app may read your calendar"); OIDC adds **authentication** ("this is Alice, as asserted by the identity provider").

- The client redirects the user to the OpenID Provider (OP); with the **authorization code flow + PKCE**, it receives a code and exchanges it for tokens.
- The **ID token** (always a JWT) is for the **client**: it says who logged in. Validate `iss`, `aud` (= your client id), `exp`, `nonce`, and the signature from the provider's JWKS.
- The **access token** is for the **API** (resource server). **Never send the ID token to an API as an access token**, and never accept an ID token as API authorization.
- Discovery: the provider publishes `/.well-known/openid-configuration` with its endpoints, JWKS URI, supported algorithms, grants and PKCE methods. The [oidc-config-check lab](labs/oidc-config-check/README.md) audits one.

## 8. SAML tokens

**SAML 2.0** is the older XML-based federation standard, still common for enterprise SSO.

- The identity provider (IdP) sends a signed **assertion** (XML) via the user's browser to the service provider (SP).
- Not designed for APIs directly; APIs usually exchange a SAML assertion for an OAuth token (RFC 7522 SAML bearer grant) or sit behind an SP session.
- Classic flaws: **XML Signature Wrapping** (a signed element is valid but the app reads a different, unsigned one), **XXE** in the parser, **comment injection** in NameID, missing checks of `Audience`, `Recipient`, `NotOnOrAfter` and `InResponseTo` (replay). Use a maintained library, never parse and verify by hand. SOAP and XML attacks are in [chapter 13](../13-owasp-api-top-10-and-other-threats/README.md).

## 9. Mutual TLS

In normal TLS only the server shows a certificate. In **mutual TLS (mTLS)** the client also presents a certificate and proves it holds the private key.

- Strong, phishing-resistant authentication of **machines and services**; used in service meshes (Istio, Linkerd), open banking, and B2B APIs.
- **OAuth mTLS (RFC 8705)** binds tokens to the client certificate, so a stolen token is useless without the key; **DPoP (RFC 9449)** does the same at the application layer.
- Operational cost: issuing, rotating and revoking certificates; a private CA; short-lived certs (SPIFFE/SPIRE automate this).
- **Common mistake:** TLS terminates at a proxy, which forwards the client certificate in a header (for example `X-Client-Cert`). If the back end also accepts that header **directly from clients**, anyone can claim any certificate. The [auth-methods lab](labs/auth-methods/README.md) trusts only the fingerprint passed by the TLS layer and ignores the header.

## 10. Talking to an API using HTTP Basic and API keys

```bash
# Basic: curl builds the header for you
curl -s -u "svc-reader:$BASIC_PW" https://api.lab/basic
# the same header by hand
curl -s -H "Authorization: Basic $(printf 'svc-reader:%s' "$BASIC_PW" | base64)" https://api.lab/basic
# API key in a header (good) vs in the URL (bad: logged everywhere)
curl -s -H "X-API-Key: $API_KEY" https://api.lab/apikey
curl -s "https://api.lab/apikey?api_key=$API_KEY"          # avoid
```

## 11. Talking to an API using OAuth and JWT

Service-to-service with the **client credentials** grant, then calling the API with the access token:

```bash
TOKEN=$(curl -s -X POST https://login.lab/oauth/token \
  -d grant_type=client_credentials -d client_id=demo-client \
  -d client_secret="$CLIENT_SECRET" -d scope=orders:read | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" https://api.lab/bearer
# look inside the JWT (no verification, just decoding the payload)
echo "$TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null; echo
```

For a **user** the client would use the **authorization code flow with PKCE** in a browser (chapter 11). In Postman, the Authorization tab's OAuth 2.0 helper performs both flows. Note the token response header `Cache-Control: no-store`: tokens must not be cached.

## 12. Scenario: the internal header

An insurer puts an mTLS-terminating load balancer in front of its claims API and configures it to forward `X-SSL-Client-Verify: SUCCESS` and the client DN. A second, older route to the same service skips the load balancer. A partner's developer notices that sending those two headers directly to the old route returns claims for any partner. **Fixes:** the back end accepts identity headers only from the proxy (network policy + a shared secret or mTLS between proxy and service), removes the old route, and the proxy **overwrites** (not appends) those headers on every request.

## 13. Self-check

1. Why is HTTP Basic acceptable only over TLS, and what does it still lack?
2. What is the difference between an ID token and an access token, and who consumes each?
3. Give two reasons to prefer RS256/ES256 over HS256 when many services verify tokens.

Next: [Lesson 02, authentication attacks](02-authentication-attacks.md).
