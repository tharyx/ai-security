# Lab: Audit an insecure OpenID Connect configuration

**Course items:** "Insecure OpenID Connect Configuration", "OIDC Authentication". **Lessons:** [01 section 7](../../01-authentication-types.md#7-oidc-authentication), [02 section 9](../../02-authentication-attacks.md#9-insecure-openid-connect-configuration).

**Time:** 30 minutes. **Tests:** 7, offline. **Safety:** two JSON discovery documents for a fictional provider; nothing is fetched. Only test systems you own or have written permission to test.

## Goal

Read `/.well-known/openid-configuration` like an auditor, flag what RFC 9700 and the OAuth 2.1 draft consider unsafe, and validate the claims of an ID token.

## Files

| File | Role |
|---|---|
| [fixtures/discovery_insecure.json](fixtures/discovery_insecure.json) | HTTP issuer, offsite JWKS, implicit + password grants, `none`/HS256 ID tokens, only `plain` PKCE |
| [fixtures/discovery_secure.json](fixtures/discovery_secure.json) | HTTPS, code flow only, RS256/ES256, S256 PKCE, private_key_jwt |
| [oidccheck.py](oidccheck.py) | `check_discovery`, `validate_id_token_claims`, `gate` |
| [demo.py](demo.py), [test_aps_ch10_oidc_config_check.py](test_aps_ch10_oidc_config_check.py) | demo and tests |

## Run

```text
.venv/Scripts/python appsec-course/10-api-authentication/labs/oidc-config-check/demo.py
.venv/Scripts/python -m pytest appsec-course/10-api-authentication/labs/oidc-config-check -q
```

## Real output

```text
=== discovery_insecure.json: 11 finding(s), gate exit 1 ===
  [High    ] OIDC-ISSUER-MISMATCH   issuer 'http://login.lab.example' != expected 'https://login.lab.example'
  [High    ] OIDC-NO-TLS            issuer is not https
  [High    ] OIDC-NO-TLS            authorization_endpoint is not https
  [Medium  ] OIDC-JWKS-OFFSITE      jwks_uri host differs from issuer host; confirm it is intended
  [Critical] OIDC-ALG-NONE          unsigned ID tokens allowed
  [Medium  ] OIDC-HS-ALG            HS* ID tokens are signed with the client secret; prefer RS256/ES256
  [High    ] OIDC-IMPLICIT          implicit/hybrid response types return tokens in the URL fragment
  [High    ] OAUTH-IMPLICIT-GRANT   implicit grant is removed in OAuth 2.1 / RFC 9700
  [High    ] OAUTH-ROPC-GRANT       resource owner password grant is removed in OAuth 2.1
  [Medium  ] OAUTH-PKCE-PLAIN       only 'plain' PKCE; require S256
  [Info    ] OAUTH-PUBLIC-CLIENTS   public clients allowed; acceptable only with PKCE S256

=== discovery_secure.json: 0 finding(s), gate exit 0 ===

=== ID token claim checks ===
  valid                -> []
  other client         -> ['aud does not contain our client_id']
  replayed + expired   -> ['expired or missing exp', 'nonce mismatch (possible replay)']
```

## Steps

1. For each High finding, describe the attack it enables (for example implicit flow: tokens in browser history and `Referer`; ROPC: the client sees the user's password; no PKCE: intercepted codes can be redeemed).
2. The JWKS host is a CDN. When is that acceptable? (When the provider documents it; verify ownership; never fetch keys from a URL taken from the token's own `jku` header.)
3. Add a rule: `request_uri_parameter_supported: true` without `require_request_uri_registration` is risky (SSRF on the provider). Add it to the insecure fixture and a test.
4. Add the `azp` case to the tests: an ID token with `aud: ["shop-spa", "other"]` and no `azp`.
5. Explain why the API (resource server) should never accept the ID token as an access token.

## Run the real tool (hedged)

```bash
curl -s https://login.lab/.well-known/openid-configuration > discovery.json
python -c "import json,oidccheck as o; print([f.rule for f in o.check_discovery(json.load(open('discovery.json')), 'https://login.lab')])"
```

(Run from this folder.) For a full OAuth/OIDC security test, the course's provider settings and Burp are the main tools; chapter 11 tests flows (redirect URIs, `state`, PKCE) hands-on. The repo's [MCP authentication lesson](../../../../04-mcp-security/authentication/README.md) shows the same rules for MCP servers.

## What you learned

- The discovery document is a quick health check of an identity provider's configuration.
- Code flow + PKCE S256, asymmetric ID-token signatures, HTTPS everywhere, no implicit or password grants.
- Clients must validate `iss`, `aud`/`azp`, `exp` and `nonce` on every ID token.
