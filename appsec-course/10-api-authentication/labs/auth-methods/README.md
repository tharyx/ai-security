# Lab: Talking to an API with Basic, API keys, OAuth + JWT and (simulated) mTLS

**Course items:** "Talking To An API Using HTTP Basic and API Keys", "Talking To An API Using OAuth and JWT", plus the "Types of Authentication" list. **Lesson:** [01 Authentication types](../../01-authentication-types.md).

**Time:** 45 minutes. **Tests:** 9, offline. **Safety:** one in-process API; every credential (Basic password, API key, client secret, JWT key, client-certificate fingerprint) is FAKE and generated per run. mTLS is **simulated**: the "TLS layer" is a function argument. Only test systems you own or have written permission to test.

## Goal

Call the same API with each authentication type, see what each 401 looks like, and learn the classic mistake for each (key in URL, tampered token, trusted certificate header).

## Routes

| Route | Auth | Notes |
|---|---|---|
| `GET /public` | none | public |
| `GET /basic` | `Authorization: Basic base64(user:pass)` | constant-time comparison; `WWW-Authenticate: Basic` on failure |
| `GET /apikey` | `X-API-Key` header | `?api_key=` in the URL is refused with 400 |
| `POST /oauth/token` | `client_credentials` grant (form body) | returns a 5-minute HS256 JWT with `Cache-Control: no-store`; the `password` grant is refused |
| `GET /bearer` | `Authorization: Bearer <JWT>` | verifies alg, signature, `aud`, `exp` |
| `GET /mtls` | client certificate (simulated) | trusts only `tls_client_fp` from the TLS layer, never an `X-Client-Cert` header |

Files: [authapi.py](authapi.py), [demo.py](demo.py), [test_aps_ch10_auth_methods.py](test_aps_ch10_auth_methods.py).

## Run

```text
.venv/Scripts/python appsec-course/10-api-authentication/labs/auth-methods/demo.py
.venv/Scripts/python -m pytest appsec-course/10-api-authentication/labs/auth-methods -q
```

## Real output

```text
=== No authentication ===
  GET /public                                  -> 200 {'data': 'anyone can read this'}

=== HTTP Basic ===
  GET /basic (right user:pass)                 -> 200 {'data': 'hello svc-reader'}
  GET /basic (wrong password)                  -> 401 {'error': 'unauthorized'}

=== API key ===
  GET /apikey  X-API-Key header                -> 200 {'data': 'api key accepted'}
  GET /apikey?api_key=... (in the URL)         -> 400 {'error': 'send the API key in the X-API-Key header, not the URL'}

=== OAuth 2.0 client_credentials -> JWT bearer ===
  POST /oauth/token -> 200 token_type=Bearer expires_in=300 Cache-Control=no-store
  GET /bearer (issued token)                   -> 200 {'data': 'token for demo-client scope=orders:read'}
  GET /bearer (signature tampered)             -> 401 {'error': 'unauthorized'}

=== Mutual TLS (simulated) ===
  GET /mtls (verified cert from TLS layer)     -> 200 {'data': 'client certificate verified'}
  GET /mtls (client sends X-Client-Cert header) -> 401 {'error': 'client certificate required'}
```

## Steps

1. Decode a Basic header by hand (`base64.b64decode`). The test `test_basic_auth_is_only_encoding_not_encryption` makes the point: TLS is mandatory.
2. Decode the issued JWT's payload (split on `.`, base64url-decode the middle). Everything in it is readable. What would be wrong with putting the user's email or a secret there?
3. Change `/apikey` to accept `?api_key=`, then imagine the access log line. Revert.
4. Change the `/mtls` route to also accept `headers["x-client-cert"]`. Run the tests: `test_mtls_trusts_only_the_tls_layer_not_a_client_header` fails. That is the scenario in lesson 01 section 12.
5. Add a `/oauth/token` check that the requested `scope` is one the client is allowed (for example only `orders:read`). Chapter 11 builds scope matrices.

## Run the real tool (hedged)

See [real-tools/auth-testing-tools.md](../../real-tools/auth-testing-tools.md): curl `-u` for Basic, `-H "X-API-Key: ..."`, a client-credentials token request with `jq -r .access_token`, and `curl --cert client.pem --key client.key` for real mTLS against your course lab.

## What you learned

- Each auth type puts different proof on the wire, and each has a signature mistake.
- API keys belong in headers; tokens must not be cached; mTLS identity comes from the handshake, not from a header.
