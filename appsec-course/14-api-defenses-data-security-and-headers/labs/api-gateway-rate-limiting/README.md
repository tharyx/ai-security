# Lab: Rate limiting and security headers at a Kong-like API gateway

**Course items:** "Implementing Rate Limiting With API Gateway", "Securing HTTP Headers using Kong Gateway", "Implementing Rate Limiting using API Key", "Rate Limiting Best Practices". Lesson: [04 rate limiting and gateways](../../04-rate-limiting-and-api-gateways.md). Real Kong: [real-tools/kong-gateway.md](../../real-tools/kong-gateway.md).

**Time:** 60 minutes. **Tests:** 10, all offline. **Safety:** in-process gateway and upstream; no sockets. API keys are FAKE and generated at runtime. Only test systems you own or have written permission to test.

## Goal

An orders API has a **4-digit PIN login** (brute-forceable) and leaks `Server` and `X-Powered-By` headers. Put a gateway in front of it and prove, with tests, that:

1. a PIN brute force that works directly against the API is stopped by an **IP-based token bucket** at the gateway;
2. `/orders` requires an **API key** (`key-auth`) and each key has its **own** rate limit;
3. **security headers** are added, and leaky headers removed, at the edge (`response-transformer`), even on gateway error responses;
4. CORS is only granted to an exact allowlisted origin.

## Concept

[minigw.py](minigw.py) mirrors Kong's model in about 250 lines: **services**, **routes**, **consumers** with key credentials, and **plugins** that run in priority order (`cors` 2000, `key-auth` 1250, `rate-limiting` 910, `response-transformer` 800, as in Kong; verify). The config file [fixtures/kong-like.json](fixtures/kong-like.json) has the shape of a decK file, in JSON. `${KEY_<consumer>}` placeholders are replaced with FAKE keys at runtime, so no key-shaped string is committed.

| Plugin | Behaviour here |
|---|---|
| `key-auth` | Reads `apikey`, maps it to a consumer, and **overwrites** `X-Consumer-Username` (clients cannot spoof it). 401 when missing or unknown. |
| `rate-limiting` | Token bucket per `consumer`, `ip` or `header`; sends `RateLimit-Limit`/`RateLimit-Remaining`; 429 with `Retry-After` when empty. Kong's bundled plugin uses fixed windows; its advanced plugin offers sliding windows (verify). |
| `response-transformer` | Adds HSTS, CSP, `nosniff`, `no-store`, `X-XSS-Protection: 0`; removes `Server`, `X-Powered-By` |
| `cors` | Exact origin allowlist with credentials |

## Run

```text
.venv/Scripts/python appsec-course/14-api-defenses-data-security-and-headers/labs/api-gateway-rate-limiting/demo.py
.venv/Scripts/python -m pytest appsec-course/14-api-defenses-data-security-and-headers/labs/api-gateway-rate-limiting -v
```

## Expected output (real run)

```text
1. Brute force the 4-digit PIN login
   direct to upstream (no gateway): PIN found (7342) after 13 tries
   through the gateway: statuses [401, 401, 401, 401, 401, 429, 429, 429]... -> 429s stop the attack; Retry-After=13
   upstream saw 5 login calls

2. API key auth and per-key rate limits on /orders
   no key      : 401
   unknown key : 401
   mobile-app x12   : [200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 429, 429]
   partner-acme x1  : 200 (own bucket, unaffected)
   mobile-app after 3s: [200, 200, 200, 429]

3. Security headers added at the edge
   Access-Control-Allow-Credentials: true
   Access-Control-Allow-Origin: https://shop.example
   Cache-Control: no-store
   Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
   Content-Type: application/json
   RateLimit-Limit: 10
   RateLimit-Remaining: 9
   Strict-Transport-Security: max-age=31536000; includeSubDomains
   Vary: Origin
   X-Content-Type-Options: nosniff
   X-XSS-Protection: 0
   upstream sent Server/X-Powered-By; gateway removed them: True
```

## Steps

1. Run the demo. Directly against the upstream, the PIN falls in 13 tries. Through the gateway, the upstream sees only 5 login calls.
2. Change the login bucket to `"capacity": 100`. Does the brute force succeed now? What is the right limit for a 4-digit PIN? (Also lock the account or require a second factor: a rate limit alone allows 10,000 guesses over time.)
3. Send 12 requests with one key and 1 with another. Explain why per-key limits are fairer than one global limit, and why per-IP limits fail behind carrier-grade NAT or against botnets.
4. Call `/orders` with a forged `X-Consumer-Username: mobile-app` header. The gateway overwrites it. Why must the upstream also refuse requests that do not come through the gateway (network policy, mTLS)?
5. Remove `Cache-Control` from the transformer and run the headers analyzer lab against the response.

## What you learned

- A gateway is the right place for **coarse** controls: authentication of API clients, quotas, headers, CORS, request size. Business rules (lockout per account, per-user object checks) still belong in the app.
- Token buckets allow short bursts but cap the average rate. Always return 429 with `Retry-After`.
- API keys identify a **client application**, not a user. Treat them as secrets, rotate them, and never use them as the only auth for user data.

## Run the real tool (hedged)

See [real-tools/kong-gateway.md](../../real-tools/kong-gateway.md) for a Kong in DB-less mode with a decK-style file that has the same plugins. Check Kong's current OSS/Enterprise packaging and licence first. Alternatives with the same concepts: Apache APISIX (`limit-count`, `key-auth`), Envoy Gateway (`BackendTrafficPolicy` rate limits), NGINX (`limit_req`), Tyk, AWS API Gateway usage plans, Azure API Management policies.
