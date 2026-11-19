# Lab: Request throttling and rate limiting at different stages

**Course items:** "Rate-Limiting Implementation and Best Practices at Different Stages", "Reverse Proxy", "Load Balancer", "API Gateways and WAFs", "Request Throttling". Lesson: [02 rate limiting at every stage](../../02-rate-limiting-at-every-stage.md). Gateway lab with Kong-style plugins: [chapter 14](../../../14-api-defenses-data-security-and-headers/labs/api-gateway-rate-limiting/README.md).

**Time:** 50 minutes. **Tests:** 10, all offline. **Safety:** pure functions with an explicit clock; no traffic is generated. Only test systems you own or have written permission to test.

## Goal

1. Compare four algorithms on the same attack: a **burst at the window boundary**.
2. See the difference between **rate limiting** (reject) and **throttling** (delay, then reject).
3. Send four attack patterns through a **layered edge** (reverse proxy → load balancer → API gateway + WAF → application) and see which stage stops each one.

## Concept

[throttle.py](throttle.py):

| Class | Idea | Weakness |
|---|---|---|
| `FixedWindow` | Counter per minute | Up to 2x the limit across a window boundary |
| `SlidingWindowLog` | Timestamp per request | Exact, but memory per request |
| `SlidingWindowCounter` | Weighted previous + current window | Approximate (slightly over) |
| `TokenBucket` | Refill at a rate, burst up to capacity | Needs tuning of two numbers |
| `Throttler` | Space requests `1/rate` apart; reject when the wait exceeds `max_wait` | Holds connections while waiting |
| `LayeredEdge` | Per-IP at the proxy, pool capacity at the LB, WAF signature + per-key quota at the gateway, per-account at the app | Each layer sees only its own identity |

## Run

```text
.venv/Scripts/python appsec-course/15-implementing-api-security-mechanisms/labs/request-throttling/demo.py
.venv/Scripts/python -m pytest appsec-course/15-implementing-api-security-mechanisms/labs/request-throttling -v
```

## Expected output (real run)

```text
1. Boundary burst: limit 10 per 60 s; attacker sends 10 at t=59.0-59.9 and 10 at t=60.0-60.9
   FixedWindow           accepted 20 of 20 in under 2 seconds
   SlidingWindowLog      accepted 10 of 20 in under 2 seconds
   SlidingWindowCounter  accepted 11 of 20 in under 2 seconds
   TokenBucket           accepted 10 of 20 in under 2 seconds

2. 429 with Retry-After
   request 1: (200, {'RateLimit-Limit': '3'})
   request 2: (200, {'RateLimit-Limit': '3'})
   request 3: (200, {'RateLimit-Limit': '3'})
   request 4: (429, {'Retry-After': '57', 'RateLimit-Limit': '3', 'RateLimit-Remaining': '0'})

3. Throttling: 2 req/s, max wait 2 s, 8 requests arrive at once
   [(200, 0.0), (200, 0.5), (200, 1.0), (200, 1.5), (200, 2.0), (429, 2.5), (429, 2.5), (429, 2.5)]

4. Limits at different stages
   single-IP flood (100 req in 10 s): {'ok': 22, 'api-gateway: per-key quota': 8, 'reverse-proxy: per-IP limit': 70}
   SQLi probe: {'waf: injection signature': 1}
   password spray on one account from 40 IPs, 1/s: {'ok': 5, 'application: per-account login attempts': 35}
   botnet: 1000 IPs at the same instant: {'ok': 200, 'load-balancer: pool capacity': 800}
```

## Steps

1. Explain the "20 of 20" for `FixedWindow`. Which systems use fixed windows by default? (Many simple gateway plugins; check yours.)
2. Read the layered results. The single-IP flood dies at the reverse proxy; the password spray from 40 IPs passes the proxy and gateway and is caught only by the **per-account** limit in the application; the botnet is shed by the load balancer's capacity limit (503, availability, not security).
3. Change `app_per_account` to `SlidingWindowLog(50, 900)`. How many spray attempts succeed now?
4. Add a stage for **per-user** limits on an expensive `/export` endpoint.
5. Discuss: where do you get the real client IP behind a CDN and a load balancer? (`X-Forwarded-For` is spoofable unless you only trust the hop added by your own proxy.)

## What you learned

- Different stages know different identities: IP (proxy), total capacity (LB), API key and signatures (gateway/WAF), user and account (app). Defense in depth needs several.
- Sliding windows or token buckets avoid the boundary burst.
- Throttling smooths load for good clients; rejection with 429 + `Retry-After` protects the service.

## Run the real tool (hedged)

- **NGINX** reverse proxy: `limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;` and `limit_req zone=api burst=20 nodelay;` (`delay=` gives throttling); `limit_conn` for connections.
- **HAProxy** load balancer: `stick-table type ip size 1m expire 60s store http_req_rate(10s)` with `http-request deny deny_status 429 if { sc_http_req_rate(0) gt 100 }`.
- **Gateways/WAF:** Kong `rate-limiting`, APISIX `limit-req`/`limit-count`, Envoy local and global rate limit, AWS WAF rate-based rules, Cloudflare rate limiting rules. Verify syntax in each project's docs.
