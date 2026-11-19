# Lab: Abusing microservices and REST APIs through implicit internal trust

**Course topic:** "Abusing Microservices and REST APIs". Lesson: [02 section 4](../../02-caching-graphql-soap-and-microservices.md#4-abusing-microservices-and-rest-apis).

**Time:** 45 minutes. **Tests:** 6, all offline. **Safety:** in-process gateway and services; FAKE session tokens; a random mesh key. Only test systems you own or have written permission to test.

## Goal

Exploit three classic microservice trust mistakes (identity headers trusted from anyone, `X-Forwarded-For` trusted for access control, a flat network that lets anyone call internal services) and replace them with a gateway that strips identity headers and mints a short-lived signed internal token.

## Concept

```text
client --(cookie)--> gateway --(X-User-Id: alice)--> orders service     <- vulnerable: header from anyone
client --(cookie)--> gateway --(signed token aud=orders, 30 s)--> orders <- secure: verify, ignore raw headers
```

| Mistake | Attack | Fix |
|---|---|---|
| Services trust `X-User-Id` / `X-Role` | Client adds the header; gateway passes it through | Gateway strips identity headers; services trust only a signed token (JWT, mTLS identity, SPIFFE SVID) |
| Flat network | Attacker (or SSRF) calls the internal service directly | Service authenticates every caller (mTLS / token); NetworkPolicy |
| `X-Forwarded-For` left-most value used for IP allowlists | Client sends `X-Forwarded-For: 10.0.0.1` | Use the right-most address added by a **trusted** proxy; better, do not use IPs as authorization |

## Steps

1. Run the demo.
2. Set `trusted_proxies=2` in the secure `client_ip` but keep one proxy. What does an attacker now control? (The left address again.)
3. Change the internal token audience check to accept any audience. Which test fails, and what attack does that enable? (A token minted for one service replayed to another.)

## Run

```text
.venv/Scripts/python appsec-course/13-owasp-api-top-10-and-other-threats/labs/microservices-header-trust/demo.py
.venv/Scripts/python -m pytest appsec-course/13-owasp-api-top-10-and-other-threats/labs/microservices-header-trust -q -p no:cacheprovider
```

## Expected output (real run)

```text
===== VULNERABLE mesh =====
alice reads her order o-1                     -> (200, {'owner': 'alice', 'total': 120})
alice adds X-User-Id: bob, reads o-2         -> (200, {'owner': 'bob', 'total': 9900})
attacker on flat network calls orders directly -> (200, {'owner': 'bob', 'total': 9900})
alice adds X-Forwarded-For: 10.0.0.1, GET /admin -> (200, 'admin console')

===== SECURE mesh =====
alice reads her order o-1                     -> (200, {'owner': 'alice', 'total': 120})
alice adds X-User-Id: bob, reads o-2         -> (404, 'not found')
attacker on flat network calls orders directly -> (401, 'unauthenticated')
alice adds X-Forwarded-For: 10.0.0.1, GET /admin -> (403, 'forbidden')
```

## Run the real tool (hedged)

In the course lab, add `X-User-Id`, `X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL` and `X-Forwarded-Host` headers with Burp (the **Param Miner** extension guesses more). In real meshes, **Istio**/**Linkerd** provide mTLS between services and **SPIFFE/SPIRE** issues workload identities; check that `PeerAuthentication` is `STRICT`.

## What you learned

- "Internal" is not a trust boundary; every service authenticates its caller.
- Identity travels as a signed, audience-bound, short-lived token, never as a plain header.
