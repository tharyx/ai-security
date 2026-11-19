# Chapter 13: OWASP API Top 10 and Other API Threats

This chapter teaches the OWASP API Security Top 10 in both editions the syllabus uses (2019 and 2023), with a tested mapping between them and one runnable mini-demo per 2023 item. It then covers threats outside the list: attacks on caching layers, GraphQL (part 2), SOAP, microservice trust, post-exploitation in the API world, privilege escalation through XSS, and CORS misconfigurations. Seven offline labs let you attack and fix each one.

> **Safety.** Every lab is a simulation: in-process APIs, a dict-based cache, a simulated browser with a toy script language, a FAKE file system for XXE, and computed (never performed) entity expansion. Secrets are random values labelled FAKE. Only test systems you own or have written permission to test.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Tool status and version numbers are hedged: **verify at the source**.

## Syllabus coverage

| Syllabus item | Where to study | Lab |
|---|---|---|
| [CASP 6] Introduction to OWASP API Top 10 | [01 section 1](01-owasp-api-top-10-2019-and-2023.md#1-introduction-to-owasp-api-top-10) | [api-top10-2023-demos](labs/api-top10-2023-demos/README.md) |
| [CASP 6] Broken Object Level Authorization | [01 section 2.1](01-owasp-api-top-10-2019-and-2023.md#21-broken-object-level-authorization); [ch11](../11-api-authorization-and-oauth/02-authorization-attacks-and-defenses.md#3-broken-object-level-authorization-bola) | [api-top10-2023-demos](labs/api-top10-2023-demos/README.md) (API1); [ch11 bola-user-location](../11-api-authorization-and-oauth/labs/bola-user-location/README.md) |
| [CASP 6] Broken Authentication | [01 section 2.2](01-owasp-api-top-10-2019-and-2023.md#22-broken-authentication); [ch10](../10-api-authentication/README.md) | [api-top10-2023-demos](labs/api-top10-2023-demos/README.md) (API2) |
| [CASP 6] Excessive Data Exposure | [01 section 2.3](01-owasp-api-top-10-2019-and-2023.md#23-excessive-data-exposure) (2019; now API3 BOPLA) | [api-top10-2023-demos](labs/api-top10-2023-demos/README.md) (API3 read side) |
| [CASP 6] Lack of Resources and Rate Limiting | [01 section 2.4](01-owasp-api-top-10-2019-and-2023.md#24-lack-of-resources-and-rate-limiting) (2019; now API4) | [api-top10-2023-demos](labs/api-top10-2023-demos/README.md) (API4) |
| [CASP 6] Broken Function Level Authorization | [01 section 2.5](01-owasp-api-top-10-2019-and-2023.md#25-broken-function-level-authorization); [ch11](../11-api-authorization-and-oauth/02-authorization-attacks-and-defenses.md#4-broken-function-level-authorization-bfla) | [api-top10-2023-demos](labs/api-top10-2023-demos/README.md) (API5) |
| [CASP 6] Mass Assignment | [01 section 2.6](01-owasp-api-top-10-2019-and-2023.md#26-mass-assignment) (2019; now API3 BOPLA) | [api-top10-2023-demos](labs/api-top10-2023-demos/README.md) (API3 write side); [ch12 mass-assignment](../12-input-validation-and-injection/labs/mass-assignment/README.md) |
| [CASP 6] Security Misconfigurations | [01 section 2.7](01-owasp-api-top-10-2019-and-2023.md#27-security-misconfigurations) | [api-top10-2023-demos](labs/api-top10-2023-demos/README.md) (API8), [cors-misconfiguration](labs/cors-misconfiguration/README.md) |
| [CASP 6] Injection | [01 section 2.8](01-owasp-api-top-10-2019-and-2023.md#28-injection) (2019; dropped in 2023); [ch12](../12-input-validation-and-injection/README.md) | [ch12 injection-playground](../12-input-validation-and-injection/labs/injection-playground/README.md); API10 demo in [api-top10-2023-demos](labs/api-top10-2023-demos/README.md) |
| [CASP 6] Improper Asset Management | [01 section 2.9](01-owasp-api-top-10-2019-and-2023.md#29-improper-asset-management) (2019; now API9) | [api-top10-2023-demos](labs/api-top10-2023-demos/README.md) (API9) |
| [CASP 6] Insufficient Logging and Monitoring | [01 section 2.10](01-owasp-api-top-10-2019-and-2023.md#210-insufficient-logging-and-monitoring) (2019; dropped in 2023); logging labs in [ch15](../15-implementing-api-security-mechanisms/README.md) | [ch12 reverse-shell-detector](../12-input-validation-and-injection/labs/reverse-shell-detector/README.md) (detection from logs) |
| [CASP 6] Broken Object Property Level Authorization | [01 section 3.1](01-owasp-api-top-10-2019-and-2023.md#31-broken-object-property-level-authorization) | [api-top10-2023-demos](labs/api-top10-2023-demos/README.md) (API3) |
| [CASP 6] Unrestricted Resource Consumption | [01 section 3.2](01-owasp-api-top-10-2019-and-2023.md#32-unrestricted-resource-consumption) | [api-top10-2023-demos](labs/api-top10-2023-demos/README.md) (API4); [ch12 graphql-attacks](../12-input-validation-and-injection/labs/graphql-attacks/README.md) |
| [CASP 6] Unrestricted Access to Sensitive Business Flows | [01 section 3.3](01-owasp-api-top-10-2019-and-2023.md#33-unrestricted-access-to-sensitive-business-flows) | [api-top10-2023-demos](labs/api-top10-2023-demos/README.md) (API6); [ch12 free-coupons](../12-input-validation-and-injection/labs/free-coupons/README.md) |
| [CASP 6] Server Side Request Forgery | [01 section 3.4](01-owasp-api-top-10-2019-and-2023.md#34-server-side-request-forgery); [ch12](../12-input-validation-and-injection/02-injection-vulnerabilities.md#6-server-side-request-forgery) | [api-top10-2023-demos](labs/api-top10-2023-demos/README.md) (API7); [ch12 injection-playground](../12-input-validation-and-injection/labs/injection-playground/README.md) |
| [CASP 6] Improper Inventory Management | [01 section 3.5](01-owasp-api-top-10-2019-and-2023.md#35-improper-inventory-management) | [api-top10-2023-demos](labs/api-top10-2023-demos/README.md) (API9 drift diff) |
| [CASP 6] Unsafe Consumption of APIs | [01 section 3.6](01-owasp-api-top-10-2019-and-2023.md#36-unsafe-consumption-of-apis) | [api-top10-2023-demos](labs/api-top10-2023-demos/README.md) (API10) |
| [CASP 6] Attacking Caching Layers (Memcache, Proxies, etc.) | [02 section 1](02-caching-graphql-soap-and-microservices.md#1-attacking-caching-layers-memcache-proxies-etc) (SVG) | [cache-poisoning-deception](labs/cache-poisoning-deception/README.md) |
| [CASP 6] Attacking GraphQL APIs | [02 section 2](02-caching-graphql-soap-and-microservices.md#2-attacking-graphql-apis-part-2); part 1 in [ch12 lesson 05](../12-input-validation-and-injection/05-post-exploitation-and-graphql.md#2-attacking-graphql-apis) | [graphql-suggestions-and-persisted-queries](labs/graphql-suggestions-and-persisted-queries/README.md); [ch12 graphql-attacks](../12-input-validation-and-injection/labs/graphql-attacks/README.md) |
| [CASP 6] Attacking SOAP APIs | [02 section 3](02-caching-graphql-soap-and-microservices.md#3-attacking-soap-apis) | [soap-xxe-and-safe-parsing](labs/soap-xxe-and-safe-parsing/README.md) |
| [CASP 6] Abusing Microservices and REST APIs | [02 section 4](02-caching-graphql-soap-and-microservices.md#4-abusing-microservices-and-rest-apis) | [microservices-header-trust](labs/microservices-header-trust/README.md) |
| [CASP 6] Post Exploitation in the API World | [03 section 1](03-post-exploitation-xss-and-cors.md#1-post-exploitation-in-the-api-world) | [ch12 reverse-shell-detector](../12-input-validation-and-injection/labs/reverse-shell-detector/README.md), [microservices-header-trust](labs/microservices-header-trust/README.md) |
| [CASP 6] Privilege Escalation With Cross Site Scripting | [03 section 2](03-post-exploitation-xss-and-cors.md#2-privilege-escalation-with-cross-site-scripting) | [xss-privilege-escalation](labs/xss-privilege-escalation/README.md) |
| [CASP 6] Abusing CORS Misconfigurations | [03 section 3](03-post-exploitation-xss-and-cors.md#3-abusing-cors-misconfigurations) | [cors-misconfiguration](labs/cors-misconfiguration/README.md) |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| The 2019 items (Excessive Data Exposure, Lack of Resources and Rate Limiting, Mass Assignment, Injection, Improper Asset Management, Insufficient Logging and Monitoring) | **OWASP API Security Top 10 2023 is the current edition** (no newer edition known). Excessive Data Exposure + Mass Assignment → **API3 BOPLA**; Lack of Resources → **API4 Unrestricted Resource Consumption**; Security Misconfiguration moves to **API8**; Improper Asset Management → **API9 Improper Inventory Management**; Injection and Insufficient Logging are no longer separate API items. |
| Injection / logging as API risks | Still real: covered by the web **OWASP Top 10:2025** (A05 Injection, A09 Security Logging and Alerting Failures). |
| SSRF as a web-only item | **API7:2023** in the API list; in the web Top 10:2025 SSRF is folded into **A01 Broken Access Control**. |
| Memcached attacks | Still relevant; Redis exposure is now at least as common. Both need private binding, auth/ACLs and TLS. |
| XML parser behaviour | Python's ElementTree does not resolve external entities; current expat limits entity amplification; `defusedxml` rejects DTDs (check Python's "XML vulnerabilities" page for your version). |

## How the three courses overlap here

- **CASP 6** owns this chapter. **CASP 4** (chapter 11) teaches BOLA/BFLA in depth and **CASP 5** (chapter 12) teaches injection, SSRF, mass assignment and GraphQL part 1; this chapter links to those labs instead of repeating them.
- The Security Champion course's **OWASP Top 10 (web) basics**, including XXE and CSRF, are in [chapter 01](../01-security-champions-and-appsec-basics/README.md), with the 2021 → 2025 web mapping.
- The OWASP API Top 10 is a ready-made **threat library** for API threat models ([chapter 04](../04-threat-modeling-methods-and-rating/README.md)).

## Learning order

1. [Lesson 01](01-owasp-api-top-10-2019-and-2023.md), then the [api-top10-2023-demos lab](labs/api-top10-2023-demos/README.md). About 3 hours.
2. [Lesson 02](02-caching-graphql-soap-and-microservices.md), then [cache-poisoning-deception](labs/cache-poisoning-deception/README.md), [graphql-suggestions-and-persisted-queries](labs/graphql-suggestions-and-persisted-queries/README.md), [soap-xxe-and-safe-parsing](labs/soap-xxe-and-safe-parsing/README.md) and [microservices-header-trust](labs/microservices-header-trust/README.md). About 4 hours.
3. [Lesson 03](03-post-exploitation-xss-and-cors.md), then [xss-privilege-escalation](labs/xss-privilege-escalation/README.md) and [cors-misconfiguration](labs/cors-misconfiguration/README.md). About 2 hours.
4. Optional: [real-tools/api-threat-testing-tools.md](real-tools/api-threat-testing-tools.md) against crAPI or the course lab. About 2 hours.

## Lab index

All labs run offline: `.venv/Scripts/python -m pytest appsec-course/13-owasp-api-top-10-and-other-threats -q -p no:cacheprovider`.

| Lab | Course exercise | Tests |
|---|---|---|
| [api-top10-2023-demos](labs/api-top10-2023-demos/README.md) | OWASP API Top 10 2019/2023, one demo per 2023 item | 15 |
| [cache-poisoning-deception](labs/cache-poisoning-deception/README.md) | Attacking Caching Layers (Memcache, Proxies, etc.) | 7 |
| [graphql-suggestions-and-persisted-queries](labs/graphql-suggestions-and-persisted-queries/README.md) | Attacking GraphQL APIs (part 2) | 6 |
| [soap-xxe-and-safe-parsing](labs/soap-xxe-and-safe-parsing/README.md) | Attacking SOAP APIs | 8 |
| [microservices-header-trust](labs/microservices-header-trust/README.md) | Abusing Microservices and REST APIs | 6 |
| [xss-privilege-escalation](labs/xss-privilege-escalation/README.md) | Privilege Escalation With Cross Site Scripting | 7 |
| [cors-misconfiguration](labs/cors-misconfiguration/README.md) | Abusing CORS Misconfigurations | 11 |

Hedged guide for real tools: [api-threat-testing-tools.md](real-tools/api-threat-testing-tools.md).

## Exam tips

- **Know both lists and the mapping.** Say "2023 is current" and name the three new items: API6 business flows, API7 SSRF, API10 unsafe consumption.
- **BOPLA = Excessive Data Exposure + Mass Assignment.** Property-level authorization, read and write.
- **API4 is about cost and capacity,** not only request rate (SMS, email, AI calls, storage).
- **API6 is abuse of a legitimate flow at scale;** each request is valid.
- **Inventory: you cannot protect what you do not know.** Old versions, shadow and zombie APIs, undocumented data flows.
- **Treat third-party API data as untrusted input** (API10).
- **Cache poisoning = unkeyed input; cache deception = static-looking path + ignored Cache-Control.**
- **SOAP: disable DTDs, authorize on the Body, verify what you use.**
- **Internal is not trusted:** strip identity headers at the edge, sign internal identity, mTLS.
- **HttpOnly stops cookie theft, not same-origin actions by XSS.**
- **CORS: exact allowlist, never reflect with credentials, CORS is not CSRF protection.**

## Interview / exam questions

<details>
<summary>1. What changed between the OWASP API Security Top 10 2019 and 2023?</summary>

Excessive Data Exposure and Mass Assignment merged into API3 Broken Object Property Level Authorization; Lack of Resources became API4 Unrestricted Resource Consumption; Security Misconfiguration moved to API8; Improper Assets Management became API9 Improper Inventory Management; Injection and Insufficient Logging were dropped as separate items; new items are API6 Unrestricted Access to Sensitive Business Flows, API7 SSRF and API10 Unsafe Consumption of APIs.
</details>

<details>
<summary>2. Explain BOPLA with a read and a write example.</summary>

Read: GET /users/7 returns password_hash or internal flags the caller should not see (excessive data exposure). Write: PATCH /users/7 accepts is_admin or balance from the client (mass assignment). Fix with per-role response and request schemas and rejection of unknown fields.
</details>

<details>
<summary>3. How is API4 Unrestricted Resource Consumption different from API6 Sensitive Business Flows?</summary>

API4 is about consuming resources without limits (CPU, memory, bandwidth, paid third-party calls), often causing DoS or cost. API6 is about automating a legitimate business flow at scale (buying all stock, mass sign-ups, booking every seat) where each request is valid but the overall use harms the business.
</details>

<details>
<summary>4. What is Improper Inventory Management and how do you address it?</summary>

Unknown or forgotten APIs: old versions, beta and staging hosts, shadow APIs outside the gateway, undocumented data flows to partners. Address with an inventory from gateways, code and traffic, OpenAPI specs as the source of truth, version retirement, and automated drift detection between deployed and documented endpoints.
</details>

<details>
<summary>5. What is Unsafe Consumption of APIs? Give a defence.</summary>

Trusting data or behaviour from third-party APIs more than user input: using their data in queries, following their redirects, accepting unbounded responses. Validate and sanitize third-party responses, use TLS, do not follow redirects blindly, set timeouts and size limits, and keep an allowlist of integrations.
</details>

<details>
<summary>6. Why were Injection and Insufficient Logging dropped from the 2023 API list?</summary>

They are well covered by the general OWASP Top 10 and the API list focuses on API-specific risks. They remain real risks: Injection is A05 and logging/alerting failures A09 in the web Top 10:2025.
</details>

<details>
<summary>7. Explain web cache poisoning and its fix.</summary>

The response depends on an input the cache does not include in its key (for example X-Forwarded-Host). An attacker sends one request with a malicious value, the response is cached and served to everyone. Fix: do not use unkeyed inputs in responses, strip forwarding headers at the edge, add varying inputs to the key or Vary, and limit what is cached.
</details>

<details>
<summary>8. Explain web cache deception.</summary>

The attacker lures a victim to /account/x.css. The origin ignores the extra path and returns the private page; the cache stores it as static because of the extension. The attacker then fetches it from the cache. Fix: respect Cache-Control private/no-store, cache by explicit rules not extensions, and return 404 for unknown paths.
</details>

<details>
<summary>9. Why is an exposed Memcached server dangerous?</summary>

No authentication by default, so anyone can read cached sessions, tokens and PII or poison entries; UDP enabled huge DDoS amplification in 2018. Bind privately, firewall, disable UDP, enable SASL and TLS where supported.
</details>

<details>
<summary>10. Name four SOAP-specific attacks and their defences.</summary>

XXE (disable external entities and DTDs), XML bombs (disable DTDs, parser limits), SOAPAction spoofing (authorize and route on the Body operation), XML Signature Wrapping (process exactly the verified element, strict schema), WSDL exposure (do not publish in production, authorize every operation).
</details>

<details>
<summary>11. How can field suggestions defeat disabled introspection in GraphQL?</summary>

Servers answer unknown fields with "Did you mean X?". Tools like Clairvoyance send near-miss names and rebuild the schema from hints. Disable suggestions in production and use persisted queries plus per-resolver authorization.
</details>

<details>
<summary>12. What is wrong with services trusting an X-User-Id header?</summary>

Any caller who can reach the service, or who can get the header through the gateway, can impersonate any user. The gateway must strip client identity headers and pass a signed, audience-bound, short-lived token (or use mTLS workload identity), and each service must verify it.
</details>

<details>
<summary>13. Why is X-Forwarded-For unsafe for access control?</summary>

The client controls the left-most values. If used at all, take the right-most address appended by a known number of trusted proxies; better, do not authorize by IP.
</details>

<details>
<summary>14. How does stored XSS lead to privilege escalation, and why does HttpOnly not stop it?</summary>

A payload stored by a low-privilege user runs in an admin's browser and calls admin APIs with the admin's cookies attached automatically. HttpOnly only prevents reading the cookie; it does not stop same-origin requests. Fix with output encoding, contain with strict CSP and Trusted Types, and require re-authentication for sensitive admin actions.
</details>

<details>
<summary>15. Describe three CORS misconfigurations and the correct configuration.</summary>

Reflecting any Origin with Access-Control-Allow-Credentials: true; allowing the null origin; suffix or prefix matching that lets evilbank.example or bank.example.evil.net through. Correct: an exact allowlist of origins, credentials only for those, Vary: Origin, and remembering that CORS is not CSRF protection.
</details>

## References

- OWASP API Security Top 10 2019 and 2023 (owasp.org/API-Security); OWASP Top 10:2021 and 2025.
- OWASP cheat sheets: REST Security, GraphQL, XML External Entity Prevention, Web Service Security, HTML5 Security (CORS), XSS Prevention.
- PortSwigger research on web cache poisoning and cache deception; Python documentation "XML vulnerabilities"; W3C Fetch standard (CORS).
- OWASP crAPI, DVGA, vAPI; graphql-cop, Clairvoyance, InQL, SoapUI, SAML Raider, Param Miner, Corsy project pages.
- Repo: [MCP authentication (confused deputy, token passthrough)](../../04-mcp-security/authentication/README.md), [SIEM](../../cybersecurity-track/06-siem-sentinel-splunk/README.md).

**Next chapter:** [Chapter 14: API Defenses: Data Security and Security Headers](../14-api-defenses-data-security-and-headers/README.md)
