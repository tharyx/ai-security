# Chapter 08: API Fundamentals and Architecture

This chapter opens the API security half of the course. It explains what an API is and why APIs need their own security thinking, takes HTTP apart field by field, walks through API protocols, data formats and deployment architectures (simple and complex), and then maps the eight core API defenses, API threat modeling and API-specific VAPT. It ends with the command-line skills the course labs assume: commands, outputs, exit codes and hosting files over HTTP.

> **Safety.** Every lab is a simulation: in-memory HTTP parsing, a simulated command runner that never launches a shell, a model of a fictional deployment, and a file server bound to 127.0.0.1 only. Fake tokens are built at runtime and labelled FAKE. Only test systems you own or have written permission to test.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Tool status and version numbers are hedged: **verify at the source**.

## Syllabus coverage

| Syllabus item | Where to study | Lab |
|---|---|---|
| [CASP 1] Introduction to Application Programming Interface | [01 section 1](01-what-is-an-api-and-why-secure-it.md#1-introduction-to-application-programming-interfaces) | n/a (concept) |
| [CASP 1] What is an API? | [01 section 2](01-what-is-an-api-and-why-secure-it.md#2-what-is-an-api) | [toy-api-crud (ch09)](../09-api-tooling-and-reconnaissance/labs/toy-api-crud/README.md) |
| [CASP 1] Need for an API | [01 section 3](01-what-is-an-api-and-why-secure-it.md#3-need-for-an-api) | n/a |
| [CASP 1] Why Should You Secure Your APIs? | [01 section 4](01-what-is-an-api-and-why-secure-it.md#4-why-should-you-secure-your-apis) and scenario | n/a |
| [CASP 1] APIs vs. Web Applications | [01 section 5](01-what-is-an-api-and-why-secure-it.md#5-apis-vs-web-applications) | n/a |
| [CASP 1] Understanding API Architecture | [02 section 1](02-http-protocol-for-apis.md#1-understanding-api-architecture) | [http-anatomy](labs/http-anatomy/README.md) |
| [CASP 1] Overview of the HTTP protocol | [02 section 2](02-http-protocol-for-apis.md#2-overview-of-the-http-protocol); repo [HTTP and TLS](../../cybersecurity-track/02-networking/04-dns-dhcp-http-tls.md) | [http-anatomy](labs/http-anatomy/README.md) |
| [CASP 1] Anatomy of a HTTP Request | [02 section 3](02-http-protocol-for-apis.md#3-anatomy-of-a-http-request) (SVG) | [http-anatomy](labs/http-anatomy/README.md) |
| [CASP 1] Anatomy of a HTTP Response | [02 section 4](02-http-protocol-for-apis.md#4-anatomy-of-a-http-response) | [http-anatomy](labs/http-anatomy/README.md) |
| [CASP 1] HTTP Response Codes and Its Significance | [02 section 5](02-http-protocol-for-apis.md#5-http-response-codes-and-their-significance) | [http-anatomy](labs/http-anatomy/README.md) |
| [CASP 1] Stateless and Stateful Requests | [02 section 6](02-http-protocol-for-apis.md#6-stateless-and-stateful-requests) | [http-anatomy](labs/http-anatomy/README.md) |
| [CASP 1] Overview of API architecture | [03 section 1](03-api-architecture-protocols-and-deployment.md#1-overview-of-api-architecture) | [api-threat-model](labs/api-threat-model/README.md) |
| [CASP 1] API Protocols | [03 section 2](03-api-architecture-protocols-and-deployment.md#2-api-protocols) (REST, GraphQL, gRPC, SOAP, WebSockets, webhooks, async) | n/a |
| [CASP 1] API Data formats | [03 section 3](03-api-architecture-protocols-and-deployment.md#3-api-data-formats) (JSON, XML, protobuf, YAML) | n/a |
| [CASP 1] Different Types of API | [03 section 4](03-api-architecture-protocols-and-deployment.md#4-different-types-of-api) | n/a |
| [CASP 1] Simple Architecture | [03 section 5](03-api-architecture-protocols-and-deployment.md#5-simple-architecture) (SVG) | [api-threat-model](labs/api-threat-model/README.md) (`simple_deployment`) |
| [CASP 1] How Are APIs Typically Deployed? | [03 section 6](03-api-architecture-protocols-and-deployment.md#6-how-are-apis-typically-deployed) | n/a |
| [CASP 1] Complex Architecture | [03 section 7](03-api-architecture-protocols-and-deployment.md#7-complex-architecture) (SVG) | [api-threat-model](labs/api-threat-model/README.md) (`hardened_deployment`) |
| [CASP 1] Strategies To Secure APIs | [04 section 1](04-securing-apis-strategies-threat-modeling-and-defenses.md#1-strategies-to-secure-apis) | n/a |
| [CASP 1] Threat Modeling of APIs | [04 section 2](04-securing-apis-strategies-threat-modeling-and-defenses.md#2-threat-modeling-of-apis); method depth in [chapter 04](../04-threat-modeling-methods-and-rating/README.md) | [api-threat-model](labs/api-threat-model/README.md) |
| [CASP 1] Traditional VAPT vs API VAPT | [04 section 4](04-securing-apis-strategies-threat-modeling-and-defenses.md#4-traditional-vapt-vs-api-vapt); repo [OpenAPI scan lab](../../devsecops-course/06-dynamic-analysis/labs/openapi-zap-api-scan/README.md) | n/a |
| [CASP 1] API Defenses | [04 section 3](04-securing-apis-strategies-threat-modeling-and-defenses.md#3-api-defenses) | [api-threat-model](labs/api-threat-model/README.md) (gate on missing defenses) |
| [CASP 1] Input Validation | [04 input validation](04-securing-apis-strategies-threat-modeling-and-defenses.md#input-validation); depth in [chapter 12](../12-input-validation-and-injection/README.md) | [api-threat-model](labs/api-threat-model/README.md) |
| [CASP 1] Identification | [04 identification](04-securing-apis-strategies-threat-modeling-and-defenses.md#identification) | [api-threat-model](labs/api-threat-model/README.md) |
| [CASP 1] Authentication | [04 authentication](04-securing-apis-strategies-threat-modeling-and-defenses.md#authentication); depth in [chapter 10](../10-api-authentication/README.md) | [api-threat-model](labs/api-threat-model/README.md) |
| [CASP 1] Authorization | [04 authorization](04-securing-apis-strategies-threat-modeling-and-defenses.md#authorization); depth in [chapter 11](../11-api-authorization-and-oauth/README.md) | [api-threat-model](labs/api-threat-model/README.md) |
| [CASP 1] Data Encryption | [04 data encryption](04-securing-apis-strategies-threat-modeling-and-defenses.md#data-encryption); depth in [chapter 14](../14-api-defenses-data-security-and-headers/README.md) | [api-threat-model](labs/api-threat-model/README.md) |
| [CASP 1] Transport Security | [04 transport security](04-securing-apis-strategies-threat-modeling-and-defenses.md#transport-security); repo [TLS testing](../../devsecops-course/06-dynamic-analysis/03-tls-and-server-misconfiguration-testing.md) | [api-threat-model](labs/api-threat-model/README.md) |
| [CASP 1] Error Handling and Logging | [04 error handling and logging](04-securing-apis-strategies-threat-modeling-and-defenses.md#error-handling-and-logging); depth in [chapter 15](../15-implementing-api-security-mechanisms/README.md) | [api-threat-model](labs/api-threat-model/README.md) |
| [CASP 1] Supply Chain Security | [04 supply chain security](04-securing-apis-strategies-threat-modeling-and-defenses.md#supply-chain-security); repo [SCA](../../devsecops-course/04-software-component-analysis/README.md) | [api-threat-model](labs/api-threat-model/README.md) |
| [CASP 1] Understanding The Lab Setup | [05 section 1](05-lab-setup-and-command-line-basics.md#1-understanding-the-lab-setup) | all labs run with `pytest` |
| [CASP 1] Working With Linux Command(s) | [05 section 2](05-lab-setup-and-command-line-basics.md#2-working-with-linux-commands) (bash + PowerShell); repo [Linux for analysts](../../cybersecurity-track/01-it-fundamentals/03-linux-for-security-analysts.md) | [command-and-http-hosting](labs/command-and-http-hosting/README.md) |
| [CASP 1] Working With Command Outputs | [05 section 3](05-lab-setup-and-command-line-basics.md#3-working-with-command-outputs) | [command-and-http-hosting](labs/command-and-http-hosting/README.md) |
| [CASP 1] Working With Exit Code | [05 section 4](05-lab-setup-and-command-line-basics.md#4-working-with-exit-codes) | [command-and-http-hosting](labs/command-and-http-hosting/README.md) |
| [CASP 1] Hosting Files Using HTTP Server | [05 section 5](05-lab-setup-and-command-line-basics.md#5-hosting-files-using-an-http-server) | [command-and-http-hosting](labs/command-and-http-hosting/README.md) (real `http.server` on 127.0.0.1) |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| "OpenAPI (Swagger)" as one thing | **Swagger 2.0 = OpenAPI 2**. OpenAPI **3.1** is widely used and **3.2.0 was published in Sept 2025**. "Swagger" today mostly names the SmartBear tools (Swagger UI, Editor). |
| API protocols listed as REST, SOAP (and maybe GraphQL) | Also expect **gRPC** (HTTP/2 + protobuf), **WebSockets**, **webhooks** and event-driven APIs described with **AsyncAPI**. |
| OWASP API Top 10 (the course mixes 2019 and 2023 names) | The **2023** edition is current. Chapter 13 has the full 2019 → 2023 mapping. |
| "HTTP protocol" meaning HTTP/1.1 | HTTP/2 is the norm for APIs behind modern proxies and gRPC; **HTTP/3** (QUIC) is common at CDNs. Methods, headers and status codes keep the same meaning. |
| Python `SimpleHTTPServer` (Python 2 era tutorials) | Python 3 uses `python3 -m http.server`; pass `--bind 127.0.0.1`. Not for production. |

## How the three courses overlap here

- **CASP 1 only** owns this chapter. Threat modeling *methods* (STRIDE, DFDs, rating) come from the Threat Modeling course in [chapters 03 to 07](../04-threat-modeling-methods-and-rating/README.md); lesson 04 applies them to APIs without re-teaching them.
- The Security Champion course's OWASP Top 10 and HTTP basics are in [chapter 01](../01-security-champions-and-appsec-basics/README.md); this chapter adds the API view.
- The eight API defenses are introduced here and taught in depth in chapters 10 to 15, so each is written once.

## Learning order

1. [Lesson 01](01-what-is-an-api-and-why-secure-it.md): what an API is and why it is different. About 45 minutes.
2. [Lesson 02](02-http-protocol-for-apis.md), then the [http-anatomy lab](labs/http-anatomy/README.md). About 2 hours.
3. [Lesson 03](03-api-architecture-protocols-and-deployment.md): protocols, formats, architectures. About 1.5 hours.
4. [Lesson 04](04-securing-apis-strategies-threat-modeling-and-defenses.md), then the [api-threat-model lab](labs/api-threat-model/README.md). About 2.5 hours.
5. [Lesson 05](05-lab-setup-and-command-line-basics.md), then the [command-and-http-hosting lab](labs/command-and-http-hosting/README.md). About 1.5 hours.

## Lab index

All labs run offline: `.venv/Scripts/python -m pytest appsec-course/08-api-fundamentals-and-architecture -q -p no:cacheprovider`.

| Lab | Course items | Tests |
|---|---|---|
| [http-anatomy](labs/http-anatomy/README.md) | HTTP request/response anatomy, response codes, stateless vs stateful | 8 |
| [api-threat-model](labs/api-threat-model/README.md) | Threat modeling of APIs, API defenses, simple vs complex architecture | 8 |
| [command-and-http-hosting](labs/command-and-http-hosting/README.md) | Linux commands, command outputs, exit codes, hosting files using an HTTP server | 8 |

## Exam tips

- **401 = not authenticated, 403 = authenticated but not allowed.** A 200 where you expected either is the headline finding.
- **Client-side checks protect nothing** in an API. The server enforces every rule.
- **Identification is the claim, authentication the proof, authorization the permission.** Be ready to separate them in one sentence each.
- **API VAPT needs two users per role** and knowledge of who owns which object; scanners alone miss BOLA.
- **Name the protocol and its classic bug:** GraphQL (introspection, depth), SOAP (XXE), gRPC (reflection, hard to proxy), WebSockets (auth only at handshake), webhooks (signature checks, SSRF).
- **Exit code 0 is success.** `|| true` and pipes without `pipefail` silently disable security gates.
- **Bind lab servers to 127.0.0.1.**

## Interview / exam questions

<details>
<summary>1. What is an API, in one sentence, and what four things does its contract define?</summary>

A defined interface that lets one program request operations or data from another. The contract defines the operations (endpoints), how to call them (protocol and format), who may call them (authentication and authorization) and what comes back (responses and errors).
</details>

<details>
<summary>2. How does securing an API differ from securing a server-rendered web application?</summary>

APIs return raw data to programs, so any field returned is exposed even if no screen shows it; they are easy to automate (enumeration, scraping); they are numerous and versioned (shadow and zombie endpoints); and their typical bugs are authorization (BOLA, BFLA, property-level), authentication and resource consumption rather than XSS and CSRF.
</details>

<details>
<summary>3. Describe the parts of an HTTP request and what a tester checks in each.</summary>

Request line (method, target, version): other methods, changeable IDs, hidden parameters. Headers: authentication scheme, Content-Type (XML accepted?), Host (used to build links?), custom identity headers that might be trusted. Blank line. Body: extra fields (mass assignment), types and sizes.
</details>

<details>
<summary>4. Why do 401, 403 and 404 matter to an attacker doing discovery?</summary>

Different codes for "does not exist" (404) and "exists but protected" (401/403) reveal which paths and objects exist. Some APIs return 404 for objects the caller may not see, to stop ID probing.
</details>

<details>
<summary>5. Compare stateless and stateful APIs and name one risk of each.</summary>

Stateless: the client sends credentials (a token) on every call and the server stores nothing; risk: stolen long-lived tokens are hard to revoke. Stateful: the server keeps a session and the client sends a cookie; risks: CSRF (cookies are sent automatically) and sessions not invalidated on logout.
</details>

<details>
<summary>6. Which HTTP methods are safe and which are idempotent, and why does it matter?</summary>

GET, HEAD, OPTIONS are safe (no state change) and idempotent; PUT and DELETE are idempotent but not safe; POST is neither; PATCH is not guaranteed idempotent. A state-changing GET can be triggered by links, crawlers or image tags, and retries of non-idempotent calls can duplicate actions (double payments) without idempotency keys.
</details>

<details>
<summary>7. Name five API styles and a security concern for each.</summary>

REST (BOLA, mass assignment), GraphQL (introspection, deep/batched queries, resolver authorization), gRPC (reflection exposes schema, needs per-call auth or mTLS), SOAP (XXE, XML bombs, signature wrapping), WebSockets (auth only at handshake, Origin check), webhooks (verify HMAC signature and timestamp, SSRF on user-supplied URLs).
</details>

<details>
<summary>8. What extra risks does a microservice architecture add compared with a monolith?</summary>

East-west traffic between services, more trust boundaries, identity lost or passed as spoofable headers after the gateway, inconsistent authorization across teams, inventory drift, async paths (queues) that skip checks, and harder tracing. Defenses: authenticate every hop (mTLS, workload identity), pass signed tokens, shared policy, inventory, tracing.
</details>

<details>
<summary>9. Does an API gateway remove the need for authorization in services? Why?</summary>

No. A gateway can check the token and coarse permissions, but only the service knows whether the caller owns object 42 or may change a given field. Also services can be reached by other paths. Object- and property-level authorization belongs in the service.
</details>

<details>
<summary>10. How would you threat model a new API endpoint in 20 minutes?</summary>

Draw the flow and trust boundaries; run STRIDE per element; ask who may call it, which object it touches and how ownership is checked, which fields are writable, the maximum cost of one call, what is logged, and which third parties it trusts. Record each threat with a decision and a test.
</details>

<details>
<summary>11. Separate identification, authentication and authorization.</summary>

Identification: the caller states who it is (user id, client id, key id). Authentication: it proves that claim (password + MFA, signed token, client certificate). Authorization: the system decides what that proven identity may do (function, object and property level).
</details>

<details>
<summary>12. What belongs in API error handling and logging?</summary>

Generic error responses with a correlation id and no stack traces or SQL errors; detailed server-side logs of security events (logins, failures, authorization denials, admin actions) with who, what, when, where; no secrets, tokens or unnecessary personal data in logs; protection against log injection; alerting on abuse patterns.
</details>

<details>
<summary>13. Contrast traditional VAPT with API VAPT.</summary>

API VAPT discovers from specs, JS bundles and path guessing instead of crawling; tests multiple users and roles to find BOLA/BFLA; checks mass assignment, rate limits, business flows and token validation; and needs test data about object ownership. Generic scanners do well on classic web bugs but miss most API authorization flaws.
</details>

<details>
<summary>14. What does exit code 127 mean, and why are exit codes important for security pipelines?</summary>

127 means "command not found". CI gates rely on tools exiting non-zero when they find problems; masking exit codes (`|| true`, pipes without `pipefail`, `curl` without `-f`) makes security gates silently pass.
</details>

<details>
<summary>15. What precautions do you take when hosting files with `python -m http.server` during a lab?</summary>

Bind to 127.0.0.1 (the default listens on all interfaces), serve a dedicated empty folder, never your home directory, stop it when finished, and never use it in production (no TLS, no authentication).
</details>

## References

- OWASP API Security Project (Top 10 2023), OWASP REST Security Cheat Sheet, OWASP ASVS 5.0 (verify current version).
- RFC 9110 (HTTP semantics), RFC 9112 (HTTP/1.1), RFC 9113 (HTTP/2), RFC 9114 (HTTP/3).
- OpenAPI Specification (3.1 and 3.2), AsyncAPI, gRPC and Protocol Buffers documentation, GraphQL specification.
- Python documentation: `http.server` (security note: not for production).
- Repo: [cybersecurity-track networking](../../cybersecurity-track/02-networking/04-dns-dhcp-http-tls.md), [devsecops ch06 OpenAPI scan lab](../../devsecops-course/06-dynamic-analysis/labs/openapi-zap-api-scan/README.md), [MCP authentication](../../04-mcp-security/authentication/README.md), [secure AI gateway](../../09-enterprise-architecture/06-secure-llm-ai-gateway.md).

**Next chapter:** [Chapter 09: API tooling and reconnaissance](../09-api-tooling-and-reconnaissance/README.md).
