# Chapter 09: API Tooling and Reconnaissance

This chapter covers the tools of the trade for API security: the moving parts every request passes through (gateway, load balancer, message queues), the development toolchain that builds and ships an API, and the tools you use to talk to one (curl, Postman, OpenAPI, Python and a MITM proxy such as Burp Suite). It then turns to reconnaissance: reading OpenAPI specs, finding shadow and zombie endpoints, ffuf-style path discovery and user-account enumeration, each with a vulnerable and a fixed version.

> **Safety.** Every lab is a simulation: an in-process toy API, parsed (never executed) curl commands, a JSON spec fixture, an in-process router for discovery, and in-process auth services with toy users. Nothing is sent over the network. Only test systems you own or have written permission to test.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Tool status and version numbers are hedged: **verify at the source**.

## Syllabus coverage

| Syllabus item | Where to study | Lab |
|---|---|---|
| [CASP 2] The Moving Parts in an API | [01 section 1](01-api-moving-parts-and-toolchain.md#1-the-moving-parts-in-an-api) (SVG) | n/a (concept) |
| [CASP 2] API Gateway | [01 API gateway](01-api-moving-parts-and-toolchain.md#api-gateway); repo [secure AI gateway](../../09-enterprise-architecture/06-secure-llm-ai-gateway.md); gateway labs in chapters 14 and 15 | n/a here |
| [CASP 2] Load Balancer/Reverse Proxy | [01 load balancer / reverse proxy](01-api-moving-parts-and-toolchain.md#load-balancer--reverse-proxy) | n/a |
| [CASP 2] Message Queues | [01 message queues](01-api-moving-parts-and-toolchain.md#message-queues) | n/a |
| [CASP 2] Critical Toolchain for API Development | [01 section 2](01-api-moving-parts-and-toolchain.md#2-critical-toolchain-for-api-development) | n/a |
| [CASP 2] Source Code Management | [01 source code management](01-api-moving-parts-and-toolchain.md#source-code-management); repo [devsecops ch02](../../devsecops-course/02-tools-pipelines-and-secure-sdlc/01-tools-of-the-trade.md) | n/a |
| [CASP 2] CI/CD Tools | [01 CI/CD tools](01-api-moving-parts-and-toolchain.md#cicd-tools); repo [devsecops ch02](../../devsecops-course/02-tools-pipelines-and-secure-sdlc/README.md), [chapter 16](../16-api-security-the-devsecops-way/README.md) | n/a |
| [CASP 2] Artifact Management | [01 artifact management](01-api-moving-parts-and-toolchain.md#artifact-management); repo [CSSE ch2](../../csse-course/ch2-attacking-code-and-application-supply-chain/README.md) | n/a |
| [CASP 2] Cloud Platform | [01 cloud platform](01-api-moving-parts-and-toolchain.md#cloud-platform); repo [cloud security](../../cybersecurity-track/10-cloud-security/README.md) | n/a |
| [CASP 2] Infrastructure as Code | [01 infrastructure as code](01-api-moving-parts-and-toolchain.md#infrastructure-as-code); repo [devsecops ch08](../../devsecops-course/08-iac-configuration-and-compliance-as-code/README.md) | n/a |
| [CASP 2] Monitoring and Logging Tools | [01 monitoring and logging tools](01-api-moving-parts-and-toolchain.md#monitoring-and-logging-tools); logging labs in [chapter 15](../15-implementing-api-security-mechanisms/README.md) | n/a |
| [CASP 2] Collaboration Tools | [01 collaboration tools](01-api-moving-parts-and-toolchain.md#collaboration-tools) and scenario | n/a |
| [CASP 2] Containerization | [01 containerization](01-api-moving-parts-and-toolchain.md#containerization); repo [devsecops ch09](../../devsecops-course/09-container-fundamentals/README.md) | n/a |
| [CASP 2] Ability To Talk to an API | [02 section 1](02-talking-to-an-api.md#1-ability-to-talk-to-an-api) | [toy-api-crud](labs/toy-api-crud/README.md) |
| [CASP 2] cURL (curl) | [02 section 2](02-talking-to-an-api.md#2-curl-curl) | [toy-api-crud](labs/toy-api-crud/README.md) |
| [CASP 2] Postman | [02 section 4](02-talking-to-an-api.md#4-postman); [real-tools/postman-and-alternatives.md](real-tools/postman-and-alternatives.md) | [toy-api-crud](labs/toy-api-crud/README.md) (same CRUD skill offline) |
| [CASP 2] OpenAPI (Swagger) | [02 section 5](02-talking-to-an-api.md#5-openapi-swagger) | [openapi-recon](labs/openapi-recon/README.md) |
| [CASP 2] Python | [02 section 6](02-talking-to-an-api.md#6-python) | every lab is Python |
| [CASP 2] An MITM Proxy | [02 section 7](02-talking-to-an-api.md#7-an-mitm-proxy); [real-tools/burp-suite-for-apis.md](real-tools/burp-suite-for-apis.md) | n/a (GUI tool) |
| [CASP 2] Understanding an API Language (Endpoints, Verbs, and State) | [02 section 8](02-talking-to-an-api.md#8-understanding-an-api-language-endpoints-verbs-and-state) | [toy-api-crud](labs/toy-api-crud/README.md) |
| [CASP 2] Understanding cURL Command | [02 section 3](02-talking-to-an-api.md#3-understanding-the-curl-command) | [toy-api-crud](labs/toy-api-crud/README.md) (`parse_curl`, `build_curl`) |
| [CASP 2] Performing CRUD Operations Using API | [02 section 9](02-talking-to-an-api.md#9-performing-crud-operations-using-an-api) | [toy-api-crud](labs/toy-api-crud/README.md) |
| [CASP 2] Setup the Burp Suite for API Security Testing | [03 section 1](03-openapi-burp-and-reconnaissance.md#1-setting-up-burp-suite-for-api-security-testing); [real-tools/burp-suite-for-apis.md](real-tools/burp-suite-for-apis.md) | offline skills: [toy-api-crud](labs/toy-api-crud/README.md) (Repeater-style), [user-enumeration](labs/user-enumeration/README.md) (Comparer-style) |
| [CASP 2] Understanding APIs Using OpenAPI Specifications | [03 section 2](03-openapi-burp-and-reconnaissance.md#2-understanding-apis-using-openapi-specifications) | [openapi-recon](labs/openapi-recon/README.md) |
| [CASP 2] Performing Reconnaissance on an API | [03 section 3](03-openapi-burp-and-reconnaissance.md#3-performing-reconnaissance-on-an-api) (SVG) | [openapi-recon](labs/openapi-recon/README.md) (shadow and zombie endpoints) |
| [CASP 2] Path And Directory Discovery Using FFUF | [03 section 4](03-openapi-burp-and-reconnaissance.md#4-path-and-directory-discovery-using-ffuf); [real-tools/ffuf.md](real-tools/ffuf.md) | [path-discovery-ffuf](labs/path-discovery-ffuf/README.md) |
| [CASP 2] Enumerating User Accounts From an AP | [03 section 5](03-openapi-burp-and-reconnaissance.md#5-enumerating-user-accounts-from-an-api) (the syllabus line is cut off; it means "an API") | [user-enumeration](labs/user-enumeration/README.md) |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| **OWASP ZAP** as the free MITM proxy | Now **"ZAP by Checkmarx"** (still free and open source), with OpenAPI/GraphQL add-ons, a Fuzzer and an Automation Framework. |
| **Burp Suite** editions | Community (free, Intruder throttled), Professional (paid), **Burp Suite DAST** (formerly Enterprise) for CI, and the free **Dastardly** CI scanner. |
| **Postman** as a local tool | Most features need a **cloud login** and sync to Postman's cloud. Offline/open alternatives: **Bruno**, Insomnia, HTTPie. Public workspaces have leaked real keys. |
| **OpenAPI (Swagger)** | Swagger 2.0 = OpenAPI 2. OpenAPI 3.1 is widely used; **3.2.0 published Sept 2025**. |
| Directory brute forcing with **wfuzz/dirb** | **ffuf** is the active, common choice (also gobuster, feroxbuster). wfuzz has had little maintenance. |
| **Kong** as the example gateway | Check Kong's current OSS vs Enterprise packaging. Alternatives: Apache APISIX, Envoy Gateway, Tyk, NGINX, cloud gateways. |
| **Terraform** in the IaC toolchain | Terraform moved to the BSL licence (2023); **OpenTofu** is the open-source fork. |

## How the three courses overlap here

- **CASP 2 only** owns this chapter. The DevSecOps toolchain (SCM, CI/CD, artifact management, IaC, containers, monitoring) is taught in depth in [devsecops-course](../../devsecops-course/README.md) and summarised in lesson 01 with links, not repeated.
- The Security Champion course's Burp introduction ([chapter 01](../01-security-champions-and-appsec-basics/README.md)) is web-app focused; this chapter's Burp guide is API focused (specs, tokens, two users).
- Spec-driven DAST scanning lives in [devsecops ch06](../../devsecops-course/06-dynamic-analysis/labs/openapi-zap-api-scan/README.md) and [chapter 16](../16-api-security-the-devsecops-way/README.md); the recon lab here only reads and compares specs.

## Learning order

1. [Lesson 01](01-api-moving-parts-and-toolchain.md): moving parts and the toolchain. About 1 hour.
2. [Lesson 02](02-talking-to-an-api.md), then the [toy-api-crud lab](labs/toy-api-crud/README.md) and the [Postman guide](real-tools/postman-and-alternatives.md). About 2.5 hours.
3. [Lesson 03 sections 1 and 2](03-openapi-burp-and-reconnaissance.md), the [Burp guide](real-tools/burp-suite-for-apis.md) and the [openapi-recon lab](labs/openapi-recon/README.md). About 2.5 hours.
4. [Lesson 03 sections 3 to 5](03-openapi-burp-and-reconnaissance.md#3-performing-reconnaissance-on-an-api), the [path-discovery-ffuf lab](labs/path-discovery-ffuf/README.md), the [ffuf guide](real-tools/ffuf.md) and the [user-enumeration lab](labs/user-enumeration/README.md). About 2.5 hours.

## Lab index

All labs run offline: `.venv/Scripts/python -m pytest appsec-course/09-api-tooling-and-reconnaissance -q -p no:cacheprovider`.

| Lab | Course items | Tests |
|---|---|---|
| [toy-api-crud](labs/toy-api-crud/README.md) | API language (endpoints, verbs, state), cURL command, CRUD operations | 8 |
| [openapi-recon](labs/openapi-recon/README.md) | Understanding APIs using OpenAPI specifications, reconnaissance | 8 |
| [path-discovery-ffuf](labs/path-discovery-ffuf/README.md) | Path and directory discovery using ffuf | 6 |
| [user-enumeration](labs/user-enumeration/README.md) | Enumerating user accounts from an API | 6 |

Hedged guides for real tools: [Burp Suite for APIs](real-tools/burp-suite-for-apis.md), [Postman and alternatives](real-tools/postman-and-alternatives.md), [ffuf](real-tools/ffuf.md).

## Exam tips

- **Know curl cold:** `-X`, `-H`, `-d`/`--json`, `-u`, `-i`/`-v`, `-s`, `-f`, `-o`, `-w '%{http_code}'`, `-x` (proxy), `-k` (lab only).
- **Verb → CRUD → expected status:** POST 201 + Location, GET 200, PUT/PATCH 200/204, DELETE 204.
- **`security: []` = public** in OpenAPI; the top-level `security` is the default.
- **Shadow = live but undocumented; zombie = old and should be gone.** Both are API9:2023 Improper Inventory Management.
- **401/403/405 during discovery mean "it exists".**
- **Enumeration fix = same status, same message, same size, similar timing,** plus rate limits.
- **A gateway does not do object-level authorization.**
- **Burp setup order:** listener on 127.0.0.1, client proxy, CA in a test profile, scope, then import the spec.

## Interview / exam questions

<details>
<summary>1. What does an API gateway do, and what can it not do?</summary>

It authenticates callers, enforces coarse authorization (scopes), rate limits and quotas, validates requests against a schema, routes versions, strips or adds headers and logs usage. It cannot decide object-level authorization (who owns order 42) or business rules, and it does not protect services that can be reached around it.
</details>

<details>
<summary>2. Why is `X-Forwarded-For` dangerous, and how do you handle it?</summary>

Clients can set it themselves. If the app trusts it from anyone, attackers spoof their IP to bypass IP-based rate limits or allowlists, or to poison logs. Trust it only when the request comes from your own proxy, and take the right-most address added by your trusted proxy chain.
</details>

<details>
<summary>3. What are the security concerns for message queues behind an API?</summary>

Authenticate producers and consumers, apply per-queue/topic ACLs, validate every message in the consumer as untrusted input, keep or encrypt sensitive data, handle poison messages with dead-letter queues, and prevent replay with idempotency keys. Anyone who can publish may be able to act as any user.
</details>

<details>
<summary>4. Pick three toolchain components and describe one way each can compromise an API.</summary>

SCM: a secret committed to history. CI/CD: an unpinned third-party action exfiltrates deployment credentials. Artifact registry: a mutable `:latest` tag replaced with a malicious image. (Also: IaC opening a security group, collaboration tools leaking keys in public workspaces, containers running as root with secrets in layers.)
</details>

<details>
<summary>5. Write a curl command that creates an item with a bearer token and prints only the status code.</summary>

`curl -s -o /dev/null -w '%{http_code}\n' -X POST https://api.lab/api/v1/items -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"name":"widget"}'`
</details>

<details>
<summary>6. What do "endpoints, verbs and state" mean in REST?</summary>

Endpoints are URLs naming resources or collections; verbs (GET, POST, PUT, PATCH, DELETE) are the operations; state is the resource's data, changed by non-safe verbs and transferred as representations (JSON). Testers ask which verbs each endpoint accepts and which state changes are allowed for the current caller.
</details>

<details>
<summary>7. How do you set up Burp Suite to test an API used by a mobile app or Postman?</summary>

Keep the listener on 127.0.0.1:8080 (or the host IP for a device), set the client's proxy, install Burp's CA certificate only in the test client or device, define the target scope, import or replay the API definition, then use Proxy history, Repeater, Comparer and (throttled) Intruder. Remove the CA afterwards.
</details>

<details>
<summary>8. What is the risk of Postman shared or public workspaces?</summary>

Collections and environments sync to the cloud; real API keys or tokens stored in them have been exposed publicly. Use private workspaces, secret variables, short-lived sandbox credentials and secret scanning, or an offline client such as Bruno.
</details>

<details>
<summary>9. What do you look for first in an OpenAPI document?</summary>

Servers (including old or staging hosts), security schemes, the default `security`, operations with `security: []` (public), path parameters that are object IDs (BOLA candidates), writable fields in request schemas (mass assignment), response fields (excessive data exposure), limits on page size, and deprecated operations.
</details>

<details>
<summary>10. Define shadow and zombie APIs and how you find them.</summary>

Shadow: live endpoints not in any documentation (debug, internal, forgotten). Zombie: old versions or retired endpoints still reachable. Find them by comparing specs with JS bundles, mobile apps, archived docs, DNS/certificate data and wordlist discovery. They map to OWASP API9:2023.
</details>

<details>
<summary>11. How does ffuf work, and how do you deal with an API that returns 200 for every path?</summary>

It replaces FUZZ in the URL, headers or body with each word and reports responses; you match or filter by status (`-mc`, `-fc`), size (`-fs`), words or lines, or use auto-calibration (`-ac`). For catch-all 200 responses, filter by the size or word count of the default body.
</details>

<details>
<summary>12. Name four places an API can leak whether an account exists.</summary>

Login (different message or status), registration ("already taken"), password reset ("unknown email"), user lookup endpoints, OTP flows, GraphQL suggestions, and timing or response size differences on any of them.
</details>

<details>
<summary>13. How do you fix user enumeration without hurting usability?</summary>

Return the same status, message and size for both cases ("If the account exists, we sent an email"), run the password hash check even for unknown users (dummy hash) to equalise timing, complete registration by email instead of saying "taken", and add rate limits and monitoring.
</details>

<details>
<summary>14. Why use Python in API testing when you have Burp and Postman?</summary>

For logic the GUI tools make awkward: two-user authorization checks across many objects, loops over IDs, custom token refresh or signing, parsing and comparing large responses, and turning findings into repeatable regression tests in CI.
</details>

<details>
<summary>15. What is a MITM proxy in testing, and why must you be careful with its CA certificate?</summary>

A proxy you place between the client and the API to view, edit, replay and fuzz traffic; to read HTTPS it re-signs traffic with its own CA. Anyone holding that CA's key could intercept the trusting device's traffic, so install it only in a test profile or device and remove it after testing.
</details>

## References

- OWASP API Security Top 10 (2023), especially API9 Improper Inventory Management; OWASP Web Security Testing Guide (API testing sections).
- curl manual (`man curl`, everything.curl.dev); ffuf project README; SecLists.
- PortSwigger Burp Suite documentation and Web Security Academy (API testing topics).
- OpenAPI Specification 3.1 / 3.2; Postman, Bruno, Insomnia and HTTPie documentation.
- Repo: [devsecops ch02 tools of the trade](../../devsecops-course/02-tools-pipelines-and-secure-sdlc/01-tools-of-the-trade.md), [devsecops ch06 OpenAPI + ZAP](../../devsecops-course/06-dynamic-analysis/04-qa-automation-and-openapi-scans.md), [cybersecurity-track Burp workflow](../../cybersecurity-track/09-pentesting-fundamentals/03-web-app-testing-and-burp.md).

**Next chapter:** [Chapter 10: API authentication attacks and defenses](../10-api-authentication/README.md).
