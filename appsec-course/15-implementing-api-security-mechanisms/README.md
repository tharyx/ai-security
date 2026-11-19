# Chapter 15: Implementing API Security Mechanisms

Chapter 14 listed the defenses; this chapter **implements** them in a running API estate. It covers secure API design, authentication and authorization implementation, permission and OAuth scope design, rate limiting at every stage (reverse proxy, load balancer, gateway, WAF, app), secrets with HashiCorp Vault, data security and TLS, and logging and monitoring with syslog, ELK and Grafana. Five offline labs make each mechanism testable without installing Vault, ELK, Prometheus or Grafana.

> **Safety.** Every lab is a simulation in one Python process: JSON specs, an explicit clock, a Vault-like store with FAKE secrets generated at runtime, an in-memory log index and metric fixtures. Nothing listens on a network. Only test systems you own or have written permission to test.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Tool status and version numbers are hedged: **verify at the source**.

## Syllabus coverage

Source: **[CASP 8]** API Security course, chapter 8 "Implementing API Security Mechanisms". Every line is listed verbatim and in source order.

| Syllabus item | Where to study | Lab |
|---|---|---|
| [CASP 8] API Security Design Best Practices | [Lesson 01 section 1](01-api-security-design-authn-authz.md#1-api-security-design-best-practices) | [permissions-and-oauth-scopes](labs/permissions-and-oauth-scopes/README.md) |
| [CASP 8] Authentication Implementation | [Lesson 01 section 2](01-api-security-design-authn-authz.md#2-authentication-implementation); attacks in [ch10](../10-api-authentication/README.md) | [permissions-and-oauth-scopes](labs/permissions-and-oauth-scopes/README.md) (token required, deny by default) |
| [CASP 8] Authorization Implementation | [Lesson 01 section 3](01-api-security-design-authn-authz.md#3-authorization-implementation); models in [ch11](../11-api-authorization-and-oauth/README.md) | [permissions-and-oauth-scopes](labs/permissions-and-oauth-scopes/README.md) (`authorize_secure`) |
| [CASP 8] Designing API Permissions | [Lesson 01 section 4](01-api-security-design-authn-authz.md#4-designing-api-permissions) | [permissions-and-oauth-scopes](labs/permissions-and-oauth-scopes/README.md) |
| [CASP 8] Designing OAuth Scopes | [Lesson 01 section 5](01-api-security-design-authn-authz.md#5-designing-oauth-scopes) | [permissions-and-oauth-scopes](labs/permissions-and-oauth-scopes/README.md) (scope matrix, SCOPE-05) |
| [CASP 8] Rate-Limiting Implementation and Best Practices at Different Stages | [Lesson 02 sections 1 and 6](02-rate-limiting-at-every-stage.md#1-why-more-than-one-stage) (SVG); best practices in [ch14 lesson 04](../14-api-defenses-data-security-and-headers/04-rate-limiting-and-api-gateways.md) | [request-throttling](labs/request-throttling/README.md) (`LayeredEdge`) |
| [CASP 8] Reverse Proxy | [Lesson 02 section 2](02-rate-limiting-at-every-stage.md#2-reverse-proxy) | [request-throttling](labs/request-throttling/README.md) |
| [CASP 8] Load Balancer | [Lesson 02 section 3](02-rate-limiting-at-every-stage.md#3-load-balancer) | [request-throttling](labs/request-throttling/README.md) |
| [CASP 8] API Gateways and WAFs | [Lesson 02 section 4](02-rate-limiting-at-every-stage.md#4-api-gateways-and-wafs); Kong lab in [ch14](../14-api-defenses-data-security-and-headers/labs/api-gateway-rate-limiting/README.md) | [request-throttling](labs/request-throttling/README.md) |
| [CASP 8] Request Throttling | [Lesson 02 section 5](02-rate-limiting-at-every-stage.md#5-request-throttling) | [request-throttling](labs/request-throttling/README.md) (`Throttler`, algorithms) |
| [CASP 8] Securely Store Secrets Using Hashicorp Vault | [Lesson 03 section 1](03-secrets-data-security-and-tls.md#1-securely-store-secrets-using-hashicorp-vault); [devsecops ch13](../../devsecops-course/13-secrets-management/04-vault-and-consul.md); [real-tools/hashicorp-vault.md](real-tools/hashicorp-vault.md) | [vault-secrets-for-apis](labs/vault-secrets-for-apis/README.md) |
| [CASP 8] Data Security Implementation | [Lesson 03 section 3](03-secrets-data-security-and-tls.md#3-data-security-implementation); concepts in [ch14 lesson 02](../14-api-defenses-data-security-and-headers/02-data-security-and-password-storage.md) | [ch14 data-security-primitives](../14-api-defenses-data-security-and-headers/labs/data-security-primitives/README.md) |
| [CASP 8] Using Transport Layer Security (TLS) | [Lesson 03 section 4](03-secrets-data-security-and-tls.md#4-using-transport-layer-security-tls); [devsecops ch06 TLS](../../devsecops-course/06-dynamic-analysis/03-tls-and-server-misconfiguration-testing.md) | [devsecops tls-misconfiguration-checks](../../devsecops-course/06-dynamic-analysis/labs/tls-misconfiguration-checks/README.md) |
| [CASP 8] Implementing Sufficient Logging & Monitoring | [Lesson 04 section 1](04-logging-and-monitoring.md#1-implementing-sufficient-logging-and-monitoring) (SVG) | [secure-logging-syslog-elk](labs/secure-logging-syslog-elk/README.md), [container-metrics-alerting](labs/container-metrics-alerting/README.md) |
| [CASP 8] Secure Logging Implementation | [Lesson 04 section 2](04-logging-and-monitoring.md#2-secure-logging-implementation) | [secure-logging-syslog-elk](labs/secure-logging-syslog-elk/README.md) (redaction, CRLF) |
| [CASP 8] Logging Using Syslog Format | [Lesson 04 section 3](04-logging-and-monitoring.md#3-logging-using-syslog-format); [real-tools/elk-and-syslog.md](real-tools/elk-and-syslog.md) | [secure-logging-syslog-elk](labs/secure-logging-syslog-elk/README.md) (RFC 5424) |
| [CASP 8] Using ELK To Capture the Log Data | [Lesson 04 section 4](04-logging-and-monitoring.md#4-using-elk-to-capture-the-log-data); [real-tools/elk-and-syslog.md](real-tools/elk-and-syslog.md) | [secure-logging-syslog-elk](labs/secure-logging-syslog-elk/README.md) (pipeline, KQL-like query) |
| [CASP 8] Using HashiCorp Vault To Create and Consume Secrets Safely | [Lesson 03 section 2](03-secrets-data-security-and-tls.md#2-using-vault-to-create-and-consume-secrets-safely); [real-tools/hashicorp-vault.md](real-tools/hashicorp-vault.md) | [vault-secrets-for-apis](labs/vault-secrets-for-apis/README.md) |
| [CASP 8] Monitoring Docker Containers Using Grafana | [Lesson 04 section 6](04-logging-and-monitoring.md#6-monitoring-docker-containers-with-cadvisor-prometheus-and-grafana); [real-tools/grafana-docker-monitoring.md](real-tools/grafana-docker-monitoring.md) (hedged walkthrough) | [container-metrics-alerting](labs/container-metrics-alerting/README.md) (offline twin) |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| **HashiCorp Vault** as the open tool | BSL licence since Aug 2023; IBM completed its acquisition of HashiCorp in 2025. **OpenBao** (Linux Foundation) is the open-source fork. Cloud secret managers and **workload identity** (SPIFFE/SPIRE, cloud IAM) reduce the need for static secrets. |
| **ELK** | Elasticsearch re-added an open-source **AGPL** option in 2024; **OpenSearch** is the AWS-led fork. Elastic Agent is replacing Beats/Logstash in many setups; OpenTelemetry for logs and traces. |
| "Insufficient Logging & Monitoring" (OWASP API Top 10 2019 API10) | Dropped as its own API item in **2023**; in the web **OWASP Top 10:2025** it is A09 Security Logging & Alerting Failures (verify name). |
| **Grafana** for Docker with Grafana Agent | **Grafana Agent reached EOL (Nov 2025)**; use **Grafana Alloy**. Typical stack: cAdvisor + Prometheus (or Alloy) + Grafana, Loki for logs. |
| Syslog | **RFC 5424** is current (RFC 3164 BSD syslog is legacy); use TLS transport (RFC 5425). |
| OAuth scopes design | **RFC 9700** (OAuth 2.0 Security BCP, Jan 2025); OAuth 2.1 still a draft; **RFC 9396** Rich Authorization Requests for fine-grained permissions; sender-constrained tokens (DPoP RFC 9449, mTLS RFC 8705). |
| WAF | ModSecurity reached EOL under Trustwave (2024) and is now an **OWASP** project; OWASP CRS is current; Coraza is a Go alternative. |

## How the three courses overlap here

- **CASP 8 only** owns this chapter. It is the implementation companion to [chapter 14](../14-api-defenses-data-security-and-headers/README.md) (CASP 7): concepts there, mechanisms here.
- Authentication and authorization **attacks** are in [chapter 10](../10-api-authentication/README.md) and [chapter 11](../11-api-authorization-and-oauth/README.md); this chapter does not repeat them.
- The repo already has deep labs on Vault internals ([devsecops ch13](../../devsecops-course/13-secrets-management/README.md)), TLS testing ([devsecops ch06](../../devsecops-course/06-dynamic-analysis/README.md)), container runtime monitoring ([devsecops ch12](../../devsecops-course/12-container-security-monitoring/README.md)) and SIEM ([cybersecurity-track 06](../../cybersecurity-track/06-siem-sentinel-splunk/README.md)). The labs here focus on the **API service's** side.

## Learning order

1. [Lesson 01](01-api-security-design-authn-authz.md), then the [permissions-and-oauth-scopes lab](labs/permissions-and-oauth-scopes/README.md). About 2.5 hours.
2. [Lesson 02](02-rate-limiting-at-every-stage.md), then the [request-throttling lab](labs/request-throttling/README.md). About 2 hours.
3. [Lesson 03](03-secrets-data-security-and-tls.md), the [vault-secrets-for-apis lab](labs/vault-secrets-for-apis/README.md) and [real-tools/hashicorp-vault.md](real-tools/hashicorp-vault.md). About 2.5 hours.
4. [Lesson 04](04-logging-and-monitoring.md), the [secure-logging-syslog-elk](labs/secure-logging-syslog-elk/README.md) and [container-metrics-alerting](labs/container-metrics-alerting/README.md) labs, and the [ELK](real-tools/elk-and-syslog.md) and [Grafana](real-tools/grafana-docker-monitoring.md) guides. About 3.5 hours.

## Lab index

All labs run offline: `.venv/Scripts/python -m pytest appsec-course/15-implementing-api-security-mechanisms -q -p no:cacheprovider`.

| Lab | Course exercise | Tests |
|---|---|---|
| [permissions-and-oauth-scopes](labs/permissions-and-oauth-scopes/README.md) | Designing API permissions and OAuth scopes; authn/authz implementation | 8 |
| [request-throttling](labs/request-throttling/README.md) | Rate limiting at different stages; request throttling | 10 |
| [vault-secrets-for-apis](labs/vault-secrets-for-apis/README.md) | Securely store secrets; create and consume secrets safely with Vault | 8 |
| [secure-logging-syslog-elk](labs/secure-logging-syslog-elk/README.md) | Secure logging; syslog format; ELK capture | 9 |
| [container-metrics-alerting](labs/container-metrics-alerting/README.md) | Monitoring Docker containers using Grafana (offline twin) | 8 |

Hedged real-tool guides: [HashiCorp Vault / OpenBao](real-tools/hashicorp-vault.md), [ELK and syslog](real-tools/elk-and-syslog.md), [Grafana for Docker](real-tools/grafana-docker-monitoring.md).

## Exam tips

- **Scopes are a ceiling for the client; roles are the user's rights.** Effective = intersection, then the object check.
- **Name scopes `resource:action`;** separate read, write, delete and admin; never one "full access" scope for third parties.
- **Each stage, its identity:** proxy = IP, LB = capacity, gateway = key/token, WAF = signatures, app = account/object.
- **Fixed window allows 2x at the boundary;** sliding window or token bucket fix it. Throttling delays; rate limiting rejects.
- **Vault in one line:** identity (auth method) → policy → short-lived secret (lease) → audit with HMACs.
- **Never log secrets;** escape CR/LF; structured logs; RFC 5424 PRI = facility × 8 + severity.
- **ELK:** Logstash/Agent parses and redacts, Elasticsearch indexes, Kibana queries and alerts; never expose 9200.
- **Grafana stack:** cAdvisor → Prometheus → Grafana; Alloy replaced Grafana Agent.

## Interview / exam questions

<details>
<summary>1. Name five API security design best practices.</summary>

Threat model first; contract-first schemas; deny by default with explicit auth on every route; separate public, partner and admin APIs; return minimal data (DTOs); idempotency keys for money operations; limits everywhere; secure-by-default shared middleware; versioning and retirement; security logging by design.
</details>

<details>
<summary>2. How should a browser SPA authenticate to your API today?</summary>

OIDC authorization code with PKCE through a Backend-for-Frontend; the browser holds only a `__Host-` HttpOnly, Secure, SameSite cookie; the BFF holds tokens and calls the API. No implicit flow, no tokens in localStorage.
</details>

<details>
<summary>3. What must every service check when it receives a JWT access token?</summary>

Signature with an allowlisted algorithm and the right key (JWKS), `iss`, `aud`, `exp`/`nbf`, token type, and required scopes; then the user's permission and object ownership. Never trust an `X-User-Id` header set by another service unless it is signed.
</details>

<details>
<summary>4. What are the three levels of authorization on every request?</summary>

Function level (may this user call this endpoint: BFLA), object level (may they access this specific record: BOLA), property level (may they read or write this field: BOPLA).
</details>

<details>
<summary>5. How do OAuth scopes differ from roles, and what is the effective permission?</summary>

Scopes limit what a client application may do on the user's behalf; roles and permissions describe what the user may do. Effective permission is their intersection, followed by object and attribute checks. A scope cannot give a user rights they lack.
</details>

<details>
<summary>6. What is wrong with a scope called `api` or `full_access`?</summary>

One stolen token can do everything; consent becomes meaningless; least privilege is impossible. Use `resource:action` scopes and grant clients only what they use.
</details>

<details>
<summary>7. Which attacks does each rate-limiting stage stop?</summary>

Reverse proxy: single-IP floods and slow-loris (per IP, body size, timeouts). Load balancer: total overload (capacity, shedding). Gateway: abuse of a key or client (quotas). WAF: signature-based attacks. Application: distributed attacks on one account or business flow (per account/object).
</details>

<details>
<summary>8. What is the boundary-burst problem and how do you fix it?</summary>

With fixed windows, a client can send the full limit at the end of one window and again at the start of the next, so 2x the limit in a short time. Sliding window log/counter or token bucket algorithms prevent it.
</details>

<details>
<summary>9. Throttling vs rate limiting?</summary>

Rate limiting rejects excess requests (429 + Retry-After). Throttling delays or queues them to a steady rate and only rejects when the wait is too long. Use rejection for security-sensitive endpoints, throttling to smooth load for good clients.
</details>

<details>
<summary>10. Describe how an API service should consume secrets from Vault.</summary>

Authenticate with a platform identity (Kubernetes SA, cloud IAM, AppRole with a single-use secret id); a narrow policy; read at startup and cache in memory; renew leases or re-fetch before expiry; prefer dynamic database credentials; reload on rotation; never log values; fail safely when Vault is down.
</details>

<details>
<summary>11. What are dynamic secrets and why are they better?</summary>

Credentials created on demand per client with a lease (for example a database user valid for 10 minutes) and revoked automatically. A stolen credential is useful only briefly, each instance is traceable, and nobody needs to know a long-lived password.
</details>

<details>
<summary>12. What must never appear in logs, and how do you enforce it?</summary>

Passwords, tokens, API keys, session ids, secrets, private keys, full card numbers and unnecessary PII. Enforce with redaction filters by field name and pattern at the source and again in the pipeline, structured logging, code review and secret scanning of log samples.
</details>

<details>
<summary>13. What is log injection and how do you prevent it?</summary>

Attacker input containing CR/LF (or control characters, or lookup syntax like `${jndi:...}`) forges or alters log records, or triggers code in the logger. Prevent with structured JSON logs, escaping control characters, never interpreting log data, and patched logging libraries.
</details>

<details>
<summary>14. Explain an RFC 5424 syslog line.</summary>

`<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD-ID key="value"] MSG`. PRI = facility × 8 + severity (authpriv.warning = 84). Structured data carries machine-readable fields. Use TCP/TLS (RFC 5425) rather than UDP across networks.
</details>

<details>
<summary>15. Which container metrics would you alert on for security, and with what tools?</summary>

CPU far above profile (crypto-miner), network egress from containers that should not talk out (exfiltration), restarts (crash loops, exploitation), new or missing containers (unexpected debug shell, stopped agent), missing memory limits. Collected by cAdvisor, stored and alerted by Prometheus, visualised in Grafana (Alloy as collector, Loki for logs).
</details>

## References

- OWASP API Security Top 10 2023; OWASP cheat sheets: Authentication, Authorization, OAuth 2.0, REST Security, Secrets Management, TLS, Logging, Denial of Service.
- RFC 9700, RFC 9068, RFC 9396, RFC 9449, RFC 8705 (OAuth); RFC 5424, RFC 5425 (syslog); RFC 6585 (429).
- HashiCorp Vault and OpenBao docs; Elastic/OpenSearch docs; Prometheus, cAdvisor, Grafana and Alloy docs; NGINX and HAProxy rate-limiting docs.
- Repo: [devsecops ch13 secrets](../../devsecops-course/13-secrets-management/README.md), [devsecops ch12 container monitoring](../../devsecops-course/12-container-security-monitoring/README.md), [cybersecurity-track 06 SIEM](../../cybersecurity-track/06-siem-sentinel-splunk/README.md).

**Next chapter:** [Chapter 16: API Security, the DevSecOps Way](../16-api-security-the-devsecops-way/README.md)
