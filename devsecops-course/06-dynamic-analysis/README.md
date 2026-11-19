# Chapter 06: Dynamic Analysis (DAST) in CI/CD

This chapter merges **[CDP 6] DAST (Dynamic Analysis) in CI/CD pipeline** and **[CDE 4] Advanced Dynamic Analysis (DAST) in CI/CD pipeline**. You learn what DAST is, why it is hard (sessions, AJAX), how to put ZAP and Dastardly in a pipeline, how to run baseline, weekly and monthly scans, how to test TLS and server misconfiguration, how to drive scans with QA automation and OpenAPI, and how to handle authentication with contexts and Zest scripts.

> **Safety.** Every lab is offline and local: servers bind to **127.0.0.1** on an ephemeral port and are started and stopped by the tests; scanners refuse non-loopback targets; credentials are FAKE; nothing needs Docker, a network, ZAP, Burp, Java or Node. Never scan systems you do not own or have written permission to test.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Tool names and versions here are hedged: **verify at the source**.

## Syllabus coverage

Every line of both source chapters, verbatim and in source order.

| Syllabus item | Where to study | Lab |
|---|---|---|
| [CDP 6] What is Dynamic Application Security Testing. | [Lesson 01 section 1](01-dast-basics-and-challenges.md#1-what-dast-is) | [dast-local-app](labs/dast-local-app/README.md) |
| [CDP 6] Dynamic Analysis and Its challenges ( Session Management, AJAX Crawling ) | [Lesson 01 section 3](01-dast-basics-and-challenges.md#3-the-challenges); [lesson 05](05-custom-authentication-and-zest.md) | [dast-local-app](labs/dast-local-app/README.md), [zap-auth-and-zest](labs/zap-auth-and-zest/README.md) |
| [CDP 6] Embedding DAST tools like ZAP and Burp Suite Dastardly into the pipeline. | [Lesson 02](02-zap-dastardly-pipelines-and-schedules.md); [ZAP Docker scans](real-tools/zap-docker-scans.md); [Dastardly and Burp DAST](real-tools/dastardly-and-burp-dast.md); repo [csse ch6 DAST in pipeline](../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/dast-in-pipeline/README.md) | [zap-scan-schedules](labs/zap-scan-schedules/README.md) |
| [CDP 6] SSL misconfiguration testing | [Lesson 03 sections 1 to 4](03-tls-and-server-misconfiguration-testing.md#1-ssl-testing-is-really-tls-testing) | [tls-misconfiguration-checks](labs/tls-misconfiguration-checks/README.md) |
| [CDP 6] Server Misconfiguration Testing like secret folders and files. | [Lesson 03 section 5](03-tls-and-server-misconfiguration-testing.md#5-server-misconfiguration-testing) | [dast-local-app](labs/dast-local-app/README.md) |
| [CDP 6] Creating baseline scans for DAST. | [Lesson 02 section 3](02-zap-dastardly-pipelines-and-schedules.md#3-baseline-scans) | [zap-scan-schedules](labs/zap-scan-schedules/README.md) |
| [CDP 6] Hands-On Labs: | Header line: the labs below | [zap-scan-schedules](labs/zap-scan-schedules/README.md) |
| [CDP 6] using ZAP to configure per commit/weekly/monthly scans. | [Lesson 02 sections 4 to 6](02-zap-dastardly-pipelines-and-schedules.md#4-per-commit-weekly-and-monthly-strategy); [Automation Framework guide](real-tools/zap-automation-framework.md) | [zap-scan-schedules](labs/zap-scan-schedules/README.md) |
| [CDE 4] Embedding DAST tools into the pipeline. | [Lesson 02](02-zap-dastardly-pipelines-and-schedules.md) (same lesson as the CDP row) | [zap-scan-schedules](labs/zap-scan-schedules/README.md) |
| [CDE 4] Leveraging QA/Performance automation to drive DAST scans. | [Lesson 04 sections 1 to 3](04-qa-automation-and-openapi-scans.md#1-the-idea-reuse-tests-you-already-have) (SVG) | [zap-selenium-zest-deep-scan](labs/zap-selenium-zest-deep-scan/README.md) |
| [CDE 4] Using Swagger (OpenAPI) and ZAP to scan APIs iteratively. | [Lesson 04 section 4](04-qa-automation-and-openapi-scans.md#4-openapi-swagger--zap-for-apis) | [openapi-zap-api-scan](labs/openapi-zap-api-scan/README.md) |
| [CDE 4] Ways to handle custom authentications for ZAP Scanner. | [Lesson 05 sections 1 to 4](05-custom-authentication-and-zest.md#2-the-building-blocks-in-zap) | [zap-auth-and-zest](labs/zap-auth-and-zest/README.md) |
| [CDE 4] Using Zest Language to provide better coverage for DAST scans. | [Lesson 05 section 5](05-custom-authentication-and-zest.md#5-the-zest-language) | [zap-auth-and-zest](labs/zap-auth-and-zest/README.md), [zap-selenium-zest-deep-scan](labs/zap-selenium-zest-deep-scan/README.md) |
| [CDE 4] Hands-On Labs: | Header line: the lab below | [zap-selenium-zest-deep-scan](labs/zap-selenium-zest-deep-scan/README.md) |
| [CDE 4] using ZAP + Selenium + Zest to configure in-depth scans. | [Lesson 04](04-qa-automation-and-openapi-scans.md) and [lesson 05](05-custom-authentication-and-zest.md) | [zap-selenium-zest-deep-scan](labs/zap-selenium-zest-deep-scan/README.md), [zap-auth-and-zest](labs/zap-auth-and-zest/README.md) |
| [CDE 4] Note: Students need to bring their Burp Suite Pro License to use in CI/CD | [Lesson 02 section 1](02-zap-dastardly-pipelines-and-schedules.md#1-the-two-tools-in-the-syllabus): hedged note, **Dastardly is free**; **Burp Suite DAST** is the commercial CI product; [Dastardly and Burp DAST guide](real-tools/dastardly-and-burp-dast.md) | n/a (no licence needed for the offline labs) |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| "ZAP" / OWASP ZAP | Now **ZAP by Checkmarx** (core developers joined Checkmarx in 2024). Still open source, with the Automation Framework (YAML), baseline/full/API scans, OpenAPI import and Zest scripts. Old tutorials say "OWASP ZAP" or use the `owasp/zap2docker-*` images: check the current image name. |
| "Burp Suite Pro License to use in CI/CD" | **Dastardly** is a free CI scanner from PortSwigger. The commercial CI product is **Burp Suite DAST** (formerly Burp Suite Enterprise). Burp Pro is a desktop tool. Verify product names and licensing. |
| "SSL misconfiguration testing" | The protocol is **TLS**. SSLv2/v3 and TLS 1.0/1.1 are deprecated; aim for TLS 1.2 and 1.3. Tools: testssl.sh, sslyze, nmap scripts. |
| "Swagger" | Now **OpenAPI** (3.x). Swagger 2.0 files still exist; many tools convert them. |
| "Zest Language" | Still supported in ZAP (also for client-side authentication scripts). Newer ZAP versions also offer **browser-based authentication**. Verify. |
| "Per commit/weekly/monthly" | Still the right idea; implement it with the Automation Framework plans and scheduled pipelines. |

## How the three courses overlap here

The Professional chapter (CDP 6) gives the basics: what DAST is, the challenges, ZAP and Dastardly in a pipeline, SSL and server checks, baselines and schedules. The Expert chapter (CDE 4) goes deeper on **coverage and access**: QA automation through a proxy, OpenAPI scans, custom authentication and Zest. The Container course has no DAST chapter, but container-hosted apps are DAST targets. "Embedding DAST tools into the pipeline" appears in both, so it is **one lesson** (lesson 02). Earlier sibling labs ([csse ch2](../../csse-course/ch2-attacking-code-and-application-supply-chain/labs/dynamic-analysis/README.md), [csse ch6](../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/dast-in-pipeline/README.md)) cover a small DAST; this chapter adds schedules, TLS, OpenAPI, authentication and QA-driven coverage. Also see [pentesting web testing and Burp](../../cybersecurity-track/09-pentesting-fundamentals/03-web-app-testing-and-burp.md).

## Learning order

1. [Lesson 01](01-dast-basics-and-challenges.md), then [dast-local-app](labs/dast-local-app/README.md). About 3 hours.
2. [Lesson 02](02-zap-dastardly-pipelines-and-schedules.md), then [zap-scan-schedules](labs/zap-scan-schedules/README.md) and the three [real-tools](real-tools/zap-docker-scans.md) guides. About 4 hours.
3. [Lesson 03](03-tls-and-server-misconfiguration-testing.md), then [tls-misconfiguration-checks](labs/tls-misconfiguration-checks/README.md). About 2 hours.
4. [Lesson 04](04-qa-automation-and-openapi-scans.md), then [openapi-zap-api-scan](labs/openapi-zap-api-scan/README.md) and [zap-selenium-zest-deep-scan](labs/zap-selenium-zest-deep-scan/README.md). About 4 hours.
5. [Lesson 05](05-custom-authentication-and-zest.md), then [zap-auth-and-zest](labs/zap-auth-and-zest/README.md). About 3 hours.
6. Then [Chapter 07: runtime analysis (RASP/IAST)](../07-runtime-analysis-rasp-iast/README.md).

## Lab index

Run all: `.venv/Scripts/python -m pytest devsecops-course/06-dynamic-analysis`.

| Lab | Exercise | Tests |
|---|---|---|
| [dast-local-app](labs/dast-local-app/README.md) | vulnerable app + mini DAST prober, then the fixed app | 7 |
| [zap-scan-schedules](labs/zap-scan-schedules/README.md) | ZAP AF plan generator, validator, report parser, break-build rules | 14 |
| [tls-misconfiguration-checks](labs/tls-misconfiguration-checks/README.md) | TLS fixture analysis | 9 |
| [openapi-zap-api-scan](labs/openapi-zap-api-scan/README.md) | OpenAPI-driven API scan (auth, injection, BOLA) | 7 |
| [zap-auth-and-zest](labs/zap-auth-and-zest/README.md) | ZAP contexts (form, header) + Zest-like interpreter | 10 |
| [zap-selenium-zest-deep-scan](labs/zap-selenium-zest-deep-scan/README.md) | QA through a recording proxy, coverage before and after | 7 |

Real-tool guides: [ZAP Docker scans](real-tools/zap-docker-scans.md), [Automation Framework](real-tools/zap-automation-framework.md), [Dastardly and Burp DAST](real-tools/dastardly-and-burp-dast.md).

## Exam tips

- **DAST needs a running app; SAST does not.** Say which finds what: DAST finds runtime and configuration issues; SAST finds code patterns.
- **Coverage is the main weakness.** A scanner tests only what it discovers. Fixes: AJAX spider, OpenAPI import, QA traffic through the proxy, Zest recordings.
- **Authentication has three parts**: log in, keep the session, **verify** you are still logged in.
- **Baseline = passive, fast, every commit. Full = active, scheduled, staging only.**
- **Break-build rules**: fail on new High; baseline known debt; accepted risk expires; scan errors fail the job.
- **Dastardly is free; Burp Suite DAST is the commercial CI product.** Say that the licence note in the syllabus needs hedging.
- **TLS checklist**: protocols, ciphers, forward secrecy, certificate expiry and chain, hostname/SAN, key size and signature, HSTS.
- **Server misconfiguration list**: `.git`, `.env`, backups, admin paths, directory listing, verbose errors, banners.
- **BOLA needs two users and object ownership data.**
- **Never active-scan production** or someone else's system.

## 15 exam-style questions

<details>
<summary>1. What is DAST and how does it differ from SAST?</summary>

DAST attacks a running application from outside over HTTP and needs no source. SAST reads source code without running it. DAST finds runtime and configuration problems and reaches only the code that requests reach; SAST sees all code but not the environment.
</details>

<details>
<summary>2. Why does a plain spider often miss important pages?</summary>

It only follows links in HTML. Pages built by JavaScript, API endpoints, and pages behind login are invisible. Use an AJAX spider, an OpenAPI import, recorded QA traffic or authenticated scanning.
</details>

<details>
<summary>3. Name three practical session-management problems for a scanner.</summary>

The scanner clicks logout; CSRF or one-time tokens change on every form; the session or token expires mid-scan and the scanner silently scans as anonymous. Fixes: exclude logout, scripted token handling, a logged-in verification regex and re-authentication.
</details>

<details>
<summary>4. What is a baseline scan and why run it on every commit?</summary>

A short scan: spider plus passive rules only, with no attack traffic. It is fast and safe, so it fits every merge request and finds cheap issues such as missing headers and cookie flags. It also establishes the baseline of known findings so only new ones fail the build.
</details>

<details>
<summary>5. Describe a per-commit, weekly and monthly scan strategy.</summary>

Per commit: baseline (passive), minutes, fail on new High. Weekly: full scan with AJAX spider, active rules and OpenAPI import on staging, fail on High and limit Medium. Monthly: authenticated, deeper policy, several roles, QA-recorded flows, fail on Medium and above, plus TLS checks.
</details>

<details>
<summary>6. What is the difference between Dastardly, Burp Suite DAST and Burp Suite Professional?</summary>

Dastardly is PortSwigger's free lightweight CI scanner. Burp Suite DAST (previously Burp Suite Enterprise) is the commercial scan server for CI and scale. Burp Suite Professional is a paid desktop tool for manual testing. Verify names and licensing at PortSwigger.
</details>

<details>
<summary>7. What does "SSL misconfiguration testing" check?</summary>

Enabled protocol versions (no SSLv2/3 or TLS 1.0/1.1), cipher suites (no NULL, EXPORT, anonymous, RC4, 3DES; prefer AEAD with forward secrecy), certificate validity, expiry, chain and self-signed status, hostname match, key size and signature algorithm, and the HSTS header.
</details>

<details>
<summary>8. Give four server misconfigurations a DAST should look for.</summary>

Exposed `/.git/` or `.env`, backup files, directory listing, admin or debug paths, verbose error pages with stack traces, version banners, dangerous HTTP methods, missing security headers. Check the content of the response, not only the status code.
</details>

<details>
<summary>9. How can QA automation improve DAST coverage?</summary>

Proxy the Selenium, Playwright or API tests through ZAP. ZAP records the real flows, parameters and sessions, runs passive rules, and then actively scans those requests. This reaches logged-in and AJAX pages with valid input at no extra scripting cost.
</details>

<details>
<summary>10. What is "iterative" API scanning with OpenAPI?</summary>

Import the spec, run a short scan, fix import and auth problems, add example values and test data, exclude destructive operations, then re-run whenever the spec changes. Keep the spec in Git and track findings against a baseline.
</details>

<details>
<summary>11. What is BOLA and why is it hard for a scanner to find?</summary>

Broken Object Level Authorization: a user can access another user's object by changing an ID. The scanner needs two users and knowledge of which object belongs to whom. Without that test data it cannot tell whether a 200 response is allowed.
</details>

<details>
<summary>12. List ZAP authentication methods and when to use each.</summary>

Form-based for classic logins with cookies; JSON-based for APIs that return tokens; HTTP/header/token for static tokens or Basic; script-based (for example Zest) for multi-step or CSRF-token logins; browser-based for complex SPA or redirect logins. Always add a logged-in verification.
</details>

<details>
<summary>13. What is Zest and where is it used in DAST?</summary>

Zest is a JSON-based, tool-neutral scripting format for security tools (requests, assertions, assignments, conditionals, actions). In ZAP it is used for authentication scripts, recorded user journeys that seed coverage, setup and teardown, and regression checks.
</details>

<details>
<summary>14. How should a DAST gate treat known and accepted findings?</summary>

Compare with a baseline so old debt does not block builds while it is being fixed, fail on new High findings, record accepted risks with an owner and an expiry, and fail the job if the scan itself errors or cannot log in.
</details>

<details>
<summary>15. The syllabus says to bring a Burp Pro licence for CI. What would you say to the team?</summary>

Burp Pro is a desktop tool. For a free CI gate use Dastardly (or ZAP baseline). If the team wants the full Burp scanner in CI, evaluate Burp Suite DAST. Check current licensing with PortSwigger and compare with ZAP on coverage, authentication, false positives and cost.
</details>

## References

- ZAP documentation (Automation Framework, baseline/full/API scans, authentication, Zest): zaproxy.org (verify current names).
- PortSwigger documentation for Dastardly and Burp Suite DAST.
- OWASP Web Security Testing Guide (WSTG); OWASP API Security Top 10; OpenAPI Specification.
- RFC 8996 (deprecating TLS 1.0 and 1.1); testssl.sh and sslyze documentation; Mozilla SSL configuration guidelines.
- Repo: [csse ch2 dynamic-analysis lab](../../csse-course/ch2-attacking-code-and-application-supply-chain/labs/dynamic-analysis/README.md), [csse ch6 DAST in pipeline](../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/dast-in-pipeline/README.md), [pentesting web testing and Burp](../../cybersecurity-track/09-pentesting-fundamentals/03-web-app-testing-and-burp.md), [DevSecOps chapter 07](../07-runtime-analysis-rasp-iast/README.md).
