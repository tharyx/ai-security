# Chapter 01: Security Champions and AppSec Basics

This chapter starts the merged course: how to approach it and its hands-on exams, what a security champion is and how a champion program runs, and then the application security basics every champion needs: HTTP, the tool families (code analyzers, dynamic scanners, application proxies such as Burp Suite), the OWASP Top 10 (2021, mapped to 2025) and the classic risks beyond it. Two offline labs let you exploit and fix SQL injection, XSS, CSRF, SSRF, command injection, IDOR, misconfigurations and open redirects, and practise the Burp workflow with a mini intercepting proxy.

> **Safety.** Every lab is a simulation: in-process toy apps with no sockets, a fake network for SSRF (with a FAKE metadata canary) and a fake shell that never executes anything. Only test systems you own or have written permission to test.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Tool status and version numbers are hedged: **verify at the source**.

## Syllabus coverage

| Syllabus item | Where to study | Lab |
|---|---|---|
| [CSC 0] Course Introduction (About the course, syllabus, and how to approach it) | [Lesson 01 section 1](01-course-orientation-and-exams.md#1-about-this-merged-course) | n/a |
| [CSC 0] About Certification and how to approach it | [01 section 2](01-course-orientation-and-exams.md#2-the-certification-exams-and-how-to-approach-them) | all labs as exam rehearsal |
| [CSC 0] Lab Environment | [01 section 3](01-course-orientation-and-exams.md#3-lab-environment) | [Lab index](#lab-index) |
| [CSC 0] Course support (Mattermost) | [01 section 4](01-course-orientation-and-exams.md#4-course-support) (the course's chat community; check your course portal) | n/a |
| [CSC 0] Who is a Security Champion, and Why do we need them? | [Lesson 02 section 1](02-security-champions.md#1-who-is-a-security-champion-and-why-we-need-them) | n/a |
| [CSC 0] Who Can Become a Security Champion? | [02 section 2](02-security-champions.md#2-who-can-become-a-security-champion) | n/a |
| [CSC 0] Security Champions’ Benefits and Challenges | [02 section 3](02-security-champions.md#3-benefits-and-challenges) | n/a |
| [CSC 0] Security Champions Program Workflow | [02 section 4](02-security-champions.md#4-the-program-workflow) (SVG) | n/a |
| [CSC 1] Introduction to application security | [Lesson 03 section 1](03-appsec-and-http-basics.md#1-introduction-to-application-security) | n/a |
| [CSC 1] The need for application security | [03 section 2](03-appsec-and-http-basics.md#2-the-need-for-application-security) | n/a |
| [CSC 1] What is application security | [03 section 3](03-appsec-and-http-basics.md#3-what-is-application-security) | n/a |
| [CSC 1] Using frameworks securely | [03 section 4](03-appsec-and-http-basics.md#4-using-frameworks-securely) | [vulnerable-shop](labs/vulnerable-shop/README.md) (secure vs vulnerable handlers) |
| [CSC 1] HTTP Security Basics | [03 section 5](03-appsec-and-http-basics.md#5-http-security-basics) (SVG); repo [HTTP and TLS](../../cybersecurity-track/02-networking/04-dns-dhcp-http-tls.md) | [intercepting-proxy](labs/intercepting-proxy/README.md) |
| [CSC 1] HTTP Requests | [03 section 6](03-appsec-and-http-basics.md#6-http-requests) | [intercepting-proxy](labs/intercepting-proxy/README.md) (`parse_request`) |
| [CSC 1] HTTP Responses | [03 section 7](03-appsec-and-http-basics.md#7-http-responses) | [intercepting-proxy](labs/intercepting-proxy/README.md) (`parse_response`) |
| [CSC 1] HTTP Status Codes | [03 section 8](03-appsec-and-http-basics.md#8-http-status-codes) | [intercepting-proxy](labs/intercepting-proxy/README.md) (`status_class`, 302/403/405/429) |
| [CSC 1] Introduction to tools of the trade | [Lesson 04 section 1](04-tools-of-the-trade-and-burp.md#1-the-tool-families) | n/a |
| [CSC 1] Code Analyzers | [04 section 2](04-tools-of-the-trade-and-burp.md#2-code-analyzers); [DevSecOps ch05](../../devsecops-course/05-static-analysis-and-secrets/README.md), [ch04](../../devsecops-course/04-software-component-analysis/README.md) | chapter 02 [code-review-checklist](../02-secure-code-review-and-asvs/labs/code-review-checklist/README.md) |
| [CSC 1] Dynamic Scanning Tools | [04 section 3](04-tools-of-the-trade-and-burp.md#3-dynamic-scanning-tools); [DevSecOps ch06](../../devsecops-course/06-dynamic-analysis/README.md) | [vulnerable-shop](labs/vulnerable-shop/README.md) (`misconfig_scan`, a DAST-style probe) |
| [CSC 1] Application Proxies | [04 section 4](04-tools-of-the-trade-and-burp.md#4-application-proxies) | [intercepting-proxy](labs/intercepting-proxy/README.md) |
| [CSC 1] OWASP Top 10 Basics | [Lesson 05 section 1](05-owasp-top-10.md#1-owasp-top-10-basics) and the [2021 to 2025 mapping](05-owasp-top-10.md#12-2021-to-2025-mapping) | [vulnerable-shop](labs/vulnerable-shop/README.md) |
| [CSC 1] Broken access control | [05 section 2](05-owasp-top-10.md#2-broken-access-control-a012021) | [vulnerable-shop](labs/vulnerable-shop/README.md) (IDOR) |
| [CSC 1] Cryptographic failures | [05 section 3](05-owasp-top-10.md#3-cryptographic-failures-a022021) | [vulnerable-shop](labs/vulnerable-shop/README.md) (cookie flags, HSTS) |
| [CSC 1] Injection | [05 section 4](05-owasp-top-10.md#4-injection-a032021) | [vulnerable-shop](labs/vulnerable-shop/README.md) (SQLi, command injection) |
| [CSC 1] Insecure design | [05 section 5](05-owasp-top-10.md#5-insecure-design-a042021) | [intercepting-proxy](labs/intercepting-proxy/README.md) (client-side price, coupon guessing) |
| [CSC 1] Security misconfiguration | [05 section 6](05-owasp-top-10.md#6-security-misconfiguration-a052021) | [vulnerable-shop](labs/vulnerable-shop/README.md) (`misconfig_scan`) |
| [CSC 1] Vulnerable and outdated components | [05 section 7](05-owasp-top-10.md#7-vulnerable-and-outdated-components-a062021); [DevSecOps ch04](../../devsecops-course/04-software-component-analysis/README.md) | DevSecOps SCA labs |
| [CSC 1] Identification and authentication failures | [05 section 8](05-owasp-top-10.md#8-identification-and-authentication-failures-a072021) | [vulnerable-shop](labs/vulnerable-shop/README.md) (default credentials, login bypass) |
| [CSC 1] Software and data integrity failures | [05 section 9](05-owasp-top-10.md#9-software-and-data-integrity-failures-a082021) | n/a (chapter 12 deserialization lab) |
| [CSC 1] Security logging and monitoring failures | [05 section 10](05-owasp-top-10.md#10-security-logging-and-monitoring-failures-a092021); repo [SIEM](../../cybersecurity-track/06-siem-sentinel-splunk/README.md) | n/a (chapter 15 secure logging lab) |
| [CSC 1] Server side request forgery | [05 section 11](05-owasp-top-10.md#11-server-side-request-forgery-a102021) | [vulnerable-shop](labs/vulnerable-shop/README.md) (SSRF) |
| [CSC 1] Risks beyond the top 10 | [Lesson 06](06-risks-beyond-the-top-10.md) | [vulnerable-shop](labs/vulnerable-shop/README.md) |
| [CSC 1] Cross-Site Scripting (XSS) | [06 section 1](06-risks-beyond-the-top-10.md#1-cross-site-scripting-xss) | [vulnerable-shop](labs/vulnerable-shop/README.md) (reflected, stored) |
| [CSC 1] Insecure Direct Object Reference (IDOR) | [06 section 2](06-risks-beyond-the-top-10.md#2-insecure-direct-object-reference-idor) | [vulnerable-shop](labs/vulnerable-shop/README.md) |
| [CSC 1] Unvalidated Requests and Forwards | [06 section 3](06-risks-beyond-the-top-10.md#3-unvalidated-redirects-and-forwards) (the OWASP 2010/2013 name is "Unvalidated Redirects and Forwards") | [vulnerable-shop](labs/vulnerable-shop/README.md) (`safe_next`) |
| [CSC 1] XML External Entities (XXE) | [06 section 4](06-risks-beyond-the-top-10.md#4-xml-external-entities-xxe) | n/a (chapter 13 XXE lab) |
| [CSC 1] Cross-Site Request Forgery (CSRF) | [06 section 5](06-risks-beyond-the-top-10.md#5-cross-site-request-forgery-csrf) | [vulnerable-shop](labs/vulnerable-shop/README.md) |
| [CSC 1] Working with Burp Suite | [04 section 5](04-tools-of-the-trade-and-burp.md#5-working-with-burp-suite); [real-tools/burp-suite.md](real-tools/burp-suite.md) | [intercepting-proxy](labs/intercepting-proxy/README.md) |
| [CSC 1] SQL Injection Fundamentals | [05 section 4](05-owasp-top-10.md#4-injection-a032021), [06 section 6](06-risks-beyond-the-top-10.md#6-the-hands-on-exercises-in-one-table) | [vulnerable-shop](labs/vulnerable-shop/README.md) (`sqli_union`, `sqli_login_bypass`) |
| [CSC 1] Cross Site Scripting (XSS) | [06 section 1](06-risks-beyond-the-top-10.md#1-cross-site-scripting-xss) | [vulnerable-shop](labs/vulnerable-shop/README.md) (`reflected_xss`, `stored_xss`) |
| [CSC 1] Cross Site Request Forgery (CSRF) | [06 section 5](06-risks-beyond-the-top-10.md#5-cross-site-request-forgery-csrf) | [vulnerable-shop](labs/vulnerable-shop/README.md) (`csrf_change_email`) |
| [CSC 1] Exploiting Server Side Request Forgery (SSRF) | [05 section 11](05-owasp-top-10.md#11-server-side-request-forgery-a102021) | [vulnerable-shop](labs/vulnerable-shop/README.md) (`ssrf_metadata`, prefix-check bypass) |
| [CSC 1] Exploiting Command Injection | [06 section 6](06-risks-beyond-the-top-10.md#6-the-hands-on-exercises-in-one-table) | [vulnerable-shop](labs/vulnerable-shop/README.md) (`command_injection`, `FakeShell`) |
| [CSC 1] Insecure Direct Object References Fundamentals | [06 section 2](06-risks-beyond-the-top-10.md#2-insecure-direct-object-reference-idor) | [vulnerable-shop](labs/vulnerable-shop/README.md) (`idor_read_other_order`) |
| [CSC 1] Security Misconfigurations | [05 section 6](05-owasp-top-10.md#6-security-misconfiguration-a052021) | [vulnerable-shop](labs/vulnerable-shop/README.md) (`misconfig_scan`) |
| [CSC 1] Open Redirect Vulnerabilities | [06 section 3](06-risks-beyond-the-top-10.md#3-unvalidated-redirects-and-forwards) | [vulnerable-shop](labs/vulnerable-shop/README.md) (`open_redirect`) |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| **OWASP Top 10** as the 2021 list | **OWASP Top 10:2025** is published: A01 Broken Access Control (SSRF folded in), A02 Security Misconfiguration, A03 Software Supply Chain Failures, A04 Cryptographic Failures, A05 Injection, A06 Insecure Design, A07 Authentication Failures, A08 Software or Data Integrity Failures, A09 Security Logging and Alerting Failures, A10 Mishandling of Exceptional Conditions. See the [mapping](05-owasp-top-10.md#12-2021-to-2025-mapping). |
| **Server side request forgery** as its own category | Folded into Broken Access Control in 2025. Still a top API risk (API7:2023). |
| **Unvalidated Requests and Forwards**, **XXE**, **CSRF**, **IDOR** | Older Top 10 names (2010/2013/2017). Today they live inside Broken Access Control, Security Misconfiguration or are not listed, but they are still common. |
| **Burp Suite** (single product) | Community (free, throttled Intruder), Professional, **Burp Suite DAST** (formerly Enterprise) and **Dastardly** (free CI). ZAP is now "**ZAP by Checkmarx**". |
| `X-XSS-Protection` and `X-Frame-Options` in older header lists | `X-XSS-Protection` is deprecated (set `0` or omit). Use CSP; `frame-ancestors` supersedes `X-Frame-Options`. |
| Semgrep as the open-source SAST default | Semgrep's rule licence changed and the community fork **Opengrep** appeared in 2025; both are in use. |

## How the three courses overlap here

- **CSC 0 and CSC 1** own this chapter. CSC 1's tools and HTTP items overlap with the API Security course's HTTP and tools chapters (chapters 08 and 09), which go deeper on APIs and build on this lesson rather than repeating it.
- The Top 10 categories return in API form in chapter 13 (OWASP API Security Top 10 2023), and injection gets its own deep dive in chapter 12.
- Threat modeling (chapters 03 to 07) is where "insecure design" is prevented; this chapter only introduces it.

## Learning order

1. [Lesson 01](01-course-orientation-and-exams.md): plan your study and exam approach. About 45 minutes.
2. [Lesson 02](02-security-champions.md): champions and the program workflow. About 1 hour.
3. [Lesson 03](03-appsec-and-http-basics.md), then the [intercepting-proxy lab](labs/intercepting-proxy/README.md). About 2 hours.
4. [Lesson 04](04-tools-of-the-trade-and-burp.md) and [real-tools/burp-suite.md](real-tools/burp-suite.md); repeat the proxy lab in Burp in the course lab. About 1.5 hours.
5. [Lesson 05](05-owasp-top-10.md) and [Lesson 06](06-risks-beyond-the-top-10.md). About 4 hours.
6. The [vulnerable-shop lab](labs/vulnerable-shop/README.md), then the same exercises in the course lab. About 2 hours plus course lab time.
7. Answer the 15 questions below, then go to [Chapter 02](../02-secure-code-review-and-asvs/README.md).

## Lab index

All labs run offline: `.venv/Scripts/python -m pytest appsec-course/01-security-champions-and-appsec-basics -q -p no:cacheprovider`.

| Lab | Course exercises | Tests |
|---|---|---|
| [vulnerable-shop](labs/vulnerable-shop/README.md) | SQL Injection Fundamentals, XSS, CSRF, SSRF, Command Injection, IDOR, Security Misconfigurations, Open Redirect | 32 |
| [intercepting-proxy](labs/intercepting-proxy/README.md) | Working with Burp Suite; HTTP requests, responses and status codes | 12 |

Hedged guide for the real tool: [real-tools/burp-suite.md](real-tools/burp-suite.md).

## Exam tips

- **Client-side controls are not controls.** Hidden fields, disabled buttons and JavaScript validation can be changed in a proxy.
- **Name the fix precisely:** "parameterized queries / bind variables", "context-aware output encoding", "anti-CSRF token plus SameSite", "owner check on every object access", "exact host allowlist on the parsed URL", "argument list, no shell".
- **401 vs 403:** not authenticated vs not allowed. **429** means rate limited.
- **Know both Top 10 lists:** the course uses 2021; mention 2025 changes when asked what is current.
- **Evidence for every finding:** request, response, steps, impact, fix.
- **A champion is not the team's only security person;** the whole team owns security.
- **Hands-on exams are time-boxed:** quick tasks first, evidence as you go, check your exam guide for rules.

## Interview / exam questions

<details>
<summary>1. What is a security champion, and what are they not?</summary>

A member of a delivery team (developer, tester, ops or product person) who spends part of their time on security inside that team: raising security stories, joining threat models, reviewing risky changes and triaging scanner findings. They are not a full-time security engineer, not the team's only tester and not a replacement for the AppSec team.
</details>

<details>
<summary>2. Why do organisations build champion programs?</summary>

The ratio of developers to AppSec engineers is high, so the AppSec team cannot review everything. Champions scale security by being present when decisions are made, catching issues early (cheaper), reducing repeat bugs and improving the relationship between security and engineering.
</details>

<details>
<summary>3. Name three challenges of a champion program and a remedy for each.</summary>

No time (agreed 10 to 20 percent allocation in sprint planning); no management support (executive sponsor, metrics tied to business goals); fading engagement or burnout (community events, recognition, rotation, a clear way to step down).
</details>

<details>
<summary>4. Describe the steps of a champion program workflow.</summary>

Define goals and get sponsorship; nominate volunteers; train them along a path; embed them in team ceremonies; run a community; measure and reward; then adjust and repeat.
</details>

<details>
<summary>5. Why is HTTP described as stateless, and how do apps add state?</summary>

Each request is independent; the server does not remember earlier ones by itself. Apps add state with a session: a random id in a cookie mapped to server-side data, or a token (such as a JWT) sent in a header.
</details>

<details>
<summary>6. What is the difference between 401, 403 and 404 for a protected object?</summary>

401: the client is not authenticated. 403: authenticated but not allowed. 404: not found. Many APIs return 404 for objects the user may not see, so they do not confirm the object exists.
</details>

<details>
<summary>7. Name five security response headers and one deprecated header.</summary>

Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options: nosniff, Referrer-Policy, Cache-Control: no-store, and Set-Cookie with HttpOnly, Secure and SameSite. Deprecated: X-XSS-Protection (set 0 or omit); X-Frame-Options is superseded by CSP frame-ancestors.
</details>

<details>
<summary>8. Compare SAST, DAST and an application proxy.</summary>

SAST reads source code and finds dangerous patterns early but has false positives and misses runtime and logic issues. DAST attacks the running app over HTTP and finds what it can reach, missing logic and multi-user authorization flaws. A proxy is a manual tool that lets a person see and change traffic, finding logic and access-control flaws that tools miss.
</details>

<details>
<summary>9. Why does a string-prefix check not stop SSRF? What does?</summary>

`https://good.example@169.254.169.254/` starts with the allowed text, but the real host is after the `@`. Parse the URL and compare the hostname exactly against an allowlist, allow only https and the default port, reject user-info, block private and link-local addresses after DNS resolution, do not follow redirects blindly, and restrict egress at the network level.
</details>

<details>
<summary>10. How do you fix SQL injection, and how is it like an Oracle practice?</summary>

Use parameterized queries (bind parameters) so data never becomes SQL text, plus least-privilege database accounts and allowlists for identifiers such as sort columns. It is the same as using bind variables (`USING :1`) instead of concatenating strings in `EXECUTE IMMEDIATE`.
</details>

<details>
<summary>11. Explain CSRF and its main defenses.</summary>

Another site makes the victim's browser send a state-changing request; the browser attaches cookies, so it is authenticated. Defenses: anti-CSRF tokens checked server-side, SameSite cookies (set explicitly), Origin or Sec-Fetch-Site checks, no state changes on GET, re-authentication for critical actions. CORS does not prevent CSRF.
</details>

<details>
<summary>12. What are reflected, stored and DOM-based XSS, and what is the primary fix?</summary>

Reflected: payload in the request is echoed back. Stored: payload saved and shown to others. DOM-based: client-side JavaScript writes attacker-controlled data into a dangerous sink. Primary fix: context-aware output encoding (with auto-escaping templates and safe DOM APIs); CSP and HttpOnly cookies are extra layers.
</details>

<details>
<summary>13. How do you prevent command injection?</summary>

Avoid calling external programs; use a library instead. If you must, pass an argument list without a shell (`shell=False`), validate the input against a strict allowlist, and run with least privilege. Never build a shell command string from input.
</details>

<details>
<summary>14. How do you safely implement a redirect after login?</summary>

Allow only local, path-absolute targets: must start with `/`, not `//`, no backslashes, no scheme or host after parsing; otherwise fall back to a default. Alternatively map a short id to an allowlisted URL.
</details>

<details>
<summary>15. What changed between the OWASP Top 10 2021 and 2025?</summary>

Broken Access Control stays first and absorbs SSRF; Security Misconfiguration rises to second; Vulnerable and Outdated Components becomes the broader Software Supply Chain Failures (third); Authentication and Logging categories are renamed (logging stresses alerting); a new A10 Mishandling of Exceptional Conditions appears. Verify exact names at owasp.org.
</details>

## References

- OWASP Top 10 (2021 and 2025), OWASP Security Champions Guide, OWASP Cheat Sheet Series (SQL Injection Prevention, XSS Prevention, CSRF Prevention, SSRF Prevention, Unvalidated Redirects and Forwards, XXE Prevention, OS Command Injection Defense).
- PortSwigger Web Security Academy (free labs on every topic in this chapter) and Burp Suite documentation.
- MDN Web Docs: HTTP messages, status codes, headers, cookies.
- Repo: [web app testing and Burp](../../cybersecurity-track/09-pentesting-fundamentals/03-web-app-testing-and-burp.md), [HTTP and TLS](../../cybersecurity-track/02-networking/04-dns-dhcp-http-tls.md), [DevSecOps SAST](../../devsecops-course/05-static-analysis-and-secrets/README.md), [SCA](../../devsecops-course/04-software-component-analysis/README.md), [DAST](../../devsecops-course/06-dynamic-analysis/README.md).

**Next chapter:** [Chapter 02: Secure Code Review and ASVS](../02-secure-code-review-and-asvs/README.md)
