# Lesson 04: Tools of the Trade: Code Analyzers, Dynamic Scanners and Application Proxies

**Syllabus items covered:** [CSC 1] Introduction to tools of the trade; Code Analyzers; Dynamic Scanning Tools; Application Proxies; Working with Burp Suite.

**Time:** 60 minutes. **Lab:** [intercepting-proxy](labs/intercepting-proxy/README.md); hedged guide [real-tools/burp-suite.md](real-tools/burp-suite.md). **Safety:** only test systems you own or have written permission to test.

> **DBA analogy.** You have three kinds of tools for a slow database: reading the SQL and execution plan (static), load-testing the running system (dynamic), and tracing a live session (`DBMS_MONITOR`, SQL trace) to see exactly what goes over the wire. AppSec has the same three: code analyzers, dynamic scanners and application proxies.

## 1. The tool families

| Family | Looks at | Finds well | Misses | Repo deep dive |
|---|---|---|---|---|
| **Code analyzers** (SAST, SCA, secrets) | Source code, dependencies, config | Injection patterns, weak crypto calls, vulnerable libraries, committed secrets | Business logic, missing authorization, runtime config | [DevSecOps ch05](../../devsecops-course/05-static-analysis-and-secrets/README.md), [ch04](../../devsecops-course/04-software-component-analysis/README.md) |
| **Dynamic scanners** (DAST) | The running app over HTTP | Missing headers, reflected XSS, some injection, TLS problems | Pages it cannot reach, logic flaws, authorization between users | [DevSecOps ch06](../../devsecops-course/06-dynamic-analysis/README.md) |
| **Application proxies** | Live traffic between client and server | Whatever a human tester thinks of: tampering, IDOR, logic flaws | Nothing automatically; it is a tool for people | This lesson, the lab |

No single tool is enough. In a pipeline, SAST and SCA run on every commit, DAST runs against a test deployment, and humans use a proxy for focused testing and to confirm findings.

## 2. Code analyzers

- **SAST (static application security testing):** parses code and looks for dangerous patterns or data flows from a source (request parameter) to a sink (SQL execute). Examples: Semgrep (and its 2025 fork Opengrep), CodeQL, SonarQube, Bandit (Python), SpotBugs with Find Security Bugs (Java), Brakeman (Rails). Expect false positives; tune rules and triage.
- **SCA (software composition analysis):** lists dependencies and matches them to known vulnerabilities (CVE, GHSA, OSV). Examples: OWASP Dependency-Check (needs an NVD API key), pip-audit, npm audit, osv-scanner, Trivy, Grype, Snyk.
- **Secrets scanners:** find keys and passwords in code and git history. Examples: Gitleaks, TruffleHog, GitHub secret scanning and push protection.
- **IaC scanners:** Checkov, KICS, Trivy for Terraform, Kubernetes and Docker files.

Chapter 02 of this course builds a small checklist-driven code reviewer to show how such rules work.

## 3. Dynamic scanning tools

A DAST tool crawls the running app, sends attack payloads to every input it finds and looks at the responses.

- **ZAP** (now "ZAP by Checkmarx", still free and open source): baseline scan (passive, safe for CI), full scan (active), API scan with an OpenAPI file, Automation Framework (YAML plans).
- **Burp Suite Professional scanner**; **Burp Suite DAST** (formerly Enterprise) for scheduled and CI scans; **Dastardly** (free, CI-focused, from PortSwigger).
- **Nuclei:** template-based checks for known issues and misconfigurations.
- **Nikto:** old but quick server misconfiguration checks.

Challenges: authentication (the scanner must stay logged in), single-page apps, coverage, scan time, and the risk of active scans changing data. Only scan with permission, preferably a test environment.

## 4. Application proxies

An intercepting proxy sits between your browser and the server. Because you install the proxy's CA certificate in your test browser, it can also read and edit HTTPS traffic. Main features:

| Feature (Burp name) | What it does | Lab equivalent in `miniproxy.py` |
|---|---|---|
| Proxy, Intercept | Stop a request, edit it, forward it | `on_request(hook)` |
| HTTP history | Every request and response, searchable | `proxy.history` |
| Match and replace | Rewrite traffic automatically by rule | `add_match_replace()` |
| Repeater | Resend an edited copy of one request, again and again | `repeater(index, edit)` |
| Intruder | Send one request many times with payloads in marked positions | `intruder_sniper(template, payloads)` |
| Decoder, Comparer | Encode/decode; diff two responses | not simulated |

Other proxies: **ZAP** (free; also a proxy with a Fuzzer add-on), **mitmproxy** (scriptable in Python), **Caido** (newer, lightweight; verify features and licence). For APIs you will also use curl, Postman or open alternatives such as Bruno, Insomnia and HTTPie (chapter 09).

## 5. Working with Burp Suite

The course exercise uses Burp Suite in the course lab environment. Key points (details and hedged steps in [real-tools/burp-suite.md](real-tools/burp-suite.md)):

1. **Edition:** Community (free; Intruder is throttled; no scanner) versus Professional (paid; scanner, full-speed Intruder, extensions that need Pro). Check current features on PortSwigger's site.
2. **Setup:** start Burp, use the built-in Chromium browser (easiest) or point your browser at `127.0.0.1:8080` and install Burp's CA certificate in that test browser only.
3. **Scope first:** add the target to Target > Scope and filter history to in-scope items so you never attack something by accident.
4. **Daily loop:** browse the app normally with the proxy on, read HTTP history, send interesting requests to Repeater, change one thing at a time, compare responses.
5. **Evidence:** right-click a request to copy it as curl or save the item; you will need request and response in your exam report.

The offline lab teaches the same mental model without installing anything: parse the raw request, change it in flight, replay it, fuzz one position, and read status codes and lengths.

## 6. Scenario: three tools, one bug

A team's SAST tool reports "possible SQL injection" in `search()` because a string is concatenated into a query. The developer marks it as a false positive: "the input is validated in the UI". The champion opens Burp, sends the search request to Repeater and adds a single quote: the response is a 500 with a SQL error. The UI validation never ran, because Burp sent the request directly. A ZAP baseline scan of the same page had reported only a missing header, because its active SQL checks were not enabled. Lessons: client-side validation is not a control; triage SAST results by **testing** them; know what each scan mode actually checks.

## 7. Checklist

- [ ] I can say what SAST, SCA, secrets scanning, DAST and a proxy each find and miss.
- [ ] I can name two tools in each family.
- [ ] I can describe Proxy, HTTP history, Repeater and Intruder in one sentence each.
- [ ] I know the difference between Burp Community and Professional.
- [ ] I set scope before testing and save evidence as I go.
