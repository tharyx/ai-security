# Lesson 01: What DAST is, and why it is hard

> **Sources merged:** [CDP 6] What is Dynamic Application Security Testing; Dynamic Analysis and its challenges (session management, AJAX crawling). [CDE 4] feeds the "how to get better coverage" ideas used later.
> **Time:** about 2 hours. **Lab:** [dast-local-app](labs/dast-local-app/README.md).

## 1. What DAST is

**DAST (Dynamic Application Security Testing)** attacks a **running** application from the outside, the way a hacker would. It sends requests and reads responses. It does not need the source code.

| | SAST (static) | SCA | DAST (dynamic) |
|---|---|---|---|
| Looks at | source code | third-party libraries | the running app over HTTP |
| Needs a running app | no | no | **yes** |
| Good at | code-level flaws early | known-vulnerable components | runtime flaws, misconfiguration, auth and session bugs |
| Weak at | environment, config | your own code | code paths it cannot reach |

DBA analogy: SAST reads your PL/SQL package source. DAST is a user calling the application with bad input and watching what comes back. Both are needed, because they find different bugs.

What DAST is good at finding:

- reflected XSS, SQL injection (from error messages and behaviour), open redirects, path traversal
- missing security headers, weak cookie flags, verbose errors, version banners
- exposed files and folders (`/.git/`, `/.env`, backups), directory listings
- TLS problems and server misconfiguration (lesson 03)
- broken authentication and session handling

What DAST cannot see: code that no request reaches, business-logic flaws that need human thinking, and anything behind a login it cannot pass.

## 2. How a DAST scanner works

```text
1. Discover   spider / crawler + AJAX spider + OpenAPI import + proxied traffic  -> the "site tree"
2. Passive    read every response it sees: headers, cookies, comments, errors  (safe, no attack)
3. Active     send attack-like requests to each parameter  (changes data, can be slow)
4. Report     alerts with risk, confidence, URL, evidence, and a fix hint
```

The **passive** step is safe enough for every commit. The **active** step is the one that can trip alarms, create junk records, or fill a queue. That split drives the scan strategy in [lesson 02](02-zap-dastardly-pipelines-and-schedules.md).

You can see this in the offline lab: [`prober.py`](labs/dast-local-app/prober.py) sends only a harmless marker string, a single quote and a few GETs, then checks the replies. Same idea, tiny scale.

## 3. The challenges

### 3.1 Coverage: a scanner only tests what it finds

If the scanner never discovers `/user?id=`, it never tests it. In the lab the home page builds two links in JavaScript. A plain spider sees only `/about` and `/login`, finds **zero testable parameters**, and reports a quiet app with only header issues. That is a **false sense of safety**: the worst bugs were there, just not reached.

### 3.2 AJAX and single-page apps (AJAX crawling)

Modern pages build links and forms with JavaScript and call APIs with `fetch`/XHR. A classic spider reads raw HTML and never runs the script.

Fixes:

- use an **AJAX spider** (ZAP's `spiderAjax` job drives a real headless browser);
- import the **OpenAPI spec** so API endpoints are known without crawling ([lesson 04](04-qa-automation-and-openapi-scans.md));
- feed the scanner **recorded traffic** from QA tests ([lesson 04](04-qa-automation-and-openapi-scans.md));
- list known URLs by hand when nothing else works.

### 3.3 Session management

Most valuable pages sit behind a login. The scanner must:

1. log in (form, JSON, token, SSO, MFA...);
2. keep the session (cookie or token) alive while it sends thousands of requests;
3. **notice when it got logged out** (session timeout, a logout link it clicked, a token that expired) and log in again.

Common traps: the spider clicks **Logout** (so exclude `/logout`), CSRF tokens change on every form, one-time tokens, short-lived JWTs, MFA, CAPTCHA. A scanner that is silently logged out scans only the login page for an hour and reports "no findings". [Lesson 05](05-custom-authentication-and-zest.md) shows how to configure and verify authentication.

### 3.4 Speed and safety

- Active scans are **slow**: every parameter times every rule. Budget them (`maxScanDurationInMins`).
- Active scans are **intrusive**: they POST junk, create accounts, trigger emails. Use a **test environment with test data**, never production.
- Rate limits, WAFs and bot protection can block the scanner, which looks like a clean result.

### 3.5 False positives and false negatives

DAST has fewer false positives than SAST (it sees a real response), but still has them: a reflected marker inside an HTML comment or a JSON response is not always exploitable. And false negatives come from coverage gaps (3.1 to 3.3). Track both; see [chapter 14](../14-vulnerability-management/README.md).

### 3.6 Findings need context

A DAST alert says "SQL injection at `/user?id=`". It does not say which line of code. Developers fix faster with a code pointer, which is one reason teams add IAST ([chapter 07](../07-runtime-analysis-rasp-iast/README.md)).

## 4. DAST versus penetration testing

A **pentest** is a human with creativity, business knowledge and time. DAST is automation: repeatable, cheap per run, runs on every build, but shallow in logic. DevSecOps uses DAST for the **repeatable baseline** and schedules human pentests for depth (see [pentesting fundamentals](../../cybersecurity-track/09-pentesting-fundamentals/03-web-app-testing-and-burp.md)). The syllabus line "DevSecOps and challenges with Pentesting and Vulnerability Assessment" is covered in [chapter 02](../02-tools-pipelines-and-secure-sdlc/README.md).

## 5. Try it

```text
.venv/Scripts/python devsecops-course/06-dynamic-analysis/labs/dast-local-app/demo.py
```

Run the prober against the weak app, then the fixed app. Then run it **without** the two hidden URLs and watch the high-severity findings disappear. That is the coverage problem in one experiment.

## 6. Summary

- DAST tests the running app from outside; SAST reads code; they find different things.
- The scanner is only as good as its **discovery**: spider, AJAX spider, API spec, recorded traffic.
- Authentication and session handling are the biggest practical difficulty. Always **verify** the scanner is still logged in.
- Passive scans are safe on every commit; active scans need a test environment and a time budget.

Existing material: [csse ch2 dynamic-analysis lab](../../csse-course/ch2-attacking-code-and-application-supply-chain/labs/dynamic-analysis/README.md), [csse ch6 DAST in pipeline](../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/dast-in-pipeline/README.md).
