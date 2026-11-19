# Lab: BDD security, codify threats as executable specs

**Course exercise:** "Using BDD security to codify threats" (listed under CDP 2; the Expert course repeats it in the requirements chapter, see [chapter 3](../../../03-security-requirements-and-threat-modeling/README.md)). Lesson: [03 section 6.2](../../03-dsomm-path-and-embedding-security.md#62-bdd-security-codify-threats-as-tests) · **Time:** 2 hours · **Safety:** offline. The "web app" is a Python class answering requests in memory; nothing listens on a port. Passwords in the fixtures are fake demo values.

> **Legacy note.** **BDD-Security** (ContinuumSecurity, later IriusRisk) appears **unmaintained since about 2022**. The idea, security requirements as Gherkin scenarios that run in CI, is still excellent. **Current options:** the same Gherkin with **behave** or **pytest-bdd** (Python) or Cucumber (JVM/JavaScript); **Gauntlt** (also old); **ZAP Automation Framework** plans for scanner-driven checks; or plain `pytest` tests. **Verify tool maintenance before adopting.** This lab uses a tiny runner so you can see how Gherkin works without any library.

## What is in it

| File | Role |
|---|---|
| `features/session.feature` | Session cookie HttpOnly and Secure, SameSite, unpredictable session id, logout invalidates the session |
| `features/authentication.feature` | Lock after 5 failures, 4 failures do not lock, same error for unknown user and wrong password, admin area (a Scenario Outline), anonymous redirect |
| `features/transport_and_exposure.feature` | Required security headers (Outline), no version banner, `.git` files not served |
| `gherkin_lite.py` | Parser (Feature, Background, Scenario, Scenario Outline + Examples, tags, comments) and step runner: results are `passed / failed / undefined / skipped` |
| `security_steps.py` | Step definitions (regex to Python function) |
| `sim_app.py` | `SimApp(vulnerable=False)` is hardened; `SimApp(vulnerable=True)` has classic mistakes |

Not supported by the mini runner: doc strings, step tables, `Rule:`, localisation. Real runners support them.

## How a threat becomes a test

| Threat (STRIDE) | Requirement | Scenario |
|---|---|---|
| Spoofing: online password guessing | Lock the account after 5 failures | `Login must lock after 5 failures` |
| Information disclosure: user enumeration | One generic login error | `Error message must not reveal whether the user exists` |
| Spoofing/Tampering: session theft by script | Session cookie is HttpOnly and Secure | `Session cookie must be HttpOnly` |
| Elevation of privilege | Admin area for admins only | `Admin area is closed to everyone but admins` |
| Information disclosure: recon | No version banners, no `.git` | headers and exposure scenarios |

## Steps

```text
.venv/Scripts/python devsecops-course/02-tools-pipelines-and-secure-sdlc/labs/bdd-security-codify-threats/demo.py
.venv/Scripts/python -m pytest devsecops-course/02-tools-pipelines-and-secure-sdlc/labs/bdd-security-codify-threats -v
```

1. Read `session.feature`. You can understand it without reading Python: that is the point of BDD.
2. Run the demo. The hardened app passes everything; the vulnerable one fails almost everything. Read each failure message: it names the broken requirement.
3. Write a new scenario: "Responses to `/login` must not be cached" (`Cache-Control: no-store`). Add a step if needed, and watch it pass on the hardened app.
4. Add `lockout_threshold=3` in `SimApp` usage and adjust the feature to "after 3 failures". Which test fails first?
5. Introduce a regression: remove `HttpOnly` from the hardened app's cookie. Which scenario catches it?
6. Stretch: port one feature file to `pytest-bdd` or `behave` in your own environment (these libraries are not required by this repo).

## Expected output (real run)

```text
== hardened app
  [PASS] Login must lock after 5 failures
  [PASS] Four failures do not lock the account yet
  [PASS] Error message must not reveal whether the user exists
  [PASS] Admin area is closed to everyone but admins [alice, correct-horse, 403]
  [PASS] Admin area is closed to everyone but admins [root-admin, battery-staple, 200]
  [PASS] Anonymous users are sent to the login page
  [PASS] Session cookie must be HttpOnly
  [PASS] Session cookie must be sent over HTTPS only
  [PASS] Session identifiers are unpredictable
  [PASS] Logout invalidates the session on the server
  [PASS] Responses carry the required security headers [Strict-Transport-Security, max-age]
  [PASS] Responses carry the required security headers [X-Content-Type-Options, nosniff]
  [PASS] Responses carry the required security headers [X-Frame-Options, DENY]
  [PASS] Responses carry the required security headers [Content-Security-Policy, default-src]
  [PASS] The server must not advertise its software version
  [PASS] Version control and backup files are not served [/.git/config]
  [PASS] Version control and backup files are not served [/.git/HEAD]
  -> 17/17 scenarios passed

== vulnerable app
  [FAIL] Login must lock after 5 failures
         why: expected status 423, got 200
  [PASS] Four failures do not lock the account yet
  [FAIL] Error message must not reveal whether the user exists
         why: messages differ: 'Unknown user' vs 'Wrong password' (user enumeration)
  [FAIL] Admin area is closed to everyone but admins [alice, correct-horse, 403]
         why: expected status 403, got 200
  [PASS] Admin area is closed to everyone but admins [root-admin, battery-staple, 200]
  [FAIL] Anonymous users are sent to the login page
         why: expected status 302, got 200
  [FAIL] Session cookie must be HttpOnly
         why: cookie 'session' is missing the HttpOnly flag (has: [])
  [FAIL] Session cookie must be sent over HTTPS only
         why: cookie 'session' is missing the Secure flag (has: [])
  [FAIL] Session identifiers are unpredictable
         why: session id too short (9 chars)
  [FAIL] Logout invalidates the session on the server
         why: expected 302 or 401, got 200
  [FAIL] Responses carry the required security headers [Strict-Transport-Security, max-age]
         why: header Strict-Transport-Security is missing
  [FAIL] Responses carry the required security headers [X-Content-Type-Options, nosniff]
         why: header X-Content-Type-Options is missing
  [FAIL] Responses carry the required security headers [X-Frame-Options, DENY]
         why: header X-Frame-Options is missing
  [FAIL] Responses carry the required security headers [Content-Security-Policy, default-src]
         why: header Content-Security-Policy is missing
  [FAIL] The server must not advertise its software version
         why: header Server reveals a version: 'Apache/2.4.1 (Ubuntu)'
  [FAIL] Version control and backup files are not served [/.git/config]
         why: expected status 404, got 200
  [FAIL] Version control and backup files are not served [/.git/HEAD]
         why: expected status 404, got 200
  -> 2/17 scenarios passed
```

## Run it against a real app

Point the step functions at a **test instance you own** using an HTTP client (for example `httpx` or `requests`) instead of `SimApp`, and keep the same feature files. Never run security tests against systems you are not authorised to test. Hedged real-tool pointers: [ZAP](../../01-tools-of-the-trade.md#5-owasp-zap-zap-by-checkmarx) for scanner-driven checks.

## Limits

The simulated app is tiny and its answers are scripted. Real applications have cookies set by frameworks, proxies that add headers, caches and CDNs, so test the **deployed** shape. Scenario text must stay readable: put detail in steps, not in prose.
