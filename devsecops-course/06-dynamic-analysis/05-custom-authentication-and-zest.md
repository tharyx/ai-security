# Lesson 05: Custom authentication for ZAP, and the Zest language

> **Sources merged:** [CDE 4] Ways to handle custom authentications for ZAP Scanner; Using Zest Language to provide better coverage for DAST scans; the "ZAP + Selenium + Zest" lab. [CDP 6] session management challenge.
> **Time:** about 3 hours. **Labs:** [zap-auth-and-zest](labs/zap-auth-and-zest/README.md), [zap-selenium-zest-deep-scan](labs/zap-selenium-zest-deep-scan/README.md).

## 1. Why authentication is the main job

Unauthenticated scans see the login page and the marketing pages. The valuable code (accounts, payments, admin) sits behind login. In the lab, `/account/notes?q=` has a reflected XSS that **only exists when logged in**: the anonymous scan gets a `401` page and finds nothing; the authenticated scan finds the bug.

## 2. The building blocks in ZAP

ZAP models authentication with a **Context**:

| Part | What it holds |
|---|---|
| **Context** | scope: URLs to include and exclude (always exclude logout) |
| **Authentication method** | how to log in |
| **Session management** | how the session is carried: cookie, HTTP header/token |
| **Users** | test accounts and credentials (use a low-privilege test user, and one per role) |
| **Verification** | a regex that proves "logged in" (for example "Welcome") and/or "logged out" (for example "Login required"), or a verification URL |

Verification is critical. Without it ZAP cannot tell that the session died, and keeps scanning as an anonymous user.

## 3. Authentication methods

| Method | Use it when | Notes |
|---|---|---|
| **Form-based** | classic HTML login form POST that sets a session cookie | give login URL, request body with `{%username%}` and `{%password%}`, and the cookie session method |
| **JSON-based** | SPA or API: POST JSON, get a token | body is JSON; response contains a token; add it as a header |
| **HTTP / header / token** | static API key, bearer token, Basic auth, or a token you obtained elsewhere | simple; sent on every request (a header or replacer rule) |
| **Script-based** | anything custom: multi-step logins, CSRF tokens, signed requests, one-time tokens | write a script (Zest or other) that returns the authenticated session |
| **Browser-based** | complex SPA logins, MFA-light flows, redirects through an identity provider | ZAP drives a real browser to log in (the newer browser-based authentication option; verify availability in your version) |

Hard cases: SSO/OIDC redirects, MFA, CAPTCHA, device binding. Best practice: ask for a **test account or test mode that skips MFA in the test environment**. Never disable MFA in production to make a scanner happy.

### The offline context fixtures

The lab includes two Automation Framework style context files:

- [`context-form.yaml`](labs/zap-auth-and-zest/fixtures/context-form.yaml): form login, cookie session, `loggedInRegex` and `loggedOutRegex`.
- [`context-header.yaml`](labs/zap-auth-and-zest/fixtures/context-header.yaml): JSON login that returns a token, carried in an `Authorization: Bearer` header.

Both read the password from `${APP_PASSWORD}` (an environment variable), never from the file. The Python helper `login_with_context` does what ZAP would do: perform the login, build the header, and `is_logged_in` runs the verification check.

## 4. Handling the hard parts

- **CSRF token per form**: a script fetches the form, extracts the token with a regex, then posts it. This is exactly what a Zest or script-based auth does.
- **Expiring tokens**: configure re-authentication when verification fails; shorten scan time or extend token life in test.
- **Logout**: exclude the logout URL from the context.
- **Multiple roles**: one user per role (user, admin) and one scan each; this is how you find vertical privilege escalation.
- **Rate limiting and lockouts**: a wrong password repeated thousands of times locks the account. Test the credentials once before the scan.

## 5. The Zest language

**Zest** is a scripting format created for security tools. It is a **JSON-based, tool-neutral language** of small statements, designed so a script can be **recorded**, **edited** and **replayed** by a tool. ZAP supports Zest (ZAP by Checkmarx: Zest scripts are still supported; verify the current add-on). In the real language a script is a list of statements such as:

- **requests** (`ZestRequest`) with method, URL, headers and body;
- **assertions** (status code, body contains, regex, length) that must hold;
- **assignments** (take a value from a response with a regex or an element and put it in a variable);
- **conditionals** and **loops** (`ZestConditional`, `ZestLoop...`);
- **actions** (fail the script, print, set a variable);
- **client-side steps** for browser recording (open URL, click, type, wait).

Typical uses in DAST:

1. **Authentication script**: log in, extract the token or CSRF value, and hand the session to ZAP.
2. **Recorded scenario**: a user journey recorded in the browser (the Zest recorder), replayed so the scanner reaches deep pages.
3. **Custom check or setup/teardown**: create a test object before a scan; delete it after.
4. **Regression for a found bug**: a Zest script that proves a vulnerability is fixed.

Why it improves coverage: ZAP can use the script to **get a valid session** and then **spider and scan with it**, and a recorded script **seeds the site tree** with pages a spider would not reach.

### The lab's Zest-like script

[`login.zest.json`](labs/zap-auth-and-zest/fixtures/login.zest.json) is a **simplified subset in the spirit of Zest**, not the exact real schema. It contains:

```text
1 ZestRequest   POST {{base}}/api/login  (body uses {{user}} and {{pass}})   assert status 200
2 ZestAssignFromJson  token <- response.token
3 ZestRequest   GET  {{base}}/account  with Authorization: Bearer {{token}}   assert status 200, body contains "Welcome alice"
4 ZestAssignRegex     notes_link <- first href in the page
```

The interpreter [`zest.py`](labs/zap-auth-and-zest/zest.py) runs it against the local app: **variables**, **assertions**, **stop on failure**. The result carries the `token`, which the prober then uses to reach `/account/notes?q=`. It refuses non-loopback targets and unsupported statements.

> **Be honest about the difference.** The real Zest format has more statement types, its own JSON field names, a recorder, and runs inside ZAP. This lab teaches the *model* (statements, assertions, variables). When you use real ZAP, build or record scripts in ZAP and check the docs.

## 6. Naming (current facts, hedged)

- OWASP ZAP is now **ZAP by Checkmarx** (core developers joined Checkmarx in 2024). Docs, add-ons and the Automation Framework continue. Some older tutorials still say "OWASP ZAP" or "ZAProxy".
- Zest scripts are still supported; ZAP also supports client-side Zest scripts for authentication.
- Verify package, image and add-on names at zaproxy.org before copying commands from older articles.

## 7. Summary

- Authenticate, **verify** you are logged in, and re-authenticate when you are not.
- Pick the simplest method that works: form, JSON/token, header; use scripts or browser-based auth for hard flows.
- Zest = recordable, replayable JSON scripts (requests, assertions, assignments). Great for auth and for seeding coverage.
- Keep credentials in the CI secret store; use test accounts per role.

Existing material: [csse ch2 ZAP guide](../../csse-course/ch2-attacking-code-and-application-supply-chain/real-tools/zap.md), [pentesting web testing and Burp](../../cybersecurity-track/09-pentesting-fundamentals/03-web-app-testing-and-burp.md).
