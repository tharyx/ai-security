# Lab: ZAP authentication contexts and a Zest-like script

**Course exercise:** "Ways to handle custom authentications for ZAP Scanner" and "Using Zest Language to provide better coverage for DAST scans". **Lesson:** [05 custom authentication and Zest](../../05-custom-authentication-and-zest.md).

**Time:** 60 minutes. **Tests:** 10, offline. **Safety:** uses the local app from [dast-local-app](../dast-local-app/README.md) on 127.0.0.1. The interpreter refuses non-loopback URLs. Demo passwords are FAKE.

## Files

| File | Role |
|---|---|
| `fixtures/context-form.yaml` | ZAP Automation Framework style context: **form-based** login, cookie session, logged-in and logged-out regexes, password from `${APP_PASSWORD}` |
| `fixtures/context-header.yaml` | **JSON login** returning a token that is sent in an `Authorization: Bearer` header |
| `fixtures/login.zest.json` | a Zest-like script: request, assertion, variable assignments |
| `zest.py` | `run_script()` (a tiny Zest-subset interpreter), `load_context()`, `login_with_context()`, `is_logged_in()` |

Interpreter statements: `ZestRequest` (with `ZestAssertStatusCode`, `ZestAssertBodyContains`), `ZestAssignFromJson`, `ZestAssignRegex`, `ZestAssignString`. `{{variable}}` substitution. Redirects are not followed so you can see the login response's cookie. A failed assertion stops the script, as in real Zest.

## Real Zest versus this lab

Real **Zest** is a JSON-based, tool-neutral scripting format with many more statements (conditionals, loops, actions, client-side browser steps), its own field names, a recorder and a runtime in ZAP. This lab uses a **simplified subset** so you can see the model (statements, assertions, variables) with Python and no ZAP. Learn the real syntax inside ZAP's Zest add-on.

## Run

```text
.venv/Scripts/python devsecops-course/06-dynamic-analysis/labs/zap-auth-and-zest/demo.py
.venv/Scripts/python -m pytest devsecops-course/06-dynamic-analysis/labs/zap-auth-and-zest -v
```

## Expected output (real run)

```text
== 1. Zest-like script: log in, keep token, assert logged in ==
  ok   POST /api/login -> 200
  ok     assert ZestAssertStatusCode
  ok   token = <json token>
  ok   GET /account -> 200
  ok     assert ZestAssertStatusCode
  ok     assert ZestAssertBodyContains
  ok   notes_link = '/account/notes?q='
  variables: {'token': 'sess-1-alice', 'notes_link': '/account/notes?q='}

== 2. Scan the authenticated page without and with the session ==
  anonymous  : no XSS seen (401 page)
  with token : ['REFLECTED-XSS']

== 3. ZAP context files (form and header based) ==
  app-form  method=form  logged in = True  header keys = ['Cookie']
  app-token method=json  logged in = True  header keys = ['Authorization']
  wrong cookie is detected as logged out: True
```

## Steps

1. Run the demo. Notice that the XSS exists only for the logged-in scan.
2. Change the script password to a wrong value. Which step fails and what does the script do next?
3. Add a `ZestAssignString` step and use its variable in a later URL.
4. Break `loggedInRegex` in `context-form.yaml`. What does `is_logged_in` report? Why is verification the most important part of authentication?
5. Remove `APP_PASSWORD` from the environment dict passed to `login_with_context`. What happens, and why is that good?

## Run the real tool

In ZAP, create a context, choose an authentication method, add a user, then record or write a Zest script. Check the Automation Framework docs for the matching `authentication` block. See [lesson 05](../../05-custom-authentication-and-zest.md) and [Automation Framework](../../real-tools/zap-automation-framework.md).
