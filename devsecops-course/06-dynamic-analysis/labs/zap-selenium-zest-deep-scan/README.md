# Lab: QA automation through a proxy for an in-depth scan

**Course exercise:** "using ZAP + Selenium + Zest to configure in-depth scans". **Lesson:** [04 QA automation and OpenAPI](../../04-qa-automation-and-openapi-scans.md), [05 Zest](../../05-custom-authentication-and-zest.md).

**Time:** 60 minutes. **Tests:** 7, offline. **Safety:** everything is on **127.0.0.1**: the app (from [dast-local-app](../dast-local-app/README.md)), a recording proxy and a scripted "browser". The proxy refuses non-loopback targets. No Selenium, no browser, no ZAP is used.

## What it simulates

```text
scripted browser (stands in for Selenium/Playwright)
     -> recording proxy on 127.0.0.1 (stands in for ZAP as a proxy)
          -> local app
```

[`fixtures/qa_steps.json`](fixtures/qa_steps.json) is a QA scenario: open home, open login, submit the login form, open the account, open notes, and two XHR calls (`/search`, `/user`). [`qaproxy.py`](qaproxy.py) has `RecordingProxy` (a forward proxy that records method, URL, status and body), `ScriptedBrowser` (cookies kept, redirects followed) and `recording_to_zest()` (turns the recording into a Zest-like script, the idea behind the real Zest recorder).

The demo then scans twice with the same prober and measures coverage.

## Run

```text
.venv/Scripts/python devsecops-course/06-dynamic-analysis/labs/zap-selenium-zest-deep-scan/demo.py
.venv/Scripts/python -m pytest devsecops-course/06-dynamic-analysis/labs/zap-selenium-zest-deep-scan -v
```

## Expected output (real run, abridged)

```text
QA run through the proxy:
  goto        /                                -> 200
  goto        /login                           -> 200
  submit_form /login                           -> 200
  goto        /account                         -> 200
  goto        /account/notes?q=meeting         -> 200
  xhr         /search?q=laptop                 -> 200
  xhr         /user?id=1                       -> 200

BEFORE (spider only)  : 3 pages, 0 testable parameters, 7 findings, 2 High
AFTER  (QA + session) : 6 URLs,  3 testable parameters, 11 findings, 6 High
parameters reached only through QA automation: [('/account/notes', 'q'), ('/search', 'q'), ('/user', 'id')]
new finding types: ['REFLECTED-XSS', 'SQLI-ERROR']
```

Coverage went from **0 to 3** testable parameters and High findings from **2 to 6**, without changing the scanner.

## Steps

1. Run the demo and read the coverage lines.
2. Remove the `xhr` steps from `qa_steps.json`. Which parameters are lost?
3. Remove the login step. Which URL now returns 401, and which finding disappears?
4. Print `qa.dump(qa.recording_to_zest(proxy.log))` and compare it with [login.zest.json](../zap-auth-and-zest/fixtures/login.zest.json) from the auth lab.
5. Write a new QA scenario that visits a page the spider also finds. Does it add coverage?

## Run the real tools

Selenium (Chrome): add `--proxy-server=localhost:8080`. Playwright: pass `proxy={"server": "http://localhost:8080"}` when launching. Start ZAP headless (daemon) as the proxy, run the tests, then run the passive wait, active scan and report through the Automation Framework. Details and cautions: [lesson 04](../../04-qa-automation-and-openapi-scans.md#2-how-to-wire-it).
