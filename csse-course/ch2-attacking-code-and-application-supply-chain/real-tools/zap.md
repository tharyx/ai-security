# OWASP ZAP: DAST against a local target

> **Status: hedged outline, not tested by the repo author.** Verify at <https://www.zaproxy.org/docs/>. The project's stewardship changed in 2024 (the core team joined Checkmarx, still open source; verify). ZAP needs Java or its Docker image.

**Offline twin (tested):** [dynamic-analysis](../labs/dynamic-analysis/README.md). **Scan only what you own or may test.** Never point ZAP at the internet or at third-party systems.

## Practice target

Start the lab's vulnerable app yourself, on localhost (the tests start it on a random port; for a manual run use a small script):

```text
.venv/Scripts/python -c "import sys; sys.path.insert(0,'csse-course/ch2-attacking-code-and-application-supply-chain/labs/dynamic-analysis'); import app,time; s,b=app.start(False); print(b); time.sleep(600)"
```

Note the printed URL (127.0.0.1 and a port). Stop it with Ctrl+C when done.

## Quick baseline scan (outline)

```text
# desktop app: set the target URL to the printed address, run an automated scan
# or the packaged scripts (verify names and flags in the docs):
zap-baseline.py -t http://127.0.0.1:<port>      # passive scan, safe
zap-full-scan.py -t http://127.0.0.1:<port>     # active scan: sends attack payloads, only on targets you own
```

If you run ZAP in Docker against a service on your laptop, the container reaches your host through a special hostname or network setting that depends on your OS (verify the docs); do not publish the app to your LAN.

## Compare with the lab

| Lab finding | Expect in ZAP |
|---|---|
| reflected XSS on `/search` | an XSS alert with the parameter `q` |
| SQL injection on `/user` | an SQL injection alert (error or boolean based) |
| SSRF on `/fetch` | usually needs a callback-style or manual test; compare with the lab's internal canary |
| missing headers | passive alerts for CSP and X-Content-Type-Options |

Look at what ZAP reports that the lab does not (cookies, information leaks) and what it misses.

## Practices

- Authenticated scans need a session set-up (context, users, login script).
- Import an **OpenAPI** definition for API coverage.
- Run in CI against a **staging** deployment with test data; export a report (SARIF or HTML) and triage ([lesson 08](../08-technologies-and-solutions-for-securing-applications.md)).

## Cleanup

Stop the app and ZAP; delete session files and any reports with sensitive data.
