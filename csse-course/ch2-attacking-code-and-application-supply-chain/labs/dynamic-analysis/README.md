# Lab: Dynamic analysis (DAST)

**Course exercise:** "Dynamic Analysis". Lessons: [08 section 3-4](../../08-technologies-and-solutions-for-securing-applications.md#3-dast), [05](../../05-attacks-on-the-application-side.md). Related: [pentest mini-app (SQLi, XSS)](../../../../cybersecurity-track/09-pentesting-fundamentals/lab/mini_app.py), [CMCPSE fuzz-mcp-tools](../../../../cmcpse-course/ch5-devsecops-for-mcp-security/labs/fuzz-mcp-tools/README.md). Real tool: [real-tools/zap.md](../../real-tools/zap.md).

**Time:** 45 minutes. **Safety:** the demo app binds to `127.0.0.1` on an ephemeral port and is started and stopped by the tests. The scanner **refuses** any target that is not loopback. The "internal secret" is a FAKE string. Never run a scanner against systems you do not own or have written permission to test.

## What it does

| File | Role |
|---|---|
| `app.py` | `create_server(fixed=False)`: a small `http.server` app with three sinks: `/search?q=` (reflected XSS), `/user?id=` (SQL injection with a verbose database error), `/fetch?url=` (SSRF to an internal metadata route). `fixed=True` is the repaired twin: `html.escape`, parameterized query with `int()`, a host allowlist, and security headers. |
| `dast.py` | crawler (follows links and GET forms), prober (marker reflection, error-based and boolean SQLi, SSRF canary), and passive header checks |

A DAST sees the app only from outside, the way an attacker does. It found the issues without reading the source.

## Run

```text
.venv/Scripts/python csse-course/ch2-attacking-code-and-application-supply-chain/labs/dynamic-analysis/demo.py
.venv/Scripts/python -m pytest csse-course/ch2-attacking-code-and-application-supply-chain/labs/dynamic-analysis
```

## Expected output (real run)

```text
== vulnerable app (listening on 127.0.0.1 only) ==
crawl found: {'/fetch': ['url'], '/search': ['q'], '/user': ['id']}
  missing-header  /        param=-    Content-Security-Policy
  missing-header  /        param=-    X-Content-Type-Options
  ssrf            /fetch   param=url  server fetched an internal URL and returned its content
  reflected-xss   /search  param=q    marker came back unescaped
  sqli-error      /user    param=id   database error text after a quote
  sqli-boolean    /user    param=id   true and false conditions give different pages
== fixed app (listening on 127.0.0.1 only) ==
crawl found: {'/fetch': ['url'], '/search': ['q'], '/user': ['id']}
  no findings
```

## A false-positive story

The first version of the boolean-SQLi check reported `/search` as injectable on the **fixed** app. Why? That page echoes its input, so the pages for `1 AND 1=1` and `1 AND 1=2` differ for a boring reason. The fix removes the echoed payload before comparing (`strip_echo`, with a test). This is typical DAST tuning work.

## Break it yourself

1. Add a `/admin` page that is not linked. Does the crawler find it? (No: crawlers only find what is linked; use an OpenAPI file or a wordlist.)
2. Add a login. What does the DAST need? (A way to authenticate and keep the session: a big part of real DAST setup.)
3. Make the fixed app's allowlist a prefix match (`startswith("docs.example")`). Write the host that breaks it. (`docs.example.attacker.example`.)

## Limits

Blind and stored issues, business-logic flaws and anything behind complex flows are hard for a generic DAST. Use SAST, DAST, SCA and manual testing together.
