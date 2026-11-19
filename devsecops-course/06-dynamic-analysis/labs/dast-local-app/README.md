# Lab: A local vulnerable app and a mini DAST prober

**Lessons:** [01 DAST basics](../../01-dast-basics-and-challenges.md), [03 server misconfiguration](../../03-tls-and-server-misconfiguration-testing.md#5-server-misconfiguration-testing). Related: [csse ch2 dynamic-analysis lab](../../../../csse-course/ch2-attacking-code-and-application-supply-chain/labs/dynamic-analysis/README.md) (a sibling lab with SSRF; this one adds exposed files, listings and login).

**Time:** 45 minutes. **Tests:** 7, all offline. **Safety:** the app binds to **127.0.0.1** on an ephemeral port and is started and stopped by the tests. The prober has a **scope guard** that refuses any non-loopback target. Secrets are FAKE canaries built at run time. Never point a scanner at systems you do not own.

## Files

| File | Role |
|---|---|
| `vulnapp.py` | `running(fixed=False)` starts a small `http.server` app. Weak version: reflected XSS (`/search?q=`), SQL error leak (`/user?id=`), directory listing (`/files/`), exposed `/.git/HEAD` and `/.env`, no security headers, version banner. Fixed version: escaping, bound parameter, 404/403 for secrets, headers, no banner. Also has form and JSON login and an authenticated `/account` area (used by later labs). |
| `prober.py` | `Prober(base).scan(urls)`: spider, header check, reflected-XSS marker, error-based SQLi, sensitive-path check (content-aware), directory-listing check, version disclosure |
| `demo.py` | scans the weak app, then the fixed app |

The home page builds two links in JavaScript. The spider cannot see them, so `Prober.scan()` with no URL list finds none of the parameter bugs. That is the "AJAX crawling" challenge in miniature.

## Run

```text
.venv/Scripts/python devsecops-course/06-dynamic-analysis/labs/dast-local-app/demo.py
.venv/Scripts/python -m pytest devsecops-course/06-dynamic-analysis/labs/dast-local-app -v
```

## Expected output (real run)

```text
== WEAK app: 10 finding(s), 10 requests ==
  [High  ] EXPOSED-FILE      /.env  (/.env readable)
  [High  ] EXPOSED-FILE      /.git/HEAD  (/.git/HEAD readable)
  [High  ] REFLECTED-XSS     /search?q=  (marker reflected unescaped)
  [High  ] REFLECTED-XSS     /user?id=  (marker reflected unescaped)
  [High  ] SQLI-ERROR        /user?id=  (database error string: 'sqlite error')
  [Medium] DIR-LISTING       /files/  (directory listing enabled)
  [Low   ] MISSING-HEADER    /  (X-Frame-Options not set)
  [Low   ] MISSING-HEADER    /  (X-Content-Type-Options not set)
  [Low   ] MISSING-HEADER    /  (Content-Security-Policy not set)
  [Low   ] VERSION-DISCLOSURE /  (Server: DemoApp/1.0 Python-http.server/3.11)
== FIXED app: 0 finding(s), 10 requests ==
```

(The XSS marker also shows up in the verbose SQL error page of `/user`, which is why that URL has two High findings. Fixing the error page removes both.)

## Steps

1. Run the demo. Match each finding to the planted flaw in `vulnapp.py`.
2. Change the demo to call `p.scan()` with **no** URL list. Which findings disappear, and why?
3. In `vulnapp.py` fix only the SQL query (parameterise it). Re-run: which finding goes away and which stays?
4. Remove `/.env` from `SENSITIVE` in `prober.py`. The scanner is now blind to that bug. This is what "coverage" means for a DAST rule set.

## Think about it

Why does the prober check the **content** of `/.env` (`PASSWORD`) and not only the HTTP status? (A "soft 404" page that returns 200 for every path would make every probe look like a finding.)

## Run the real tool

Point ZAP baseline at a local copy of your own app: see [ZAP Docker scans](../../real-tools/zap-docker-scans.md). Compare ZAP's alerts with this prober's list.
