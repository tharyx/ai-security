# Lab: Implement DAST as part DevOps pipelines

**Course exercise:** "Implement DAST as part DevOps pipelines". Lesson: [06-automating-controls-in-ci-cd.md](../../06-automating-controls-in-ci-cd.md#4-dynamic-security-analysis-of-applications-apis-containers-and-clusters). Chapter guide: [README](../../README.md). Real-tool guides: [real-tools](../../real-tools/README.md).

**Time:** 60 minutes. **Tests:** 9, all offline. **Safety:** fixtures only; secrets are FAKE, domains are `.example`, advisory ids are fictional, nothing is downloaded or executed, and tests never need Docker, Kubernetes, a network or an account.

> **Outdated to current.** Named tool: **OWASP ZAP in GitLab CI**. OWASP ZAP is actively maintained (verify; check the current container image name). Run only against environments you own.

## What the offline twin does

`dast_stage.py` starts a deliberately weak HTTP app on **127.0.0.1 (ephemeral port)** and a hardened one, then scans them: missing security headers, version disclosure, cookie flags, **reflected input** (a canary string, not an exploit), exposed `/.git/HEAD`, and verbose errors. A **scope guard** refuses any target that is not loopback. `gate()` turns findings into pass or fail.

## Steps

```text
.venv/Scripts/python csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/dast-in-pipeline/demo.py
.venv/Scripts/python -m pytest csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/dast-in-pipeline -v
```

1. Run the demo. The servers start and stop inside the script.
2. Try `scan('http://app.example')` and read the scope guard error. Why is a scope guard part of a safe DAST design?
3. Weaken the hardened app (remove one header) and see the finding.

## Expected output (real run)

```text
== weak app: gate failed (8 findings)
   [medium] DAST-HEADER              missing Content-Security-Policy
   [low   ] DAST-HEADER              missing X-Content-Type-Options
   [low   ] DAST-HEADER              missing Strict-Transport-Security
   [low   ] DAST-VERSION-DISCLOSURE  Server header reveals version: WeakApp/1.0.3
   [medium] DAST-COOKIE-FLAGS        session cookie lacks HttpOnly and/or Secure
   [high  ] DAST-REFLECTED-XSS       input reflected without encoding (canary markup came back intact)
   [high  ] DAST-EXPOSED-GIT         /.git/HEAD is publicly readable
   [medium] DAST-VERBOSE-ERROR       stack trace shown to the client
== hardened app: gate passed (0 findings)
scope guard: target http://app.example is out of scope: only loopback targets are allowed in this lab
```

## Real-tool guide (hedged: verify commands against the current docs)

```text
# ZAP baseline (passive) scan against a TEST environment you own
docker run --rm -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t https://test.example/ -r zap-report.html
# API scan from an OpenAPI file
docker run --rm -v "$PWD:/zap/wrk" -t ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py -t openapi.json -f openapi -r api-report.html
```
```yaml
dast:
  stage: deploy          # after deploying to a TEST environment
  script: [zap-baseline.py -t "$TEST_URL" -J zap.json]
  rules: [{if: '$CI_COMMIT_BRANCH == "main"'}]
  allow_failure: false
```
Written permission and scope first. Use an authenticated test account and test data. Never point an active scan at production or third-party systems. See the repo [pentesting track](../../../../cybersecurity-track/09-pentesting-fundamentals/README.md).
