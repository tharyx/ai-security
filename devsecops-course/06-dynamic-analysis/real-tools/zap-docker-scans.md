# Real tool: ZAP Docker scans (baseline, full, API)

> **Hedged guide.** Nothing here is run by the course tests. Image names, flags and script names change; **verify at zaproxy.org** before copying. Scan only systems you own or have written permission to test. Use a staging copy, never production, for full and API scans.

## 1. The three packaged scans

The ZAP Docker image ships three helper scripts:

| Script | What it does | Active attacks? | Typical use |
|---|---|---|---|
| `zap-baseline.py` | spiders the target for a limited time, runs **passive** rules | no | every merge request |
| `zap-full-scan.py` | spider (+ optional AJAX spider) then **active scan** | yes | weekly, staging |
| `zap-api-scan.py` | imports an OpenAPI, SOAP or GraphQL definition then scans the API | yes | API repos |

Image: the project publishes on GitHub Container Registry (for example `ghcr.io/zaproxy/zaproxy:stable`) and Docker Hub. Older tutorials use `owasp/zap2docker-stable`, which is the old name; check which one is current. **Pin a version tag or digest**, not a moving tag.

## 2. Example commands (verify flags)

```text
# baseline: passive, 5 minutes of spidering, HTML + JSON reports
docker run --rm -v "$(pwd)":/zap/wrk:rw -t ghcr.io/zaproxy/zaproxy:stable \
    zap-baseline.py -t https://staging.example.test -m 5 -r baseline.html -J baseline.json

# full: active scan (staging only!)
docker run --rm -v "$(pwd)":/zap/wrk:rw -t ghcr.io/zaproxy/zaproxy:stable \
    zap-full-scan.py -t https://staging.example.test -m 30 -r full.html -J full.json

# API scan from an OpenAPI file or URL
docker run --rm -v "$(pwd)":/zap/wrk:rw -t ghcr.io/zaproxy/zaproxy:stable \
    zap-api-scan.py -t openapi.yaml -f openapi -r api.html -J api.json
```

Useful options (names as documented at the time of writing): `-t` target, `-m` minutes of spidering, `-r`/`-J`/`-x` HTML/JSON/XML report, `-c` a rules config file (set each rule to `IGNORE`, `WARN` or `FAIL`), `-I` do not return failure on warnings, `-a` include alpha rules, `-j` use the AJAX spider, `-z` extra ZAP options, `-n` a context file for authentication.

The exit code tells CI what to do: `0` pass, `1` failures, `2` warnings, `3` error (check the docs). A scan that cannot reach the target must **fail the job**, not pass.

## 3. The rules config file (the "baseline" file)

`-c zap-rules.conf` holds one rule per line with an action. Use it to record known issues so only **new** alerts break the build:

```text
10038   WARN   (CSP header not set: known debt, ticket SEC-123)
10021   IGNORE (accepted: internal tool)
40012   FAIL   (reflected XSS must never ship)
```

Keep each exception with a ticket and an expiry date in a comment.

## 4. In GitHub Actions and GitLab CI

- **GitHub Actions**: the ZAP project publishes actions for baseline, full and API scans (names like `zaproxy/action-baseline`). Pin to a **commit SHA**, give the job the minimum permissions, and note that the action can open issues: check what token scope it needs.
- **GitLab CI**: run the container image in a job:

```yaml
dast-baseline:
  stage: dast
  image:
    name: ghcr.io/zaproxy/zaproxy:stable   # pin a version
    entrypoint: [""]
  script:
    - mkdir -p /zap/wrk
    - zap-baseline.py -t "$REVIEW_APP_URL" -J zap.json -r zap.html || true   # decide the gate on parsed results
  artifacts:
    when: always
    paths: [zap.json, zap.html]
```

Parse `zap.json` with your own gate (see [`schedules.py`](../labs/zap-scan-schedules/schedules.py)) and decide pass or fail. GitLab's own DAST feature (a built-in template, Ultimate tier) is another option; verify availability.

## 5. Safety and hygiene

- Active scans change data. Staging with test data only.
- Give the scanner an **allowlist** of the target host. Exclude logout and destructive URLs.
- Pass credentials through CI secrets, never on the command line in logs.
- Keep reports as artifacts for audit; they can contain sensitive request data.

Related: [Automation Framework guide](zap-automation-framework.md), [Dastardly and Burp DAST](dastardly-and-burp-dast.md), [csse ch2 ZAP guide](../../../csse-course/ch2-attacking-code-and-application-supply-chain/real-tools/zap.md).
