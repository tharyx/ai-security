# Real tool: ZAP Automation Framework (YAML plans)

> **Hedged guide.** The Automation Framework (AF) is documented at zaproxy.org. Job and parameter names evolve between versions: **validate against the version you pin**. Nothing here is executed by the course tests; the offline [zap-scan-schedules](../labs/zap-scan-schedules/README.md) lab generates and validates plans of this shape.

## 1. What it is

An AF plan is a YAML file with:

- **`env`**: `contexts` (scope, authentication, session management, users) and global `parameters` (for example `failOnError`, `failOnWarning`, `progressToStdout`);
- **`jobs`**: an ordered list. Common job types: `openapi`, `spider`, `spiderAjax`, `passiveScan-config`, `passiveScan-wait`, `activeScan`, `requestor`, `script`, `alertFilter`, `delay`, `report`.

Because it is a file in Git, a plan can be **reviewed, versioned and reused** across projects, and ZAP exposes a "generate plan from the desktop" workflow so you can build it in the UI first.

## 2. Running it

```text
# local install
zap.sh -cmd -autorun /path/to/plan.yaml

# Docker (mount the plan and an output folder)
docker run --rm -v "$(pwd)":/zap/wrk:rw -t ghcr.io/zaproxy/zaproxy:stable \
    zap.sh -cmd -autorun /zap/wrk/plan.yaml
```

Environment variables can be referenced inside the plan as `${NAME}`. Use that for passwords and tokens so the file holds no secrets.

## 3. A commit-profile plan (what the lab generates)

```yaml
env:
  contexts:
  - name: app
    urls: [https://staging.example.test]
    includePaths: ["https://staging.example.test.*"]
    excludePaths: ["https://staging.example.test/logout.*"]
  parameters: {failOnError: true, failOnWarning: false, progressToStdout: true}
jobs:
- type: passiveScan-config
  parameters: {scanOnlyInScope: true}
- type: spider
  parameters: {context: app, maxDuration: 2}
- type: passiveScan-wait
  parameters: {maxDuration: 5}
- type: report
  parameters: {template: traditional-json, reportDir: /zap/wrk, reportFile: zap-commit}
```

Weekly adds `spiderAjax` and an `activeScan` with a time limit. Monthly adds an authenticated context, a `user`, a stricter scan policy and longer limits.

## 4. Authentication in a plan

```yaml
authentication:
  method: json            # or form, http, script, browser (verify names for your version)
  parameters:
    loginRequestUrl: https://staging.example.test/api/login
    loginRequestBody: '{"username":"{%username%}","password":"{%password%}"}'
  verification:
    method: response
    loggedInRegex: '\QWelcome\E'
users:
- name: scan-user
  credentials: {username: "${ZAP_SCAN_USER}", password: "${ZAP_SCAN_PASSWORD}"}
```

Then give the jobs `user: scan-user`. See [lesson 05](../05-custom-authentication-and-zest.md).

## 5. Review checklist (the same rules the lab validator applies)

1. Context URLs are on the **allowed target list**.
2. The commit profile has **no active scan**.
3. Every `activeScan` has a **maximum duration**.
4. `passiveScan-wait` comes before the report; **`report` is the last job**.
5. **No literal passwords** in the file.
6. Every referenced `user` and `context` exists.
7. Logout and destructive URLs are excluded.

## 6. Gating on the report

The `traditional-json` report has `site[].alerts[]` with `pluginid`, `name`, `riskdesc`, `count` and `instances`. Parse it in a small script and apply your break-build rule (new High fails, baseline and accepted-risk lists suppress known debt). The lab parser [`parse_zap_report`](../labs/zap-scan-schedules/schedules.py) uses a fixture of that shape.

Related: [ZAP Docker scans](zap-docker-scans.md), [Dastardly and Burp DAST](dastardly-and-burp-dast.md).
