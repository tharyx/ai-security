# Lab: A complete CI/CD pipeline (simulated runner)

**Course exercise:** "Use the above tools to create a complete CI/CD pipeline" and "Create a CI/CD pipeline suitable for modern application". Lesson: [02 section 4](../../02-secure-sdlc-and-security-gates.md#4-mapping-the-gates-to-pipeline-jobs) · **Time:** 1.5 hours · **Safety:** offline; the tools are Python functions over fixture files. Nothing is installed, executed in a shell, or sent over a network.

> This lab is **self-contained**. For a more general GitLab-style runner (`needs`, `rules`, artifacts, `when: manual`) see [csse ch1 how-cicd-works](../../../../csse-course/ch1-introduction-to-supply-chain-security/labs/how-cicd-works/README.md); this one focuses on the **security gates** and fake scanner output.

## What it models

`pipeline.yml` defines five stages and five jobs: **build → SCA → SAST → DAST → deploy**.

| Job | Fake tool | What it reads | Fails when |
|---|---|---|---|
| `build` | `npm-build` | `package.json` | never (it creates the artifact `dist/app.tar`) |
| `dependency-scan` | `npm-audit` | `package.json` vs `fixtures/advisories.json` (demo advisories) | any finding at or above `high` |
| `code-scan` | `semgrep` | `*.js` files, four regex rules (eval, SQL concatenation, weak random, hard-coded password) | any finding at or above `high` |
| `baseline-scan` | `zap-baseline` | `runtime.json`: headers, cookie flags, exposed paths, TLS version | any finding at or above `high` (and needs the build artifact) |
| `deploy-staging` | `deploy` | the artifact | `only: main` decides whether it runs |

Runner behaviour: stages run in order; a failed job fails the pipeline and **later stages are skipped**; `allow_failure: true` turns a failure into `failed_allowed` (the pipeline continues: a report, not a gate); `only: main` excludes the job on other branches; findings **below** the `fail_on` threshold are shown but do not block.

## Steps

```text
.venv/Scripts/python devsecops-course/02-tools-pipelines-and-secure-sdlc/labs/complete-cicd-pipeline/demo.py
.venv/Scripts/python -m pytest devsecops-course/02-tools-pipelines-and-secure-sdlc/labs/complete-cicd-pipeline -v
```

1. Run the demo and follow the story: commit 1 has a vulnerable `lodash`, commit 2 bumps it, commit 3 adds SQL concatenation.
2. In `pipeline.yml` set `fail_on: medium` for `baseline-scan`. Does commit 2 still deploy? (The missing CSP header is medium.)
3. Add `allow_failure: true` to `dependency-scan` and run commit 1 again. What is the final status? Why is this dangerous?
4. Add a rule to `SAST_RULES` in `runner.py` (for example `console.log` of a variable named `password`) and a test.
5. Remove the `build` job. What does `baseline-scan` say, and why is "nothing to test" the right failure?
6. Stretch: add a `trivy` image scan job that reads a fake image listing and fails on a critical package.

## Expected output (real run)

```text

== commit 1 (lodash 4.17.15 in package.json): pipeline FAILED
  build   build            success   
  sca     dependency-scan  failed    1 finding(s) >= high
            - [high] ADV-DEMO-001: lodash@4.17.15: Prototype pollution in merge helpers (demo advisory) (fix: 4.17.21) @ package.json
  sast    code-scan        skipped   an earlier stage failed
  dast    baseline-scan    skipped   an earlier stage failed
  deploy  deploy-staging   skipped   an earlier stage failed

== commit 2 (dependency bumped): pipeline SUCCESS
  build   build            success   
  sca     dependency-scan  success   
  sast    code-scan        success   
            - [medium] js-weak-random: Math.random() is not a secure random source (CWE-338) @ server.js:13
  dast    baseline-scan    success   
            - [medium] missing-csp: Content-Security-Policy header not set @ /
            - [low] server-banner: Server header reveals the framework @ /
  deploy  deploy-staging   success   

== commit 3 (someone adds SQL concatenation): pipeline FAILED
  build   build            success   
  sca     dependency-scan  success   
  sast    code-scan        failed    1 finding(s) >= high
            - [medium] js-weak-random: Math.random() is not a secure random source (CWE-338) @ server.js:13
            - [high] js-sql-concat: SQL built by string concatenation (CWE-89) @ server.js:20
  dast    baseline-scan    skipped   an earlier stage failed
  deploy  deploy-staging   skipped   an earlier stage failed

== commit 2 again, but on a feature branch: pipeline SUCCESS
  build   build            success   
  sca     dependency-scan  success   
  sast    code-scan        success   
            - [medium] js-weak-random: Math.random() is not a secure random source (CWE-338) @ server.js:13
  dast    baseline-scan    success   
            - [medium] missing-csp: Content-Security-Policy header not set @ /
            - [low] server-banner: Server header reveals the framework @ /
  deploy  deploy-staging   excluded  only: main
```

## Limits

The fake tools are tiny teaching rules. Real SCA compares version ranges against databases (npm audit, OSV, NVD), real SAST uses parsing and data flow, and real DAST crawls and attacks a live app. Real pipelines add caching, parallelism, services, retries and permissions. See [csse ch6 pipeline labs](../../../../csse-course/ch6-common-defenses-against-supply-chain-attacks/README.md) for tool-shaped labs, and [ci-pipeline-multi-platform](../ci-pipeline-multi-platform/README.md) for the real syntaxes.
