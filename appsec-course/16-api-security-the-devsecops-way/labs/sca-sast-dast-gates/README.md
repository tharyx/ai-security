# Lab: Embedding SCA, SAST and DAST into the CI/CD pipeline (gates over real report formats)

**Course items:** "Embedding Software Composition Analysis Into CI/CD Pipeline", "Embedding Static Application Security Testing Into CI/CD Pipeline", "Embedding Dynamic Application Security Testing Into CI/CD Pipeline", "Integrating Software Component Analysis (SCA) in CI/CD pipeline", "Integrating Static Application Security Testing (SAST) in CI/CD pipeline", "Integrating Dynamic Application Security Testing (DAST) in CI/CD pipeline", plus the three "Finding/Automating" discovery items. Lessons: [02 automated discovery](../../02-automated-vulnerability-discovery.md), [03 section 5](../../03-api-security-at-scale-and-cicd.md#5-embedding-sca-sast-and-dast-into-the-pipeline). Deep dives: [devsecops ch04 SCA](../../../../devsecops-course/04-software-component-analysis/README.md), [ch05 SAST](../../../../devsecops-course/05-static-analysis-and-secrets/README.md), [ch06 DAST](../../../../devsecops-course/06-dynamic-analysis/README.md).

**Time:** 60 minutes. **Tests:** 9, all offline. **Safety:** fixture reports only; all package names and advisory ids are FICTIONAL (`EXAMPLE-2026-NNNN`). The DAST report describes a lab app on 127.0.0.1. Only test systems you own or have written permission to test.

## Goal

Make the three scanners **gates**, not just reports:

| Scanner | Report format here | Real tools that emit it |
|---|---|---|
| SCA | OSV-scanner-like JSON (`results[].packages[].vulnerabilities[]`) | osv-scanner, (similar data) pip-audit, Trivy, Grype, Dependency-Check |
| SAST | **SARIF 2.1.0** (`runs[].results[]`, `rules[].properties.security-severity`) | Semgrep/Opengrep, CodeQL, Bandit (via converter), SonarQube export |
| DAST | ZAP traditional JSON (`site[].alerts[]`, `riskcode` 0–3) | ZAP baseline/API/full scan, (similar) Nuclei, Burp DAST |

Then embed them in the pipeline from the [simple-cicd-pipeline lab](../simple-cicd-pipeline/README.md) (loaded by path, not copied) so a failed gate stops staging and production deploys.

## Concept

[gates.py](gates.py):

- `parse_sca`, `parse_sarif`, `parse_zap` → one `Finding` type with a stable **fingerprint**.
- `evaluate()` applies a policy: fail on HIGH+; for SCA only when a **fix exists**, but **always** for known-exploited (KEV-listed) ids; SARIF `security-severity` mapped like GitHub code scanning; ZAP `riskcode 3` = High.
- A **baseline of suppressions** needs an owner, a reason and a future expiry date; anything else is ignored ([fixtures/baseline.json](fixtures/baseline.json) has one valid, one expired and one invalid entry).
- `embed_in_pipeline()` registers `sca-scan`, `sast-scan`, `dast-scan` and `deploy-staging` actions; [fixtures/secure-pipeline.json](fixtures/secure-pipeline.json) runs SCA and SAST in parallel, deploys to staging, runs DAST against staging, then deploys to prod.

## Run

```text
.venv/Scripts/python appsec-course/16-api-security-the-devsecops-way/labs/sca-sast-dast-gates/demo.py
.venv/Scripts/python -m pytest appsec-course/16-api-security-the-devsecops-way/labs/sca-sast-dast-gates -v
```

## Expected output (real run)

```text
== BEFORE the fixes: 11 findings, gate exit 1
   [FAIL] SAST CRITICAL python.sqlalchemy.sqli.string-concat SQL built with string concatenation @ orders/repo.py:41 #3e4aa463b6ac
   [FAIL] SCA CRITICAL EXAMPLE-2026-0001 Unsafe deserialization in loads() @ fastjsonx@1.2.0 KEV fix-available #666bb1afdc87
   [FAIL] DAST HIGH 40018 SQL Injection @ GET http://127.0.0.1:8080/v2/orders?id=1 #225ac8b0e5af
   [suppressed until 2027-01-31 (appsec-champion: false positive: decode() is only used in a test helper)] SAST HIGH python.jwt.verify-disabled JWT decoded without signature verification @ orders/auth.py:17 #1b061fc4d049
   [FAIL] SCA HIGH EXAMPLE-2026-0002 alg=none accepted @ tinyjwt@0.9.1 fix-available #7c9d4b3cb5f2
   [warn] SCA HIGH EXAMPLE-2026-0003 Billion laughs, no fix yet @ yamlish@3.0.0 #30dbdbc64c69
   [warn] DAST MEDIUM 10038 Content Security Policy (CSP) Header Not Set @ GET http://127.0.0.1:8080/v2/orders #8517dab3e533
   [warn] SAST MEDIUM python.flask.debug-enabled Flask debug mode enabled @ orders/app.py:88 #f7f4e70ddaa2
   [warn] DAST LOW 10021 X-Content-Type-Options Header Missing @ GET http://127.0.0.1:8080/v2/orders #76bac51227f9
   [warn] SAST LOW python.logging.secret-in-log Possible secret written to a log @ orders/payments.py:12 #a6ba6209ecaa
   [warn] SCA LOW EXAMPLE-2026-0004 ANSI injection in log output @ colorlog-lite@2.1.0 fix-available #37472f482e6d

== AFTER the fixes: 4 findings, gate exit 0
   [warn] SCA HIGH EXAMPLE-2026-0003 Billion laughs, no fix yet @ yamlish@3.0.0 #30dbdbc64c69
   [warn] DAST MEDIUM 10038 Content Security Policy (CSP) Header Not Set @ GET http://127.0.0.1:8080/v2/orders #8517dab3e533
   [warn] SAST MEDIUM python.flask.debug-enabled Flask debug mode enabled @ orders/app.py:88 #f7f4e70ddaa2
   [warn] SCA LOW EXAMPLE-2026-0004 ANSI injection in log output @ colorlog-lite@2.1.0 fix-available #37472f482e6d

== Embedded in the pipeline (reports-before), branch main
build      build                success
test       unit-tests           success
security   sca                  failed
security   sast                 failed
staging    deploy-staging       skipped
dast       dast                 skipped
deploy     deploy-prod          skipped
pipeline: failed

== Embedded in the pipeline (reports-after), branch main
build      build                success
test       unit-tests           success
security   sca                  success
security   sast                 success
staging    deploy-staging       success
dast       dast                 success
deploy     deploy-prod          success
pipeline: passed
   sca job artifact: ['gl-sca-report.json']
```

## Steps

1. Read the BEFORE list from the top. Why does the unfixable `yamlish` HIGH only warn, but `fastjsonx` fail even if you raised the threshold to CRITICAL only? (It is known-exploited.)
2. Find the three baseline entries in the output: one applied, one expired, one ignored for having no owner or reason.
3. Move the clock: `evaluate(..., today=date(2027, 2, 1))`. The JWT suppression expires and the gate fails again. Suppressions must come back for review.
4. In the pipeline output, DAST never ran BEFORE the fixes because SCA/SAST failed first. Is "fail fast" right, or should DAST still run to collect findings? (Many teams run all scanners and gate at the end.)
5. Add a fourth tool: a secrets scanner gate (`gl-secret-detection-report.json`) using the same `Finding` type.

## What you learned

- Normalising reports into one finding model makes policies, baselines and dashboards possible.
- Good gates are **specific** (fixable, exploited, high-confidence), so developers trust them; everything else is a warning with a ticket.
- Suppressions are risk acceptances: owner, reason, expiry.

## Run the real tool (hedged)

```bash
osv-scanner scan --format json -L requirements.txt > sca-osv.json         # verify subcommand/flags for your version
semgrep scan --config p/owasp-top-ten --sarif -o sast.sarif .              # or opengrep; CodeQL also emits SARIF
docker run --rm -v "$PWD:/zap/wrk" -t ghcr.io/zaproxy/zaproxy:stable \
  zap-api-scan.py -t http://127.0.0.1:8080/openapi.json -f openapi -J zap-report.json   # your own lab API only
```

GitLab offers templates (`Security/SAST.gitlab-ci.yml`, `Security/Dependency-Scanning.gitlab-ci.yml`, `Security/Secret-Detection.gitlab-ci.yml`, `Security/DAST.gitlab-ci.yml`); the DAST analyzer is now browser-based (verify). GitHub: CodeQL action, `upload-sarif`, Dependabot. Collect results in DefectDojo for tracking.
