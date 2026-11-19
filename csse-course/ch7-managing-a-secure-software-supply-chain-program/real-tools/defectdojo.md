# DefectDojo with Docker Compose and the API (outline)

> **Status: hedged outline, not tested by the repo author.** Read the official docs first: <https://docs.defectdojo.com>. If a command differs, trust the docs.

**Course exercises:** Working with Defect Dojo; Vulnerability Management With DefectDojo.
**Offline twins (tested):** [defectdojo-basics](../labs/defectdojo-basics/README.md) (model, importers, dedup) and [vuln-management-defectdojo](../labs/vuln-management-defectdojo/README.md) (SLA, acceptance, metrics).

## 1. Start it locally (conceptual)

```text
git clone https://github.com/DefectDojo/django-DefectDojo
cd django-DefectDojo
# the project documents a docker compose based start (a helper script such as ./dc-build.sh and ./dc-up.sh,
# or `docker compose up`). Check the README for your release.
docker compose logs initializer | grep "Admin password"   # first-run admin password is printed once (verify)
```

- Open `http://localhost:8080` (port depends on the compose file). Keep it bound to localhost.
- First run pulls several images (web server, Django app, Celery worker, database, message broker). Expect GBs of disk and a few GB of RAM.
- Docker is optional for the course: use the course lab if your laptop is small.

## 2. Model your world

1. Create a **Product Type** and a **Product** (for example `example-app`).
2. Create an **Engagement** (CI/CD type for automated runs).
3. Set **SLA configuration** for the product (days per severity; verify the defaults in your version).
4. Add users and roles (least privilege; SSO if available).

## 3. Import scanner results

Through the UI (Add Findings with a scan type) or the API v2. Get an API token from your user profile; use it from an environment variable.

```text
# conceptual; check /api/v2/oa3/swagger-ui/ on your instance for exact fields
curl -s -X POST "http://localhost:8080/api/v2/import-scan/" \
  -H "Authorization: Token $DD_API_TOKEN" \
  -F "scan_type=Trivy Scan" \
  -F "file=@trivy-results.json" \
  -F "product_name=example-app" \
  -F "engagement_name=ci-main" \
  -F "auto_create_context=true"
```

- `import-scan` creates a test with the results. For repeated CI runs, use **`reimport-scan`** with the same product, engagement and scan type so fixed findings close and regressions reopen.
- Typical producers: `trivy fs --format json`, Semgrep (JSON or SARIF), OSV-Scanner, Gitleaks, Dependency-Check. Scan type names must match the parser list in your version.

## 4. Deduplication and triage

- Check which dedup algorithm your scan type uses (hash code fields, unique id from tool, or both) and whether dedup is per engagement or per product. Compare with `HASH_FIELDS` in the offline lab.
- Mark **false positives** with a reason; use **risk acceptance** with an expiry; link findings to Jira or GitHub issues if configured.

## 5. Metrics

Use the product and global **metrics** and dashboards for open findings by severity, SLA status and MTTR. Cross-check against the offline lab's numbers on your own data.

## 6. Safety

- Never import real customer data into a shared demo instance.
- Rotate or delete API tokens after the exercise.
- Do not expose the instance publicly; it holds a list of your weaknesses.
