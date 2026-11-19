# Real tool: Burp Suite Dastardly and Burp Suite DAST

> **Hedged guide.** Product names, image names and variables change. **Verify at PortSwigger's documentation** before use. Nothing here runs in the course tests. Scan only systems you own or have permission to test.

## 1. Which Burp product is which

| Product | What it is | Licence | Use in CI |
|---|---|---|---|
| **Dastardly** | lightweight scanner for CI, built on Burp's engine, focused on a limited set of checks that give few false positives | **free** | quick gate on every build |
| **Burp Suite DAST** (previously called Burp Suite Enterprise Edition) | commercial scan server with scheduling, many sites, reports, CI integration and the full Burp scanner | paid | scale and depth |
| **Burp Suite Professional** | desktop tool for manual testing with an automated scanner | paid, per user | a tester's workstation, not the pipeline |

### The syllabus note, in plain words

The CDE chapter says *"Students need to bring their Burp Suite Pro License to use in CI/CD."* In this unified course:

- You do **not** need a Pro licence to learn the pipeline pattern: **Dastardly is free** and gives you the CI-friendly workflow (start URL, scan, JUnit XML, fail the build).
- If your employer wants the full Burp scanner in CI, the product built for that is **Burp Suite DAST**.
- Burp Pro is still the manual tool a pentester uses to explore findings the pipeline raised.
- Licensing and product lines change, so **verify** with PortSwigger.

## 2. Dastardly in GitHub Actions (shape, verify details)

PortSwigger publishes a GitHub Action for Dastardly (a repository named like `PortSwigger/dastardly-github-action`). The pattern:

```yaml
name: dast
on: [pull_request]
jobs:
  dastardly:
    runs-on: ubuntu-latest
    steps:
      - name: Start the app under test (your own step; for example docker compose up -d)
        run: docker compose up -d
      - name: Dastardly scan
        uses: PortSwigger/dastardly-github-action@<PIN-A-COMMIT-SHA>   # pin to a commit SHA
        with:
          target-url: http://localhost:8080   # your review app
      - name: Publish results
        if: always()
        uses: actions/upload-artifact@<PIN-A-COMMIT-SHA>
        with:
          name: dastardly-report
          path: dastardly-report.xml
```

The scan result is a **JUnit XML** file, so CI test-report viewers can show findings and fail the job. Check the action's README for the exact input names.

## 3. Dastardly in GitLab CI (shape, verify details)

Run the published container image in a job and point it at the review app with the documented environment variables (for example a start URL and a report file path). The report is JUnit XML that GitLab shows in the pipeline's test tab. Use a service container or a deployed review environment as the target. Verify the image name, entrypoint and variable names in PortSwigger's docs; they have changed in the past.

```yaml
dastardly:
  stage: dast
  image:
    name: public.ecr.aws/portswigger/dastardly:latest   # pin a version or digest instead of latest
    entrypoint: [""]
  variables:
    BURP_START_URL: "$REVIEW_APP_URL"
    BURP_REPORT_FILE_PATH: "$CI_PROJECT_DIR/dastardly-report.xml"
  script:
    - echo "run the Dastardly entrypoint documented by PortSwigger here"
  artifacts:
    when: always
    reports:
      junit: dastardly-report.xml
```

## 4. Burp Suite DAST

Commercial. You install a scan server (or use the vendor's hosted option, verify), register your sites, set authentication (recorded login sequences), schedule scans and connect CI/CD through its API or integrations. Findings can flow to ticketing and to a findings database ([chapter 14](../../14-vulnerability-management/README.md)). Evaluate it against ZAP on: coverage of your stack, authentication support, false-positive rate, reporting, price and support.

## 5. Choosing

| Need | Pick |
|---|---|
| free, fast gate in CI | Dastardly (or ZAP baseline) |
| free, full-featured, scriptable | ZAP |
| enterprise scale, scheduling, vendor support | Burp Suite DAST (or another commercial DAST) |
| manual exploration | Burp Suite Professional or ZAP desktop |

Related: [lesson 02](../02-zap-dastardly-pipelines-and-schedules.md), [ZAP Docker scans](zap-docker-scans.md), [Automation Framework](zap-automation-framework.md).
