# Lab: Embedding Trivy scanning in GitLab CI

**Course exercise:** "Embedding Trivy Scanning in GitLab CI" [CCSE 4]. Lesson: [04 section 4](../../04-trust-registries-and-cicd.md#4-devops-cicd-integration).

**Time:** 35 minutes. **Safety:** YAML is parsed, never executed; no GitLab runner needed.

**Link, do not repeat:** the pipeline basics are in [csse ch1](../../../../csse-course/ch1-introduction-to-supply-chain-security/README.md) (runner, stages) and the repo's release gate is in [06-ai-devsecops/cicd](../../../../06-ai-devsecops/cicd/README.md).

## What it does

[ci_validate.py](ci_validate.py) checks that a `.gitlab-ci.yml` really enforces a Trivy gate. The classic ways to fake it:

| Smell | Why it breaks the gate |
|---|---|
| no `--exit-code 1` | Trivy exits 0 whatever it finds |
| `\|\| true` | swallows the exit code |
| `allow_failure: true` | job fails, pipeline stays green |
| image `:latest` | the scanner itself can change under you |
| no artifacts / `when: on_success` | no report exactly when you need it |
| release job does not `needs` the scan | deploy can run in parallel with the scan |

Compare [gitlab-ci.good.yml](fixtures/gitlab-ci.good.yml) with [gitlab-ci.bad.yml](fixtures/gitlab-ci.bad.yml).

## Steps

```text
.venv/Scripts/python devsecops-course/11-defending-containers-at-scale/labs/trivy-in-gitlab-ci/demo.py
.venv/Scripts/python -m pytest devsecops-course/11-defending-containers-at-scale/labs/trivy-in-gitlab-ci -v
```

1. Run the validator on both files.
2. Fix the bad file until it prints 0 problems.
3. Add a second job that scans the Dockerfile with `trivy config` and extend the validator to accept it.

## Expected output (real run)

```text
== gitlab-ci.good.yml: 0 problem(s)
== gitlab-ci.bad.yml: 7 problem(s)
  - trivy-scan: image aquasec/trivy:latest is not pinned (latest)
  - trivy-scan: no --exit-code 1, so findings never fail the job
  - trivy-scan: no --severity threshold
  - trivy-scan: '|| true' swallows the exit code
  - trivy-scan: allow_failure: true makes the gate advisory
  - trivy-scan: no artifacts, nobody can read the report
  - trivy-scan: stage scan is not declared
```

## Run the real tool (hedged)

GitLab also has a built-in Container Scanning template (it can use Trivy or Grype under the hood; which analyzer is the default depends on the GitLab version: verify in the GitLab docs). Feature tiers differ between GitLab editions. Pin the scanner image and cache its database directory. See [real-tools](../../real-tools/README.md).
