# Lab: Creating a simple CI/CD pipeline (simulated GitLab-style runner)

**Course items:** "Creating a Simple CI/CD Pipeline", "Working With GitLab CI/CD", "Continuous Integration and Continuous Deployment". Lesson: [03 sections 2 and 3](../../03-api-security-at-scale-and-cicd.md#2-creating-a-simple-cicd-pipeline). Related labs in the repo: [devsecops ch02 complete-cicd-pipeline](../../../../devsecops-course/02-tools-pipelines-and-secure-sdlc/labs/complete-cicd-pipeline/README.md), [csse ch1 gitlab-ci-stages](../../../../csse-course/ch1-introduction-to-supply-chain-security/labs/gitlab-ci-stages/README.md).

**Time:** 40 minutes. **Tests:** 8, all offline. **Safety:** no shell, no network. Script steps are Python functions; the deploy token is FAKE. Only test systems you own or have written permission to test.

## Goal

Build and run a pipeline for the orders API with **build → test → package → deploy**, and see the CI features that matter for security behave correctly: stage gating, `allow_failure`, artifacts passed only along `needs` (with digests), manual approval for production, branch rules, **protected** and **masked** variables, and validation of the pipeline file itself.

## Concept

[pipeline.py](pipeline.py) reads [fixtures/pipeline.json](fixtures/pipeline.json), a simplified `.gitlab-ci.yml` written as JSON. The GitLab equivalent looks like this (sketch, verify keywords in the GitLab CI reference):

```yaml
stages: [build, test, package, deploy]
build:      {stage: build,   script: [make build], artifacts: {paths: [dist/orders-api.tar]}}
unit-tests: {stage: test,    script: [pytest],     needs: [build]}
lint:       {stage: test,    script: [ruff check .], allow_failure: true}
package:    {stage: package, script: [docker build ...], needs: [build, unit-tests]}
deploy-prod:
  stage: deploy
  script: [./deploy.sh]
  needs: [package]
  when: manual
  rules: [{if: '$CI_COMMIT_BRANCH == "main"'}]
  environment: production
# DEPLOY_TOKEN is a CI/CD variable marked Protected and Masked in project settings
```

## Run

```text
.venv/Scripts/python appsec-course/16-api-security-the-devsecops-way/labs/simple-cicd-pipeline/demo.py
.venv/Scripts/python -m pytest appsec-course/16-api-security-the-devsecops-way/labs/simple-cicd-pipeline -v
```

## Expected output (real run)

```text
1. main branch, no approval yet
build      build                success
test       unit-tests           success
test       lint                 failed (allowed)
package    package              success
deploy     deploy-prod          manual
pipeline: blocked (manual)

2. main branch, deploy-prod approved
build      build                success
test       unit-tests           success
test       lint                 failed (allowed)
package    package              success
deploy     deploy-prod          success
pipeline: passed
   build artifact digest: {'dist/orders-api.tar': '254d4c767976ac2e5e6f6f0d3687e20f6b3615c63c5d20742a40f11e368d0d19'}
   deploy log: ['deploying with token [MASKED]']

3. feature branch with a failing unit test
build      build                success
test       unit-tests           failed
test       lint                 failed (allowed)
package    package              skipped
deploy     deploy-prod          not-run (rules)
pipeline: failed

4. invalid definitions are rejected before anything runs
   - build: needs 'deploy' from a later stage
   - build: unknown script step 'curl-bash'
   - cycle in needs at 'deploy'
```

## Steps

1. Run the demo and read the four scenarios.
2. Remove `"build"` from `package.needs` and run again: the artifact never arrives. Explicit `needs` is also a security boundary: jobs get only what they declare.
3. Remove `only_branches` from `deploy-prod` and run on a feature branch with approval. The deploy fails because the **protected** variable is not exposed there. Explain why that matters for merge requests from forks.
4. Look at the deploy log: the token was printed, but masking replaced it. Why is masking a last line of defense and not a control? (Base64 or splitting the value defeats it.)
5. Add a `curl-bash` step and see the validator reject it. In real CI, review `.gitlab-ci.yml` changes like code (CODEOWNERS).

## What you learned

- A pipeline is code with privileges. Stage gates, explicit artifacts, protected branches and variables, and manual approvals are its access controls.
- Record artifact digests so later stages (and deployment) use exactly what was built and tested.
- Validate the pipeline definition itself before running anything.

## Run the real tool (hedged)

- GitLab: create a project, add `.gitlab-ci.yml`, set `DEPLOY_TOKEN` as **Protected** and **Masked**, protect `main`, and use **environments** with required approvals. Validate with the CI Lint tool in the UI or API. See [devsecops ch02 real-tools/gitlab-ci.md](../../../../devsecops-course/02-tools-pipelines-and-secure-sdlc/real-tools/gitlab-ci.md).
- GitHub Actions equivalents: `needs`, `environment` protection rules, encrypted secrets, OIDC to cloud instead of stored keys.
