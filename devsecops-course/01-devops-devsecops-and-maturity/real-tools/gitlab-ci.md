# GitLab CI/CD: first pipeline with security jobs (real tool, hedged)

> **Status: hedged outline, not tested by the repo author.** GitLab changes often. Verify keywords and menus at <https://docs.gitlab.com/ee/ci/yaml/>. Tests in this repo never need GitLab.

**Offline twins (tested):** [pipeline-design](../labs/pipeline-design/README.md) (design rules), [csse ch1 how-cicd-works](../../../csse-course/ch1-introduction-to-supply-chain-security/labs/how-cicd-works/README.md) (runner behaviour). Existing guide with runner and stage basics: [csse ch1 GitLab quickstart](../../../csse-course/ch1-introduction-to-supply-chain-security/real-tools/gitlab-ci-quickstart.md). The hardened version is in [chapter 2](../../02-tools-pipelines-and-secure-sdlc/real-tools/gitlab-ci.md).

## Where to run it

- **Course lab:** the browser lab already has GitLab and a runner.
- **GitLab.com free tier:** fine for practice. Compute minutes are limited, and some security features (for example the built-in scanner templates, protected-environment approvals) depend on the tier. Check the pricing and feature pages before relying on one.
- **Self-managed GitLab:** needs several GB of RAM. Not recommended next to other heavy tools on a 16 GB laptop.

## A first pipeline: build, test, one scan

```yaml
stages: [test, build]

default:
  image: node:20          # pin an exact tag or digest in real projects

secrets-scan:
  stage: test
  image: zricethezav/gitleaks:latest   # example only: pin a version
  script: [gitleaks detect --source . --redact]

audit:
  stage: test
  script: [npm ci --ignore-scripts, npm audit --audit-level=high]

build:
  stage: build
  script: [npm run build]
  artifacts: {paths: [dist/]}
```

(`latest` above is a deliberate shortcut for a first look; chapter 2 shows why you pin.)

## Things to try

1. Push the file and watch the pipeline graph. Break `npm audit` on purpose (add an old dependency) and see the later stage get skipped.
2. Add `allow_failure: true` to the audit job and compare the pipeline status. This is how a gate quietly turns into a report.
3. Protect your default branch (Settings, Repository) and require the pipeline to pass before merge.
4. Add a manual production deploy job with `when: manual` inside a protected environment (continuous delivery).

## Security notes

- Prefer ephemeral Docker-executor runners; never mount the Docker socket on runners that build untrusted code.
- Mask and protect CI variables; protected variables are only exposed to protected branches.
- GitLab ships scanner templates (SAST, dependency scanning, secret detection, DAST, container scanning). Which ones are free and which need a paid tier changes: **verify on the GitLab docs**.
