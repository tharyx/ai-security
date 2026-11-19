# Lab: One secure pipeline, five CI systems

**Course exercise:** "Building a CI Pipeline using Gitlab CI/Jenkins/Travis and Gitlab/Github Actions". Lesson: [01 section 4](../../01-tools-of-the-trade.md#4-ci-systems-gitlab-ci-github-actions-circleci-jenkins-travis) · **Real tools:** [GitLab](../../real-tools/gitlab-ci.md), [GitHub Actions](../../real-tools/github-actions.md), [Jenkins](../../real-tools/jenkins.md) · **Time:** 2 hours · **Safety:** offline; the fixtures are never run, and the 40-character "SHAs" and the encrypted placeholder are fake.

## What is in it

`fixtures/` holds **the same secure pipeline** (secrets scan, SCA, SAST, build, image scan, DAST, deploy) written for five systems:

| File | System | Note |
|---|---|---|
| `gitlab-ci.yml` | GitLab CI | Kaniko build (no Docker socket), service container for DAST, OIDC `id_tokens` on deploy |
| `github-actions.yml` | GitHub Actions | Top-level `permissions: contents: read`, actions pinned to SHAs, `needs:` chain |
| `Jenkinsfile` | Jenkins | `agent none`, Docker agent per stage, credentials bound only in Deploy |
| `circleci-config.yml` | CircleCI | `requires:` chain, deploy uses a restricted `context` and a branch filter |
| `travis.yml` | Travis CI (**legacy**) | Encrypted `secure:` variable, deploy only `if: branch = main` |

`ci_validate.py` reads any of them, extracts the steps in execution order, maps each step to a canonical stage by the tool it runs, and checks:

| Check | Rules |
|---|---|
| **stages** | All seven stages present. Order: secrets, SCA and SAST before build; build before image scan and DAST; image scan and DAST before deploy |
| **pinning** | GitHub `uses:` must be a full 40-hex commit SHA (a tag, branch or short SHA is an error); container images need an exact tag or digest (`latest` or no tag is an error); CircleCI orbs need an exact version |
| **secrets** | No token-shaped strings (GitHub, AWS, Slack, GitLab, private key headers) and no literal values assigned to keys like `password`, `token`, `secret`, `api_key`. References (`$VAR`, `${{ secrets.X }}`, `credentials('id')`) are fine |
| **privilege** | No `docker.sock` or privileged containers; GitHub: top-level `permissions` present and read-only, no `write-all`, job-level `write` only for `id-token`; GitLab: no personal access tokens; Jenkins: credentials only in the deploy stage; CircleCI: deploy has a context; Travis: deploy has a branch condition |

## Steps

```text
.venv/Scripts/python devsecops-course/02-tools-pipelines-and-secure-sdlc/labs/ci-pipeline-multi-platform/demo.py
.venv/Scripts/python -m pytest devsecops-course/02-tools-pipelines-and-secure-sdlc/labs/ci-pipeline-multi-platform -v
```

1. Read the five fixtures side by side. Find the same job (`sca`) in each. What is the equivalent of `needs:` in each system?
2. Run the demo. All five should pass with 7/7 stages.
3. In `github-actions.yml` change one `uses:` to `@v4`. Which message appears and why is a tag weaker than a SHA?
4. Change `semgrep/semgrep:1.56.0` to `semgrep/semgrep:latest` in the GitLab file. What does the validator say?
5. Add `DB_PASSWORD: hunter2-example` somewhere. Which check fires? Now replace it by `${{ secrets.DB_PASSWORD }}`. Why does it pass?
6. Change `permissions:` to `write-all`. Then change it back and add `packages: write` to a job. Which one is allowed (`id-token: write`) and which is not?
7. Stretch: add a sixth system (Azure Pipelines `azure-pipelines.yml`) with an adapter in `ci_validate.py` and a fixture.

## Expected output (real run)

```text
== the same secure pipeline in five syntaxes
  gitlab-ci.yml        gitlab    stages=7/7 issues=0 ok=True
  github-actions.yml   github    stages=7/7 issues=0 ok=True
  Jenkinsfile          jenkins   stages=7/7 issues=0 ok=True
  circleci-config.yml  circleci  stages=7/7 issues=0 ok=True
  travis.yml           travis    stages=7/7 issues=0 ok=True

== damaged GitHub workflow (tag instead of SHA, write-all, literal password, no DAST)
  error    stages     required stage 'dast' not found
  error    pinning    secrets-scan: 'actions/checkout@v4' is not pinned to a commit SHA
  error    secrets    literal value assigned to 'DB_PASSWORD'
  error    privilege  permissions: write-all
```

## Run the real tools

Hedged guides: [GitLab](../../real-tools/gitlab-ci.md), [GitHub Actions](../../real-tools/github-actions.md), [Jenkins](../../real-tools/jenkins.md). Dedicated linters exist for real workflows (for example `actionlint` for GitHub Actions, GitLab's CI Lint, Jenkins' declarative linter, CircleCI's config validation): **verify their current status and usage**. Use them in addition to this teaching validator.

## Limits

- The validator is a **teaching linter**. It uses regular expressions for the Jenkinsfile and simple heuristics (for example, a `docker run` image inside a shell line is not pinned-checked). Real tools understand far more.
- Pinning an image by tag is weaker than by digest; the validator accepts both.
- It does not check that the tools actually work, that thresholds are right, or that jobs really block.
