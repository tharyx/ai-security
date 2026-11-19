# GitHub Actions: first workflow with security jobs (real tool, hedged)

> **Status: hedged outline, not tested by the repo author.** Verify syntax at <https://docs.github.com/actions>. Tests in this repo never need GitHub.

**Offline twins (tested):** [pipeline-design](../labs/pipeline-design/README.md). The hardened, validated workflow is in [chapter 2](../../02-tools-pipelines-and-secure-sdlc/real-tools/github-actions.md) and its [fixture](../../02-tools-pipelines-and-secure-sdlc/labs/ci-pipeline-multi-platform/fixtures/github-actions.yml).

## Concepts mapped from what you know

| Idea | GitLab CI | GitHub Actions |
|---|---|---|
| Pipeline file | `.gitlab-ci.yml` | `.github/workflows/*.yml` |
| Stage ordering | `stages:` list | `needs:` between jobs |
| Reusable step | include / template | an *action* (`uses: owner/repo@ref`) or a reusable workflow |
| Runner | runner | runner (GitHub-hosted or self-hosted) |
| Deploy approval | protected environment | environment with required reviewers |
| Secrets | CI/CD variables | repository, environment and organisation secrets |

## A first workflow

```yaml
name: ci
on: [pull_request]
permissions:
  contents: read          # start from the least privilege

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<full commit SHA>   # pin to a SHA, keep "# v4" as a comment
        with: {persist-credentials: false}
      - run: npm ci --ignore-scripts
      - run: npm audit --audit-level=high
```

## Try it

1. Create the file in a test repository, open a pull request and watch the checks.
2. In repository settings, require the `test` check to pass before merging.
3. Look at the **Security** tab: code scanning (CodeQL), Dependabot alerts and secret scanning exist on GitHub, and their availability depends on repository type and plan. **Verify what your plan includes.**

## Security notes

- Third-party actions run with your token and secrets. Pin to full commit SHAs and review updates (Dependabot can propose SHA bumps).
- Never use `pull_request_target` with a checkout of untrusted pull request code unless you know exactly why (classic "pwn request").
- Set `permissions:` at the top of every workflow; grant extra rights per job only.
- Prefer OIDC to cloud roles over long-lived cloud keys in secrets.
