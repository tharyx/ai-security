# GitHub Actions: running and hardening the secure workflow (real tool, hedged)

> **Status: hedged outline, not tested by the repo author.** Verify at <https://docs.github.com/actions>. Repo tests never need GitHub.

**Offline twin (tested):** [ci-pipeline-multi-platform](../labs/ci-pipeline-multi-platform/README.md) validates [fixtures/github-actions.yml](../labs/ci-pipeline-multi-platform/fixtures/github-actions.yml). Basics: [chapter 1 guide](../../01-devops-devsecops-and-maturity/real-tools/github-actions.md).

## Run the fixture

1. Create a test repository with a small Node app.
2. Copy the fixture to `.github/workflows/secure-pipeline.yml`.
3. The `uses:` lines contain **fake** 40-character values. Replace each with the real commit SHA of a release you reviewed (look it up on the action's releases page) and keep the version as a trailing comment.
4. Open a pull request. Mark the jobs as required checks in branch protection or a ruleset.

## Pinning actions to SHAs

A tag like `@v4` can be moved by the action's owner (or an attacker who takes over the repository). A full commit SHA cannot. Options to keep pins fresh:

- **Dependabot** for the `github-actions` ecosystem can open pull requests that update SHA pins (verify the current behaviour and configuration).
- Community tools exist that rewrite tags to SHAs and lint workflows (for example `pinact`, `actionlint`, `zizmor`): **check each one's maintenance status** before adopting.
- Organisation settings can **require** SHA-pinned actions (availability depends on plan; verify).

## Least-privilege token checklist

| Item | Example |
|---|---|
| Top-level default | `permissions: {contents: read}` |
| Extra rights per job only | deploy job: `id-token: write` for OIDC |
| No `write-all` | Search for it in reviews |
| Checkout without persisting the token | `persist-credentials: false` |
| Environments with required reviewers | Production deploys need an approval |
| Secrets scoped to environments | Production secrets only visible to the production environment |
| Careful with `pull_request_target` and `workflow_run` | They run with secrets: never check out and run untrusted code with them |

## Notes

- GitHub-hosted runners are ephemeral VMs: a good default. Self-hosted runners on persistent machines need extra care, especially for public repositories.
- Code scanning (CodeQL), secret scanning push protection and Dependabot alerts exist on GitHub; their availability depends on repository visibility and plan. **Verify before you promise them to a team.**
