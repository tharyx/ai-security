# GitLab CI/CD quickstart (real tool, hedged)

> **Status: hedged outline, not tested by the repo author.** GitLab changes often. Verify keywords and menus at <https://docs.gitlab.com/ee/ci/>. Tests in this repo never need GitLab.

**Course exercises:** Working with Gitlab CI/CD; Understanding Stages; Continuous Deployment.
**Offline twins (tested):** [how-cicd-works](../labs/how-cicd-works/README.md), [gitlab-ci-stages](../labs/gitlab-ci-stages/README.md), [continuous-deployment](../labs/continuous-deployment/README.md).

## Where to run it

- **Course lab:** the browser lab already has a GitLab and a runner. Use it for the graded exercises.
- **GitLab.com free tier (your own account):** good for practice. Free tiers have compute-minute limits and some features (for example certain security scanners and protected-environment approvals) may need a paid tier. Check the pricing and feature page before you rely on a feature.
- **Self-managed GitLab:** heavy (several GB RAM). Not recommended on a 16 GB laptop next to other tools.

## Runners

A **runner** is the program that executes jobs. Types: shared (provided by the platform), group/project runners (yours), and executors such as Docker or shell. Security points:

- Prefer the **Docker executor** with ephemeral containers. A shell executor on a persistent machine can leak files and secrets between jobs.
- **Never mount the Docker socket** or use privileged mode on a runner that builds untrusted code.
- Tag runners so sensitive jobs run only on runners you control.
- Register runners with the current authentication-token workflow described in the docs (the older registration tokens are being phased out; verify).

## Step by step

1. Create a **private** project. Add a file `.gitlab-ci.yml` at the root.
2. Start from the solution of the offline stages lab, replacing the `echo` lines with harmless real commands.
3. Commit. Open **Build > Pipelines** to see stages as columns and jobs inside them.
4. Add a `rules:` condition so the deploy job runs only on the default branch, with `when: manual`.
5. Add a **protected branch** (Settings > Repository) and a **protected environment** for production if your tier supports required approvals.
6. Add GitLab's built-in security templates (for example SAST and Secret Detection via `include: - template: ...`) and read the findings. Which templates exist, and in which tier, changes: verify.

## Secrets: never put them in YAML

- Do not write tokens, passwords or keys in `.gitlab-ci.yml` or in the repository. It would be in Git history for ever.
- Use **Settings > CI/CD > Variables**: mark them **Masked** (hidden in logs) and **Protected** (only on protected branches and tags). Masking is a best effort; printing a variable in a transformed way can still leak it.
- Better: use **short-lived credentials** with OIDC (`id_tokens`) toward your cloud, or a secrets manager (HashiCorp Vault and similar), instead of stored keys.
- Pipelines for **forks and merge requests from outsiders** should not receive secrets.
- If a secret was committed: revoke and rotate it first, then clean history.

## Conceptual GitLab privilege-escalation points (no exploits)

- A user with a **Maintainer** role can change protected-branch settings and CI/CD variables; Developers can edit the pipeline file on unprotected branches. Check who has which role.
- **Project and group access tokens** and **deploy tokens** can outlive the person who made them and often have wide scope. Inventory and expire them.
- A pipeline job gets a **job token** (`CI_JOB_TOKEN`); limit which projects can use it (allowlist).
- Anyone who can edit the pipeline file on a branch that can read protected variables controls those secrets: keep protected variables on protected branches only.

## Practice questions

1. Which job would you protect first, and how?
2. How would you prove which commit a deployed artifact came from? (Think: provenance, digest.)
3. What stops a developer from approving their own production deploy?

## References

- <https://docs.gitlab.com/ee/ci/yaml/> · <https://docs.gitlab.com/ee/ci/variables/> · <https://docs.gitlab.com/ee/ci/environments/protected_environments.html> · <https://docs.gitlab.com/ee/ci/secrets/id_token_authentication.html> (verify links).
