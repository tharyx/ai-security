# 04. Attacks on Pipelines, including Poisoned Pipeline Execution

> **Syllabus:** Introduction to AI in DevOps: "Attacks on Pipelines". Course outcomes: "Analyze attacks on AI deployment pipelines", "Conduct poisoned pipeline attack exercises".
> **Time:** 1.5 hours + lab. Repo companion: [06-ai-devsecops/cicd](../../06-ai-devsecops/cicd/README.md) (`workflow_lint.py` already flags `pull_request_target` with a checkout of PR code).

## Why this matters

If an attacker can make your CI/CD system run their code, they get what the pipeline has: cloud credentials, registry tokens, signing keys, access to private data. In AI projects that can mean model weights, training data and GPU clusters. Pipelines are attractive because they are powerful, trusted and rarely watched as closely as production.

## Understand it

### Common pipeline attack classes

| Class | Idea | AI-flavored example |
|---|---|---|
| **Poisoned Pipeline Execution (PPE)** | Change what the pipeline runs | A PR makes the training or release job run attacker code |
| **Secret theft** | Read tokens from env vars, logs, files | Registry or cloud key printed in a log, or sent out by a step |
| **Dependency attacks** | Typosquatting, dependency confusion, compromised package | A training job installs a malicious package |
| **Poisoned artifacts** | Replace a built artifact | A trojaned model file pushed to the registry |
| **Insufficient flow control** | One person can push code to production | A single account both writes and approves a release |
| **Over-privileged runners and identities** | Runners with admin cloud roles | A job that only trains can also delete buckets |
| **Self-hosted runner compromise** | Persistent runners keep state between jobs | Leftover credentials from a previous job |
| **Third-party actions and plug-ins** | Using unpinned external steps | A moved tag on an action runs new code |
| **Insecure configuration of the AI helpers** | Agents with pipeline tokens read untrusted text | A triage agent obeys an instruction hidden in an issue |

OWASP lists these in the Top 10 CI/CD Security Risks (for example CICD-SEC-1 Insufficient Flow Control Mechanisms, CICD-SEC-4 Poisoned Pipeline Execution, CICD-SEC-5 Insufficient PBAC (pipeline-based access controls), CICD-SEC-6 Insufficient Credential Hygiene, CICD-SEC-3 Dependency Chain Abuse). Verify the current list at https://owasp.org/www-project-top-10-ci-cd-security-risks/.

### Poisoned Pipeline Execution (PPE), OWASP CICD-SEC-4

**Definition:** an attacker who has access to a source repository (or can open a pull request) but **no access to the build environment** manipulates the build process so the pipeline executes malicious code. The attacker borrows the pipeline's identity.

Two forms:

| Form | What the attacker changes | Example |
|---|---|---|
| **Direct PPE (D-PPE)** | The pipeline definition file itself (for example `.github/workflows/*.yml`, `Jenkinsfile`, `.gitlab-ci.yml`), in a branch or PR that the pipeline will run | Add a step that sends `$DEPLOY_TOKEN` to a host the attacker owns |
| **Indirect PPE (I-PPE)** | A file the unchanged pipeline *uses*: `Makefile`, shell scripts, `conftest.py`, test files, build config, `requirements.txt`, a lint config, a Dockerfile | Edit `make test` to run an extra command. The workflow file looks untouched, so a quick review misses it |
| (Public PPE) | The same, from an anonymous fork, when the pipeline is triggered by public PRs | A fork PR to a repo that runs `pull_request_target` and checks out the PR code |

Why it works:

1. The pipeline runs **code that comes from the PR** (workflow file, script, tests).
2. The pipeline runs with **secrets and a powerful token**.
3. Nobody reviews build files as carefully as application code.

The "pwn request" pattern (GitHub Actions): `pull_request_target` runs the *base* workflow with secrets and a write token. If a step then checks out the PR head and runs its scripts, the PR's code runs with those secrets. (GitHub rules change over time: verify in the current GitHub documentation.)

### Anatomy of the lab attack (simulated)

```text
attacker opens PR  ->  PR edits Makefile "test:" target  ->  CI runs "make test"
   ->  runner has DEPLOY_TOKEN in env  ->  PR code sends the value to evil.example
```

In the [poisoned-pipeline lab](labs/poisoned-pipeline/README.md) the token is a canary and the "send" only writes to a log. You will see direct PPE, indirect PPE and the pull_request_target case all steal the canary from a vulnerable setup, and fail against the fixes.

## Defend it

| Control | Hard / Process | Stops |
|---|---|---|
| **Do not run untrusted code with secrets.** PR jobs get no secrets and a read-only token (`permissions: contents: read`) | Hard | D-PPE, I-PPE |
| **Secrets in protected environments** with branch policy and required reviewers; only deploy jobs on the protected branch can use them | Hard | stealing the deploy secret from a PR job |
| **Never check out and run PR code in `pull_request_target`** (or `workflow_run` with untrusted artifacts). Split into an unprivileged build and a separate privileged step that only consumes results | Hard | public PPE |
| **Protect pipeline files:** CODEOWNERS and branch protection for workflows, Makefile, scripts, `conftest.py`, requirements | Process | D-PPE, I-PPE reaching a branch the pipeline trusts |
| **Require approval before workflows run for fork or first-time contributors** | Process | public PPE |
| **Pin actions and dependencies** to commit SHAs and hashes; use a private mirror | Hard | dependency and action attacks |
| **Ephemeral, isolated runners**; no persistent self-hosted runners for public repos | Hard | runner persistence |
| **Short-lived credentials** (OIDC federation to the cloud) instead of stored long-lived keys | Hard | token theft impact |
| **Separate duties:** the author cannot approve their own release | Process | insufficient flow control |
| **Lint the workflows** (actionlint, zizmor, the repo's [workflow_lint.py](../../06-ai-devsecops/cicd/lab/workflow_lint.py)) | Soft | known bad patterns |
| **Log and alert** on pipeline definition changes and unusual secret use | Process | detection |
| **Sign artifacts and verify before deploy** | Hard | poisoned artifacts |

What does NOT work alone: reviewing only the workflow file (indirect PPE avoids it), trusting "only collaborators can open PRs" (accounts get compromised), and masking secrets in logs (a step can still send them elsewhere).

## Hands-on

[labs/poisoned-pipeline](labs/poisoned-pipeline/README.md): three attacks, five fixes, and a linter. Then run the real linters on a workflow of your own, and read the [06 cicd lesson](../../06-ai-devsecops/cicd/README.md).

## Real-world scenarios

1. **Training job with a cloud admin role.** A PR changes `requirements.txt` to add a package. The training pipeline installs it and the package sends cloud credentials out. *Fix:* hash-pinned lock files, private index, a training role with only the data and registry rights it needs, no network egress except an allowlist.
2. **AI review bot reads PR text.** The PR description contains hidden instructions that make the bot approve and merge. *Fix:* bots cannot merge; human approval; treat PR text as untrusted for the bot.
3. **Release job on a self-hosted GPU runner.** A previous job left a token in the workspace. *Fix:* ephemeral runners, clean workspace, short-lived credentials.

## Interview Q&A

<details><summary><b>Q1. What is Poisoned Pipeline Execution?</b></summary>
OWASP CICD-SEC-4. An attacker with repository access (or PR access) but no build-system access changes what the pipeline runs, so the pipeline executes their code with its credentials and permissions.
</details>

<details><summary><b>Q2. Explain direct versus indirect PPE.</b></summary>
Direct: the attacker edits the pipeline definition file. Indirect: the pipeline definition is untouched, but the attacker edits a file it runs, such as a Makefile, script, test or dependency list. Indirect is harder to spot in review.
</details>

<details><summary><b>Q3. Why is pull_request_target dangerous?</b></summary>
It runs the base repository's workflow with secrets and a write token even for fork PRs. If the job checks out and runs the PR's code, untrusted code runs with those secrets. Avoid checking out PR code there, or split the workflow.
</details>

<details><summary><b>Q4. Name three controls that stop PPE even if a PR is malicious.</b></summary>
No secrets in PR jobs, secrets only in protected environments on the protected branch, and a least-privilege read-only token. Process controls such as code-owner review of pipeline files and approval for fork workflows add a second layer.
</details>

## References

- OWASP Top 10 CI/CD Security Risks, CICD-SEC-4: https://owasp.org/www-project-top-10-ci-cd-security-risks/
- GitHub documentation on security hardening for GitHub Actions and on `pull_request_target` (verify current behavior)
- Repo: [06 cicd](../../06-ai-devsecops/cicd/README.md), [workflow_lint.py](../../06-ai-devsecops/cicd/lab/workflow_lint.py)
