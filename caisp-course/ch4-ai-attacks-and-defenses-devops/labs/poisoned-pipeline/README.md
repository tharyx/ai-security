# Lab: Poisoned Pipeline Execution (PPE) Exercise

**Course outcome:** "Conduct poisoned pipeline attack exercises". You simulate a CI runner, poison it three ways with a harmless payload, then fix the setup.

**Time:** 45-60 minutes. Offline. **Nothing real runs.** `ci_sim.py` parses workflow YAML but sends every `run:` line to a tiny fake shell. The attacker command `exfil NAME host` only appends the value to a log. The "secret" is a canary from `make_canary()`.

```text
.venv/Scripts/python caisp-course/ch4-ai-attacks-and-defenses-devops/labs/poisoned-pipeline/demo.py
.venv/Scripts/python -m pytest caisp-course/ch4-ai-attacks-and-defenses-devops/labs/poisoned-pipeline -v
```

## What PPE is

An attacker who can open a pull request (or push to a branch) gets the CI system to run their code with the pipeline's power. OWASP lists it as CICD-SEC-4 in the Top 10 CI/CD Security Risks (verify the current list at owasp.org).

| Form | The PR changes | Example here |
|---|---|---|
| Direct (D-PPE) | the pipeline file itself | add a step to `.github/workflows/ci.yml` |
| Indirect (I-PPE) | a file the unchanged pipeline runs | edit the `Makefile`, `scripts/test.sh`, `conftest.py` |
| Public / "pwn request" | a fork PR plus a privileged trigger | `pull_request_target` that checks out the PR head |

For AI projects the pipeline holds model-registry tokens, cloud credentials and signing keys, so the prize is large (see [chapter 4 lesson 04](../../04-pipeline-attacks-and-ppe.md)).

## Expected output

```text
Attack                                  Vulnerable CI         Secure CI
1 direct PPE (edit ci.yml)              SECRET STOLEN         safe  (protected pipeline file changed (.github/workflows/ci.yml): code-owner review required)
2 indirect PPE (edit Makefile)          SECRET STOLEN         safe  (protected pipeline file changed (Makefile): code-owner review required)
3 pull_request_target + fork script     SECRET STOLEN         safe  (protected pipeline file changed (scripts/test.sh): code-owner review required)

Linter on vulnerable-pr-target.yml:
   PPE-1 eval: pull_request_target checks out untrusted PR code
   PPE-3 workflow has no explicit least-privilege permissions
```

## Setups

| File | Verdict | Why |
|---|---|---|
| `workflows/vulnerable-ci.yml` | vulnerable | a deploy secret is in a job that runs PR code, and the token is write-all |
| `workflows/vulnerable-pr-target.yml` | vulnerable | `pull_request_target` plus checkout of the PR head SHA |
| `workflows/secure-ci.yml` | secure | PR job has no secrets and `contents: read`; deploy is a separate job in a protected `production` environment |
| `workflows/secure-pr-target.yml` | secure | only labels; never checks out or runs PR code |

## The fixes (each one has a test)

| Control | Type | Test shows |
|---|---|---|
| Secrets live in a protected **environment** that only a push to the main branch can use | Hard | holds even when every other control is off, and when the attacker adds `environment:` to their own workflow copy |
| Do not check out and run PR code in a privileged trigger | Hard | the linter flags PPE-1 on the vulnerable file |
| Least-privilege token (`permissions: contents: read`) | Hard | token reads `read` |
| **Protected pipeline files** (code owners must review changes to workflows, Makefile, scripts, conftest) | Process | the poisoned PR is blocked until a code owner reviews |
| Approval before fork PRs run workflows | Process | the run is blocked until a maintainer approves. A careless approval still runs the code, but with no secrets |
| Pin actions to full commit SHAs, review third-party actions | Process | not simulated, see the 06 linter |

## Exercises

1. Add a second indirect vector: a `requirements.txt` that points to an attacker's package index. What would you add to `_exec`? What is the real-world fix? (Hash-pinned lock files, a private index.)
2. The vulnerable job leaks to a **same-repo** branch PR but not to a fork PR with `pull_request`. Why do insiders and compromised accounts matter anyway?
3. Run the real linters on your own workflow files: `actionlint` and `zizmor`. Compare with the repo's [workflow_lint.py](../../../../06-ai-devsecops/cicd/lab/workflow_lint.py).
4. Real GitHub behavior changes. Check the current rules for `pull_request_target`, fork approval and environment protection in the GitHub documentation before relying on this model.

## Related

- Course lesson: [04 Attacks on pipelines and PPE](../../04-pipeline-attacks-and-ppe.md)
- Repo: [06-ai-devsecops/cicd](../../../../06-ai-devsecops/cicd/README.md) (workflow_lint with the `pull_request_target` rule, release gate, deploy approval)
