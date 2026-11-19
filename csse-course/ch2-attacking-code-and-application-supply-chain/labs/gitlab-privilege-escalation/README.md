# Lab: GitLab privilege escalation

**Course exercise:** "GitLab privilege escalation". Lessons: [04 section 7](../../04-attacks-on-build-and-cicd-systems.md#7-gitlab-ci-and-privilege-escalation-concepts), [02 section 2](../../02-attacks-on-scm-systems.md#2-git-servers-leaking-confidential-information). Real tool guide: [real-tools/gitlab.md](../../real-tools/gitlab.md). Related: [06 cicd](../../../../06-ai-devsecops/cicd/README.md), [CAISP ch4 poisoned-pipeline](../../../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/poisoned-pipeline/README.md).

**Time:** 45 minutes. **Safety:** this is a SIMULATED role model, not GitLab. Real GitLab rules differ by version and edition (verify at docs.gitlab.com). Secrets are FAKE strings.

## What is modelled

Roles Guest, Reporter, Developer, Maintainer and Owner. A project with protected branches, CI/CD variables (`protected`, `masked`), pipeline trigger tokens and a CI job token allowlist. `misconfigured_project()` has four mistakes:

| Mistake | Escalation |
|---|---|
| `DEPLOY_TOKEN` is not a protected variable | A Developer pushes a branch with a pipeline that prints the environment and reads the token |
| `main` is protected but **Developers may push** | A Developer edits the CI file that runs on `main`, where protected variables exist |
| A trigger token is usable by Developers on protected refs | A Developer triggers a pipeline on `main` and gets protected variables |
| Job token allowlist is off | Jobs in other projects can reach this project with their job token |

`audit()` lists them; `harden()` fixes them. Tests prove the attacks work first and fail after hardening, and that normal work still works.

## Run

```text
.venv/Scripts/python csse-course/ch2-attacking-code-and-application-supply-chain/labs/gitlab-privilege-escalation/demo.py
.venv/Scripts/python -m pytest csse-course/ch2-attacking-code-and-application-supply-chain/labs/gitlab-privilege-escalation
```

## Expected output (real run)

```text
== Attacks as a Developer (dave) ==
own branch, leaked vars:    ['APP_ENV', 'DEPLOY_TOKEN']
push to main allowed:       True
trigger token on main:      ['APP_ENV', 'DEPLOY_TOKEN', 'SIGNING_KEY']
== Audit ==
[high  ] VAR-UNPROTECTED      secret-like variable DEPLOY_TOKEN is not protected
[low   ] VAR-UNMASKED         SIGNING_KEY is protected but not masked in logs
[high  ] BRANCH-DEV-PUSH      protected branch main lets Developers push
[medium] BRANCH-DEV-MERGE     protected branch main lets Developers merge without review
[high  ] TRIGGER-LOW-ROLE     trigger token #0 usable by role level 30 on protected refs
[medium] JOBTOKEN-OPEN        CI job token allowlist is off: other projects' jobs can reach this project
== After harden() ==
findings left:              0
dev push to main allowed:   False
dev leaked vars on branch:  ['APP_ENV']
dev trigger on main:        []
```

## Break it yourself

1. Mark only `SIGNING_KEY` as protected and leave `main` open to Developers. Is the key safe? (No: the Developer simply pushes to `main`.)
2. Set `masked=True` on the unprotected `DEPLOY_TOKEN`. Does that stop the branch attack? (No. Masking only hides the value in logs, and a job can still transform and print it. The value is still in the job environment.)
3. Write a new audit rule: "an Owner token stored as a variable". What severity?

## Limits

Real GitLab has more (group inheritance, deploy tokens, runners shared or protected, environment rules, merge request approvals, scoped job tokens). Treat the model as a checklist generator, then check your instance with [real-tools/gitlab.md](../../real-tools/gitlab.md).
