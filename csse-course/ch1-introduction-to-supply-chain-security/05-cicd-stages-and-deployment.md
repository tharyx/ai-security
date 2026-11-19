# 05. CI/CD, GitLab stages, continuous deployment, and the Equifax hack

> **Chapter 1 · Time:** 3 hours · **You will:** explain how a pipeline runs, read a `.gitlab-ci.yml`, understand stages and gates, and explain how Equifax happened as an inventory and patching failure.
> **Labs:** [how-cicd-works](labs/how-cicd-works/README.md), [gitlab-ci-stages](labs/gitlab-ci-stages/README.md), [continuous-deployment](labs/continuous-deployment/README.md), [equifax-case-study](labs/equifax-case-study/README.md). **Real tool:** [GitLab quickstart](real-tools/gitlab-ci-quickstart.md).
> Verify GitLab keywords at <https://docs.gitlab.com/ee/ci/yaml/>.

## 1. Why this matters

The pipeline is the factory. If you cannot read a pipeline file, you cannot threat-model it. This lesson covers the course's hands-on topics for chapter 1.

## 2. Understand it

### 2.1 Learn how to use the browser-based lab environment

Open the lab, find GitLab and the terminal, create a project, and run a pipeline once. Reset the lab if you break it. See [lesson 00](00-how-to-approach-this-course.md#23-course-lab-environment).

### 2.2 How CI/CD works

1. A developer pushes a commit or opens a merge request.
2. GitLab reads `.gitlab-ci.yml` and creates a **pipeline**.
3. The pipeline is split into **stages** that run in order. Each stage holds **jobs**.
4. A job is picked up by a **runner** (a machine or container) that runs the job's `script` lines.
5. Jobs can save **artifacts** (files) that later jobs download.
6. If any required job fails, the pipeline stops (later stages do not run).
7. Deploy jobs push the result to an environment.

**CI** (continuous integration) = build and test on every change. **Continuous delivery** = every good build is ready to release, with a human pressing the button. **Continuous deployment** = every good build is released automatically (usually with strong gates). The lab [how-cicd-works](labs/how-cicd-works/README.md) simulates this.

### 2.3 Working with GitLab CI/CD

Key pieces of `.gitlab-ci.yml`:

| Keyword | Meaning | Security note |
|---|---|---|
| `stages` | Order of stages | A scan stage placed after deploy protects nothing |
| `script` | Commands a job runs | Untrusted input (branch names, MR titles) must not be pasted into shell |
| `rules` | When the job runs (branch, tag, MR) | Use to keep deploy jobs on protected branches |
| `needs` | Start when named jobs finish, skipping the stage order | Faster, but check the gate jobs are still required |
| `artifacts` | Files passed on or downloaded | Do not store secrets in artifacts |
| `variables` | Environment variables | Secrets belong in masked, protected CI/CD variables, never in the YAML |
| `environment` | A named deployment target | Protect production |
| `when: manual` | A person must start the job | A manual gate |
| `allow_failure` | A failure does not stop the pipeline | A security scan with `allow_failure: true` is advisory only |

**Runners:** shared runners are used by many projects; self-hosted runners may persist state between jobs. Prefer ephemeral, isolated runners for sensitive projects.

### 2.4 Understanding stages in CI/CD pipelines

Common order: `build` → `test` → `security` (SAST, secret scan, dependency scan, container scan) → `package/sign` → `deploy-staging` → `deploy-prod`. Rules of thumb: fail fast (cheap checks first), run security **before** deploy, and make scans **blocking** for serious findings. The lab [gitlab-ci-stages](labs/gitlab-ci-stages/README.md) has you add a test stage, a security stage and a manual deploy gate.

### 2.5 Continuous deployment

Deploy the **same artifact** (same digest) to dev, then staging, then prod. Do not rebuild per environment. Protect production: restrict to protected branches, require an approval from someone other than the author, use short-lived credentials (OIDC), run health checks, and be able to roll back quickly. The lab [continuous-deployment](labs/continuous-deployment/README.md) models this; compare with [deploy_approval](../../06-ai-devsecops/cicd/README.md).

### 2.6 How the Equifax hack happened

Public reporting (verify the exact dates): a serious flaw in Apache Struts (CVE-2017-5638) was announced and patched in early March 2017. A vulnerable Struts component stayed in an internet-facing consumer web application. Attackers used the flaw from mid-May, moved inside, and the intrusion was found in late July. About 147 million people were affected. The failures were organizational and supply-chain ones: an incomplete asset and component inventory, a patch process that did not reach the system, a vulnerability scan that did not find it, and weak segmentation and monitoring. The lab [equifax-case-study](labs/equifax-case-study/README.md) finds the component by inventory plus advisory matching and computes **days exposed** against a **patch SLA**.

## 3. Defend it

| Control | Layer |
|---|---|
| Protected branches, protected variables, protected environments | Hard |
| Security stage before deploy, blocking | Hard |
| Artifact digest promotion and signing | Hard |
| Inventory with owners and advisory matching | Process plus tooling |
| Patch SLAs by severity and exposure | Process |

**What does NOT work on its own:** a security job with `allow_failure: true`; a manual approval by the same person who made the change; "we scan quarterly".

## 4. Hands-on

Run each lab README in order; do the edit exercises in [gitlab-ci-stages](labs/gitlab-ci-stages/README.md).

## 5. Interview preparation

<details><summary><b>Q1. Difference between continuous delivery and continuous deployment?</b></summary>
Delivery: every good build is releasable, a human triggers release. Deployment: every good build is released automatically after gates.
</details>

<details><summary><b>Q2. What does `needs` change?</b></summary>
A job starts as soon as the jobs it needs finish, instead of waiting for the whole previous stage. It also limits which artifacts it receives.
</details>

<details><summary><b>Q3. How would you have prevented Equifax?</b></summary>
Complete inventory of components with owners, automated advisory matching, a critical-patch SLA (days, not months), verified rescans, segmentation and monitoring.
</details>

## 6. Checklist

- [ ] I can explain stages, jobs, runners and artifacts.
- [ ] I can explain a manual protected deploy gate and rollback.
- [ ] I can explain Equifax as an inventory and patching failure.

## 7. References

- GitLab CI/CD docs: <https://docs.gitlab.com/ee/ci/> · CVE-2017-5638 on NVD · US House Oversight and GAO reports on the Equifax breach (verify at source).
