# Lesson 01: Tools of the trade

> **Chapter:** 2 · Tools, Pipelines and Secure SDLC · **Time:** ~4 hours
> **You will:** place each course tool in the pipeline (GitLab/GitHub, Docker, five CI systems, ZAP, Ansible, InSpec), read the same job in five CI syntaxes, and map the ideas to cloud pipeline services.

| | |
|---|---|
| **Prerequisites** | [Chapter 1](../01-devops-devsecops-and-maturity/README.md) |
| **Labs** | [ci-pipeline-multi-platform](labs/ci-pipeline-multi-platform/README.md) · [complete-cicd-pipeline](labs/complete-cicd-pipeline/README.md) |
| **Real tools** | [GitLab CI](real-tools/gitlab-ci.md) · [GitHub Actions](real-tools/github-actions.md) · [Jenkins](real-tools/jenkins.md) |
| **Syllabus lines** | GitLab/GitHub · Docker · GitLab CI / GitHub Actions / CircleCI / Jenkins / Travis · OWASP ZAP · Ansible · InSpec · the cloud providers note |

> **Status check (Nov 2026, verify at source).** The tool list in your syllabus is a few years old. GitLab CI, GitHub Actions, CircleCI and Jenkins are all current. **Travis CI** still exists but has lost most of its open-source user base since its 2020-21 pricing changes: learn it as legacy. **OWASP ZAP** is now "ZAP by Checkmarx" (the core team joined Checkmarx in 2024). **Ansible Tower** is now Ansible Automation Platform; **InSpec 6+** needs a licence key, and the community alternative **CINC Auditor** exists.

## 1. Why it matters

One idea, many tools. If you understand a **pipeline as an ordered list of jobs that run commands in a clean environment**, you can move between all of them in a day. Employers do not ask "do you know GitLab?", they ask "can you build a secure pipeline on what we have?"

## 2. Source hosting: GitLab and GitHub

Both host Git repositories and add review (merge requests / pull requests), issues, permissions and a built-in CI service.

| Feature | GitLab | GitHub |
|---|---|---|
| Review unit | Merge request | Pull request |
| Built-in CI | GitLab CI/CD (`.gitlab-ci.yml`) | GitHub Actions (`.github/workflows/*.yml`) |
| Protect important branches | Protected branches, approval rules | Branch protection rules or rulesets |
| Secrets | CI/CD variables (masked, protected) | Actions secrets (repository, environment, organisation) |
| Hosted or self-managed | Both | Mostly hosted; Enterprise Server is self-managed |
| Built-in security features | Scanner templates (tier dependent) | Code scanning, secret scanning, Dependabot (plan dependent) |

**Always protect the default branch, require reviews and require the pipeline to pass.** Everything in this course assumes it.

## 3. Docker in the pipeline

Docker packages the app and its dependencies as an **image** so it runs the same everywhere. In pipelines Docker plays three roles:

1. **The job environment:** `image: node:20.11.1` gives every run a clean, known toolbox.
2. **The scanner delivery vehicle:** most scanners (ZAP, Trivy, gitleaks) ship as images, so you do not install them on runners.
3. **The artifact:** your app image is built, scanned, signed and deployed.

Security rules:

- **Pin images by exact tag or digest.** `latest` changes under your feet.
- **Do not mount `/var/run/docker.sock` or use privileged mode** in jobs that build untrusted code: it is root on the runner. Prefer rootless builders such as Kaniko or BuildKit in rootless mode.
- Run containers as a non-root user and scan every image you build.

Deep dives: [csse ch3 containers](../../csse-course/ch3-attacking-container-supply-chain/README.md) and, in this course, [chapter 9](../09-container-fundamentals/README.md) and [chapter 11](../11-defending-containers-at-scale/README.md).

## 4. CI systems: GitLab CI, GitHub Actions, CircleCI, Jenkins, Travis

### 4.1 Comparison

| | GitLab CI | GitHub Actions | CircleCI | Jenkins | Travis CI |
|---|---|---|---|---|---|
| Status | Current | Current | Current | Current (older, plugin-heavy) | **Legacy** for most OSS |
| Config | `.gitlab-ci.yml` | `.github/workflows/*.yml` | `.circleci/config.yml` | `Jenkinsfile` (Groovy) | `.travis.yml` |
| Hosting | SaaS or self-managed | SaaS (self-hosted runners possible) | SaaS (self-hosted runners possible) | Self-hosted | SaaS (self-hosted option exists) |
| Ordering | `stages:` list | `needs:` between jobs | `requires:` in a workflow | `stages { }` blocks in order | `stages:` + `jobs.include` |
| Reuse | `include`, templates, components | Actions and reusable workflows | Orbs and commands | Shared libraries | Limited (build config imports) |
| Secrets | Masked/protected variables | Secrets, environment secrets | Contexts, project variables | Credentials store | Encrypted variables |
| Cloud identity without long-lived keys | OIDC ID tokens | OIDC (`id-token: write`) | OIDC tokens | Plugins/custom | Not a typical strength |
| Biggest security watch-point | Runner isolation, protected variables | Third-party actions, token permissions | Context scoping; a 2023 incident led to secret rotation advice | Plugins, exposed controller, shared agents | Fork/PR builds exposing secrets; stale service |

### 4.2 The same job in five syntaxes

Job: after checkout, install dependencies and fail if `npm audit` finds a high vulnerability. (Compact on purpose; the full pipeline is in the [lab fixtures](labs/ci-pipeline-multi-platform/fixtures/).)

**GitLab CI**

```yaml
dependency-scan:
  stage: sca
  image: node:20.11.1-alpine3.19
  script:
    - npm ci --ignore-scripts
    - npm audit --audit-level=high
```

**GitHub Actions**

```yaml
dependency-scan:
  runs-on: ubuntu-24.04
  steps:
    - uses: actions/checkout@<commit SHA> # v4
    - run: npm ci --ignore-scripts
    - run: npm audit --audit-level=high
```

**CircleCI**

```yaml
jobs:
  dependency-scan:
    docker: [{image: cimg/node:20.11.1}]
    steps:
      - checkout
      - run: npm ci --ignore-scripts
      - run: npm audit --audit-level=high
```

**Jenkins (declarative)**

```groovy
stage('Dependency scan') {
  agent { docker { image 'node:20.11.1-alpine3.19' } }
  steps {
    sh 'npm ci --ignore-scripts'
    sh 'npm audit --audit-level=high'
  }
}
```

**Travis CI (legacy)**

```yaml
jobs:
  include:
    - stage: sca
      language: node_js
      node_js: "20"
      script:
        - npm ci --ignore-scripts
        - npm audit --audit-level=high
```

### 4.3 Equivalent keywords

| Need | GitLab | GitHub Actions | CircleCI | Jenkins | Travis |
|---|---|---|---|---|---|
| Run only on main | `rules: - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'` | `if: github.ref == 'refs/heads/main'` | `filters: branches: only: main` | `when { branch 'main' }` | `if: branch = main` |
| Run after another job | `stage` order or `needs:` | `needs:` | `requires:` | stage order | stage order |
| Save a file for later jobs | `artifacts:` | `actions/upload-artifact` | `persist_to_workspace` | `archiveArtifacts` / `stash` | `cache` or external storage |
| Use a secret | `$VARIABLE` (masked) | `${{ secrets.NAME }}` | Context variable | `withCredentials` / `credentials('id')` | `secure:` encrypted env |
| Manual approval | `when: manual` + protected environment | Environment with required reviewers | `type: approval` job | `input` step | Not built-in |
| Let a failed job continue | `allow_failure: true` | `continue-on-error: true` | `when: always` patterns | `catchError` | `allow_failures` |

Security reading of the last row: **every "continue on error" switch is a gate that became a report.** Search for it in reviews.

### 4.4 Choosing

- **Code already on GitHub or GitLab:** use that platform's CI first; fewer systems to secure.
- **Complex, custom, on-prem needs:** Jenkins, with strict plugin hygiene.
- **Want hosted speed and caching across many languages:** CircleCI is a common choice.
- **Travis CI:** only if you inherit it. Plan a migration.

## 5. OWASP ZAP (ZAP by Checkmarx)

ZAP is a free, open-source web application scanner and proxy. In pipelines you run it headless, mostly as a container image (the project publishes to `ghcr.io/zaproxy/zaproxy`; verify the current image names on zaproxy.org).

| Mode | What it does | When |
|---|---|---|
| **Baseline scan** (`zap-baseline.py`) | Spider and **passive** checks only: no attacks | Every deploy to staging; quick |
| **Full scan** (`zap-full-scan.py`) | Spider plus **active** attacks | Nightly/weekly against a test environment you own |
| **API scan** (`zap-api-scan.py`) | Imports an OpenAPI/GraphQL definition and tests the endpoints | APIs |
| **Automation Framework** | Plans described in YAML | Repeatable, reviewable scans |

Rules: scan only systems you own or are authorised to test, never production by default, and keep scan configs in the repo. Auth, Zest scripts and deeper tuning are in [chapter 6](../06-dynamic-analysis/README.md).

## 6. Ansible

Ansible is **agentless configuration management**: you write **playbooks** in YAML (tasks that call modules), and Ansible connects over SSH (or WinRM) and makes the machine match the description. Running a play twice should change nothing the second time (**idempotent**).

```yaml
- hosts: webservers
  become: true
  tasks:
    - name: Disable SSH root login
      ansible.builtin.lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^PermitRootLogin'
        line: 'PermitRootLogin no'
      notify: restart sshd
  handlers:
    - name: restart sshd
      ansible.builtin.service: {name: sshd, state: restarted}
```

> **DBA analogy.** A playbook is a repeatable, reviewed version of your post-install checklist: parameters, OS settings, users, and listener config applied the same way to every host.

Security points: **Ansible Vault** encrypts variables and files; the controller holds keys to every target, so protect it like a domain controller; **Ansible Tower** is now **Ansible Automation Platform (AAP)** and **AWX** is the open-source upstream project. Ansible is covered in depth in [chapter 8](../08-iac-configuration-and-compliance-as-code/README.md).

## 7. InSpec (and CINC Auditor)

InSpec describes **compliance and security checks as code** ("controls") and runs them against hosts, containers or cloud accounts.

```ruby
control 'ssh-1' do
  impact 1.0
  title 'SSH root login is disabled'
  describe sshd_config do
    its('PermitRootLogin') { should cmp 'no' }
  end
end
```

Licence note: **InSpec 6 and later require a licence key** (verify the current terms with Progress Chef). **CINC Auditor** is a free community build that stays compatible with InSpec profiles. OpenSCAP with the SCAP Security Guide is another route. Details in [chapter 8](../08-iac-configuration-and-compliance-as-code/README.md).

How the three infrastructure tools fit in a pipeline:

```text
build image / host  ->  Ansible hardens it  ->  InSpec/CINC checks it  ->  pipeline fails if a control fails
```

## 8. The note: cloud providers

The syllabus says that once you learn these tools you can build DevSecOps pipelines on cloud providers such as **AWS** and **Azure DevOps**. That is true, because the concepts map one to one:

| Concept | AWS | Azure | Google Cloud |
|---|---|---|---|
| Source hosting | CodeCommit (availability has changed over time: **verify**), or GitHub/GitLab connected | Azure Repos, or GitHub | Cloud Source Repositories (**check current status**), or GitHub/GitLab |
| Pipeline orchestration | CodePipeline | Azure Pipelines (`azure-pipelines.yml`) | Cloud Build / Cloud Deploy |
| Build/test runner | CodeBuild (`buildspec.yml`) | Microsoft-hosted or self-hosted agents | Cloud Build steps |
| Registry | ECR | Azure Container Registry | Artifact Registry |
| Secrets | Secrets Manager, Parameter Store | Key Vault | Secret Manager |
| Identity for pipelines | IAM roles (use OIDC federation, not static keys) | Service connections, workload identity | Service accounts, workload identity federation |
| Policy and security | IAM, Config, Inspector, Security Hub | Defender for Cloud, Azure Policy | Security Command Center, Organization Policy |

Reading tip: translate every provider feature back to the questions of this chapter. *Where do the gates run? What identity does the pipeline use? Where are findings stored? Who can edit the pipeline?* Product names and availability change often: verify in each provider's current documentation.

## 9. Self-check

1. Name three jobs of Docker in a pipeline and one rule for each.
2. Translate "run only on main, after tests" into GitLab, GitHub Actions and Jenkins syntax.
3. What is the difference between a ZAP baseline scan and a full scan, and which one runs on every merge?
4. What does "idempotent" mean for an Ansible play?
5. Why might you choose CINC Auditor over InSpec 6?
6. Map a GitHub Actions workflow to AWS CodePipeline plus CodeBuild.

## 10. Where next

[Lesson 02](02-secure-sdlc-and-security-gates.md): what the pipeline should check, phase by phase.
