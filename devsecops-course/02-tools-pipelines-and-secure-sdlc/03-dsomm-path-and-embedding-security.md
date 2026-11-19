# Lesson 03: The DSOMM path, tools in CI/CD and embedding security

> **Chapter:** 2 · Tools, Pipelines and Secure SDLC · **Time:** ~4 hours
> **You will:** walk the DevSecOps Maturity Model from level 1 to level 4, explain the "4 axes" idea with its caveat, apply the tools to the secure SDLC activities, embed security in a pipeline, manage findings automatically, codify threats as BDD tests and explain why DevSecOps does not replace pentesting.

| | |
|---|---|
| **Prerequisites** | [Lesson 02](02-secure-sdlc-and-security-gates.md) · [Chapter 1 lesson 03](../01-devops-devsecops-and-maturity/03-devsecops-toolchain-sdlc-and-dsomm.md) |
| **Labs** | [ci-pipeline-multi-platform](labs/ci-pipeline-multi-platform/README.md) · [complete-cicd-pipeline](labs/complete-cicd-pipeline/README.md) · [manage-findings-automatically](labs/manage-findings-automatically/README.md) · [bdd-security-codify-threats](labs/bdd-security-codify-threats/README.md) |
| **Syllabus lines** | DSOMM levels and tasks · 4 axes · Level 1 to 4 · L1 best practices · L2 considerations · L3 challenges · Dream of L2 · Tools in CI/CD · Embedding security · DevSecOps vs pentesting/VA |

## 1. Why it matters

A maturity model answers "what should we do next?" so you do not buy every tool at once. Without it, teams alternate between doing nothing and doing too much, and security work is invisible to management. With it you can say: "we are level 2 in Build and Deployment, level 1 in Culture, here are the three cheapest steps to move up."

## 2. DSOMM: maturity levels and tasks

> **Caveat (read this first).** The OWASP DevSecOps Maturity Model (dsomm.owasp.org) has been revised several times. Older descriptions, and your course, use **four levels** and **four axes**. **Current versions** group activities into more dimensions (for example Build and Deployment, Culture and Organization, Implementation, Information Gathering, Test and Verification) and may use four or five levels. **Learn the course framing for the exam; open the current model before you use it at work.** The labs in this repo use a simplified list, not the official one.

DSOMM is a catalogue of **activities (tasks)**, each assigned a **level**. Level 1 tasks are the cheap, high-value basics; level 4 tasks are advanced and need the lower levels first.

| Level | Commonly used name | What the tasks look like | Example tasks |
|---|---|---|---|
| **1** | Basic security practices | Manual or ad hoc, done by motivated people | Version control, a pentest before big releases, a list of applications |
| **2** | Adoption of basic security goals | Basic automation exists, coverage is growing | Dependency and secret scanning in the pipeline, SAST on merge requests, security training |
| **3** | High adoption of security goals | Broad, enforced, measured | Break-build thresholds, DAST on staging, metrics, defined SLAs, threat modelling per feature |
| **4** | Advanced deployment at scale | Consistent, low friction, risk-based | Signed artifacts with provenance, policy as code, auto-remediation, runtime feedback loops |

Each **task** has a description, an implementation hint and often a mapping to standards (ASVS, SAMM, NIST). In an exam, say: "a level is a set of tasks, not a number of tools."

## 3. The 4 axes in DSOMM

The syllabus mentions **4 axes**. In older DSOMM material the axes were about **how well application security testing is done**: roughly

| Axis (older description; verify) | Question it answers |
|---|---|
| **Static depth** | How deep is the static analysis (lint, SAST, dependency checks, secrets)? |
| **Dynamic depth** | How deep is dynamic testing (DAST, API tests, IAST, fuzzing)? |
| **Intensity** | How often and how widely do you test (per commit, nightly, all apps or only critical)? |
| **Consolidation** | How well do you collect, deduplicate and act on the results? |

**Caveat:** recent versions of the model describe more dimensions covering culture, build and deployment, implementation, information gathering and testing and verification. The two views overlap: older axes are about *testing depth, frequency and handling*; the newer dimensions cover *the whole delivery system*. If your exam asks for "the 4 axes", give the course's answer. If your manager asks for a plan, use the current model.

In the [dsomm-assessment lab](../01-devops-devsecops-and-maturity/labs/dsomm-assessment/README.md) the dimensions are the newer style, so you can see "the weakest dimension decides the overall level".

## 4. How to go from level 1 to level 4

| Step | Typical activities | Evidence you have arrived |
|---|---|---|
| **Start (level 0 to 1)** | Put code in version control, list your applications, run one manual pentest, name a security contact | A repository per app; an inventory; a pentest report |
| **1 to 2** | Pipeline with dependency, secret and SAST scans, **non-blocking at first**; training; baseline of existing findings | Scans run on every merge request; a dashboard of findings |
| **2 to 3** | Make gates blocking (start with critical); add DAST and image scans; central templates; SLAs and owners; metrics | Builds fail on agreed thresholds; time-to-fix is tracked |
| **3 to 4** | Signing and provenance; policy as code; auto-created tickets and fix pull requests; runtime feedback; risk-based scoring | Only signed artifacts deploy; recurring findings drop; incidents create tests |

The stretch from level 2 to 4 is described in more detail in [chapter 1](../01-devops-devsecops-and-maturity/03-devsecops-toolchain-sdlc-and-dsomm.md#7-devsecops-maturity-model-dsomm-moving-from-level-2-to-level-4).

Golden rules for the climb:

1. **Do not skip levels.** Level 4 tasks sit on level 1 to 3 foundations.
2. **Fix the weakest dimension first.** Strong scanning with no ownership still produces no fixes.
3. **Report first, block later.** A gate that blocks on day one gets disabled on day two.
4. **Measure**, otherwise nobody can tell progress from activity.

## 5. Level by level

### 5.1 Best practices for Maturity Level 1

- Everything in version control (code, pipeline files, infrastructure scripts).
- A written inventory of applications, owners and data sensitivity.
- Secrets out of the repository from day one; rotate any that leaked.
- One automated check, even a simple one: dependency scan or secret scan, in report mode.
- A pentest before major releases, with findings tracked as tickets.
- A named security contact in each team.
- Basic logging and a patching routine for servers and base images.

### 5.2 Considerations for Maturity Level 2

- **Triage ownership:** who looks at a finding and decides? Decide before you enable the scanner.
- **Baseline legacy debt:** record existing findings so the pipeline fails on **new** problems while old ones are burned down on a schedule.
- **Tune first:** disable rules that never matter for your stack; false positives kill trust.
- **Speed budget:** keep merge-request checks within a few minutes; move deep scans to nightly.
- **Communication:** tell developers what will happen, when blocking starts, and how to request a waiver.
- **Training:** a short, practical session on the top issues your own scans find.

### 5.3 Challenges in Maturity Level 3

| Challenge | Why | Direction |
|---|---|---|
| Findings flood after enabling blocking gates | Years of debt appear at once | Block on critical only, then tighten gradually |
| False positives | Rules not tuned | Review, suppress with justification, track false-positive rate |
| Slow pipelines | Too many serial scans | Parallel jobs, caching, incremental scans |
| Unclear ownership | "Security will fix it" | Owner on every ticket, team dashboards, SLAs |
| Waivers become permanent | No expiry | Expiry date and monthly review ([findings lab](labs/manage-findings-automatically/README.md)) |
| Legacy apps | Cannot meet the bar quickly | Time-boxed plans and compensating controls |

### 5.4 The dream of achieving Maturity Level 2

The syllabus line "Dream of achieving Maturity Level 2" can be read this way (our interpretation; check your video):

> Many organisations *talk* about level 3 and 4 automation, but have not reached a solid **level 2**: basic scans running consistently in pipelines across most teams. Level 2 sounds modest and is often the real, valuable goal for a year.

How to make the "dream" real: pick a standard pipeline template, roll it out to the ten most important applications, report findings in one place and agree who fixes what. A level 2 that **actually runs everywhere** is worth more than a level 4 slide deck.

## 6. Using the tools of the trade to do these activities in CI/CD

### 6.1 Activity to tool to pipeline job

| Activity | Tool | Pipeline job | Gate |
|---|---|---|---|
| Secrets scan | gitleaks, TruffleHog | `secrets-scan` (first) | any verified secret |
| Dependency check | `npm audit`, osv-scanner, pip-audit | `sca` | high/critical with a fix |
| Static analysis | Semgrep, Bandit, SpotBugs | `sast` | high severity |
| Image build and scan | Docker/Kaniko, Trivy | `build`, `image-scan` | critical |
| Dynamic test | ZAP baseline | `dast` (needs a running app) | high risk |
| Hardening | Ansible | image or deploy job | job succeeds |
| Compliance check | InSpec/CINC | `compliance` | control failures |
| Deploy | scripts, Argo CD, Ansible | `deploy` | approval + health check |

The same pipeline in five syntaxes, with a validator, is the lab [ci-pipeline-multi-platform](labs/ci-pipeline-multi-platform/README.md). A runnable simulation with fake tool outputs is [complete-cicd-pipeline](labs/complete-cicd-pipeline/README.md) (this lab corresponds to the syllabus lab "Create a CI/CD pipeline suitable for modern application").

### 6.2 BDD security: codify threats as tests

**BDD** (behaviour-driven development) writes requirements as readable examples in **Gherkin**:

```gherkin
Scenario: Login must lock after 5 failures
  When I fail to log in as "alice" 5 times in a row
  And I log in as "alice" with password "correct-horse"
  Then the response status is 423
```

Each line is a **step** that a small piece of code runs against the application. The benefits: a threat (online guessing) becomes a requirement (lock after 5 failures) and then an **automated test** that runs in the pipeline for ever.

> **Legacy note.** The syllabus names **BDD-Security** (an open-source framework from ContinuumSecurity, later associated with IriusRisk). It appears **unmaintained since about 2022**: learn the *idea* from it, but do not start a new project on it. **Gauntlt** is another Gherkin-based security tool that is also old. **Current options:** write the same Gherkin with **behave** or **pytest-bdd** (Python) or Cucumber (JVM/JavaScript) and call your app, a ZAP API or `requests`; or express checks as **ZAP Automation Framework** plans or plain `pytest` tests. **Verify maintenance status before adopting any tool.**

The lab [bdd-security-codify-threats](labs/bdd-security-codify-threats/README.md) has a tiny pure-Python Gherkin runner and three feature files, run against a hardened and a vulnerable simulated app. The longer treatment of requirements and threat modelling as code is [chapter 3](../03-security-requirements-and-threat-modeling/README.md).

### 6.3 Manage the findings in a fully automated pipeline

Ten scanners create ten formats and thousands of lines. Automation here means:

1. **Collect** in standard formats (**SARIF** for static tools, JSON for others; ZAP and npm audit have their own JSON).
2. **Normalise** into one record: tool, rule, severity, location, CWE.
3. **Deduplicate** with a stable fingerprint (rule + file or URL path, ignoring line numbers or query strings).
4. **Apply waivers** (accepted risks) that **expire**.
5. **Decide** with thresholds (break the build above the limit).
6. **Ticket** new findings with owner, labels and a due date from the SLA, once only; list tickets whose finding has gone so they can be closed.
7. **Report** metrics. (A real vulnerability manager such as DefectDojo does this at scale: [chapter 14](../14-vulnerability-management/README.md).)

The lab [manage-findings-automatically](labs/manage-findings-automatically/README.md) does steps 1 to 6 with fake SARIF, ZAP and npm audit outputs.

## 7. Embedding security as part of the CI/CD pipeline

| Principle | Practice |
|---|---|
| **Security jobs are required jobs** | Central templates; teams cannot delete them; alert on removal |
| **Fast first** | Cheap checks early, deep scans nightly; merge-request pipeline in minutes |
| **Feedback where developers work** | Comments on the merge request, SARIF in the code view, not PDFs |
| **Report, then block** | Start non-blocking with a baseline, then block on new critical/high |
| **One findings list** | Normalise and deduplicate before humans see it |
| **Evidence by default** | Keep scan reports, approvals and signatures as pipeline artifacts |
| **Protect the pipeline itself** | Pinned actions/images, scoped tokens, protected variables, reviewed pipeline files |
| **Measure** | Time to fix, open by severity, false-positive rate, escape rate, pipeline duration |

The validator in [ci-pipeline-multi-platform](labs/ci-pipeline-multi-platform/README.md) checks four of these automatically: required stages, pinned actions and images, no secrets in YAML, and least-privilege tokens.

## 8. DevSecOps vs pentesting and vulnerability assessment

| | Penetration test | Vulnerability assessment (VA) | DevSecOps automation |
|---|---|---|---|
| Who | Human experts | Scanner plus analyst | Pipeline and developers |
| Frequency | Periodic (yearly, before big releases) | Periodic (weekly, monthly) | Every change |
| Finds | Chained attacks, business logic flaws, creative abuse | Known vulnerabilities and misconfigurations at scale | Known patterns early, regressions |
| Output | A report | A long list | Findings inside the merge request |
| Weakness | Point in time: stale in weeks | No exploitation context; noisy; infra-focused | Misses logic flaws; tool gaps |

**Challenges when you only have pentests and VA** (and why DevSecOps exists):

- The report arrives **after** release, so fixing means a hotfix and an argument.
- The app changes weekly or daily, so a yearly pentest is out of date quickly.
- Findings are not mapped to a code owner or repository.
- Duplicates and noise across scanner runs; no history.
- Scope and schedule negotiations delay testing.

**Challenges when you only have DevSecOps automation:**

- Tools miss logic, authorisation and design flaws.
- False negatives give false confidence.
- Pipelines and tools are themselves attack targets.

**Right answer in an interview:** you need all three. Automation prevents the common bugs cheaply and continuously, VA covers infrastructure drift, and pentests find what tools cannot. Feed pentest findings back as new rules and regression tests. See the repo's [vulnerability management](../../cybersecurity-track/08-vulnerability-management/README.md) and [pentesting fundamentals](../../cybersecurity-track/09-pentesting-fundamentals/README.md) tracks.

## 9. Self-check

1. Describe the four DSOMM levels in one line each and give the caveat about versions.
2. What are the "4 axes" in the older description, and what do newer versions use instead?
3. List the first three steps from level 1 to level 2 and say why they start non-blocking.
4. What does "the dream of level 2" mean, and why is level 2 a good goal?
5. Name the six steps of automated findings management.
6. Write a Gherkin scenario for "password reset links expire after 15 minutes".
7. Give three reasons a pentest does not replace the pipeline and three why the pipeline does not replace a pentest.

## 10. Where next

Your hands-on work: the four labs in this chapter. Then continue with [Chapter 3: requirements and threat modelling](../03-security-requirements-and-threat-modeling/README.md) and [Chapter 4: SCA](../04-software-component-analysis/README.md).
