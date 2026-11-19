# Chapter 1: DevOps, DevSecOps and Maturity

This chapter covers **what DevOps and DevSecOps are**, how CI/CD pipelines work (CI vs continuous delivery vs continuous deployment, blue/green releases, full automation, designing a pipeline), what goes into the **DevSecOps toolchain**, the **secure SDLC**, the **DevSecOps Maturity Model (DSOMM)** from level 2 to 4, and a walkthrough of a ten-stage **enterprise DevSecOps pipeline**. Two offline labs have tests: **no Docker, CI server or cloud account is needed**.

> **Safety.** Every lab is a simulation: YAML files and Python functions. Nothing is deployed, scanned or sent over a network. Fixtures use fake names and demo values.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Tool status and numbers here are hedged: **verify at the source**. Case studies about big companies are told in broad strokes; do not quote their numbers without checking.

## Syllabus coverage

Sources: **[CDP 1]** DevSecOps Professional chapter 1 and **[CDE 1]** DevSecOps Expert chapter 1. Every line is listed verbatim and in source order. Where the two courses repeat a topic, both rows are kept and point to the same lesson.

| Syllabus item | Where to study | Lab |
|---|---|---|
| [CDP 1] What is DevOps? | [Lesson 01 section 2](01-devops-foundations.md#2-what-is-devops) | n/a |
| [CDP 1] DevOps Building Blocks – People, Process and Technology. | [Lesson 01 section 3](01-devops-foundations.md#3-the-building-blocks-people-process-technology) | n/a |
| [CDP 1] DevOps Principles – Culture, Automation, Measurement and Sharing (CAMS) | [Lesson 01 section 4](01-devops-foundations.md#4-cams-the-four-principles) | n/a |
| [CDP 1] Benefits of DevOps – Speed, Reliability, Availability, Scalability, Automation, Cost and Visibility. | [Lesson 01 section 5](01-devops-foundations.md#5-benefits-of-devops) | n/a |
| [CDP 1] What is Continuous Integration and Continuous Deployment? | [Lesson 02 section 2](02-cicd-and-deployment-strategies.md#2-what-is-continuous-integration-and-continuous-deployment) | n/a |
| [CDP 1] Continuous Integration to Continuous Deployment to Continuous Delivery. | [Lesson 02 section 3](02-cicd-and-deployment-strategies.md#3-continuous-integration-to-continuous-deployment-to-continuous-delivery) | n/a |
| [CDP 1] Continuous Delivery vs Continuous Deployment. | [Lesson 02 section 3.1](02-cicd-and-deployment-strategies.md#31-continuous-delivery-vs-continuous-deployment) | n/a |
| [CDP 1] General workflow of CI/CD pipeline. | [Lesson 02 section 4](02-cicd-and-deployment-strategies.md#4-general-workflow-of-a-cicd-pipeline); repo [csse ch1 how-cicd-works](../../csse-course/ch1-introduction-to-supply-chain-security/labs/how-cicd-works/README.md) | n/a |
| [CDP 1] Blue/Green deployment strategy | [Lesson 02 section 5](02-cicd-and-deployment-strategies.md#5-blue-green-deployment-and-its-cousins) (SVG) | [pipeline-design](labs/pipeline-design/README.md) |
| [CDP 1] Achieving full automation. | [Lesson 02 section 6](02-cicd-and-deployment-strategies.md#6-achieving-full-automation) | [pipeline-design](labs/pipeline-design/README.md) |
| [CDP 1] Designing a CI/CD pipeline for web application. | [Lesson 02 section 7](02-cicd-and-deployment-strategies.md#7-designing-a-cicd-pipeline-for-a-web-application) | [pipeline-design](labs/pipeline-design/README.md) |
| [CDP 1] Common Challenges faced when using DevOps principle. | [Lesson 01 section 6](01-devops-foundations.md#6-common-challenges-and-what-to-do) | n/a |
| [CDP 1] Case studies on DevOps of cutting edge technology at Facebook, Amazon and Google | [Lesson 01 section 7](01-devops-foundations.md#7-case-studies-how-three-big-technology-companies-did-it) (hedged) | n/a |
| [CDP 1] Demo: A full enterprise grade DevSecOps Pipeline. | [Lesson 04](04-enterprise-devsecops-pipeline-demo.md) (SVG) | [pipeline-design](labs/pipeline-design/README.md), [complete-cicd-pipeline (ch02)](../02-tools-pipelines-and-secure-sdlc/labs/complete-cicd-pipeline/README.md) |
| [CDE 1] DevOps Building Blocks- People, Process and Technology. | [Lesson 01 section 3](01-devops-foundations.md#3-the-building-blocks-people-process-technology) | n/a |
| [CDE 1] DevOps Principles – Culture, Automation, Measurement and Sharing (CAMS) | [Lesson 01 section 4](01-devops-foundations.md#4-cams-the-four-principles) | n/a |
| [CDE 1] Benefits of DevOps – Speed, Reliability, Availability, Scalability, Automation, Cost and Visibility. | [Lesson 01 section 5](01-devops-foundations.md#5-benefits-of-devops) | n/a |
| [CDE 1] Overview of the DevSecOps critical toolchain | [Lesson 03 section 2](03-devsecops-toolchain-sdlc-and-dsomm.md#2-the-devsecops-critical-toolchain) | n/a |
| [CDE 1] Repository management tools. | [Lesson 03 section 2.1](03-devsecops-toolchain-sdlc-and-dsomm.md#21-repository-management-tools) | n/a |
| [CDE 1] Continuous Integration and Continuous Deployment tools. | [Lesson 03 section 2.2](03-devsecops-toolchain-sdlc-and-dsomm.md#22-continuous-integration-and-continuous-deployment-tools) | n/a |
| [CDE 1] Infrastructure as Code (IaC) tools. | [Lesson 03 section 2.3](03-devsecops-toolchain-sdlc-and-dsomm.md#23-infrastructure-as-code-iac-tools) | n/a |
| [CDE 1] Communication and sharing tools. | [Lesson 03 section 2.4](03-devsecops-toolchain-sdlc-and-dsomm.md#24-communication-and-sharing-tools) | n/a |
| [CDE 1] Security as Code (SaC) tools. | [Lesson 03 section 2.5](03-devsecops-toolchain-sdlc-and-dsomm.md#25-security-as-code-sac-tools) | n/a |
| [CDE 1] SDLC | [Lesson 03 section 3](03-devsecops-toolchain-sdlc-and-dsomm.md#3-sdlc-the-plain-software-development-life-cycle) | n/a |
| [CDE 1] Overview of secure SDLC and CI/CD. | [Lesson 03 section 4](03-devsecops-toolchain-sdlc-and-dsomm.md#4-overview-of-secure-sdlc-and-cicd); [ch02 lesson 02](../02-tools-pipelines-and-secure-sdlc/02-secure-sdlc-and-security-gates.md) | n/a |
| [CDE 1] Review of security activities in secure SDLC. | [Lesson 03 section 5](03-devsecops-toolchain-sdlc-and-dsomm.md#5-review-of-security-activities-in-the-secure-sdlc) | n/a |
| [CDE 1] Continuous Integration and Continuous Deployment. | [Lesson 03 section 6](03-devsecops-toolchain-sdlc-and-dsomm.md#6-continuous-integration-and-continuous-deployment-security-view); [Lesson 02 section 2](02-cicd-and-deployment-strategies.md#2-what-is-continuous-integration-and-continuous-deployment) | [pipeline-design](labs/pipeline-design/README.md) |
| [CDE 1] How to move from DevSecOps Maturity Model (DSOMM) Level 2 to Level 4. | [Lesson 03 section 7](03-devsecops-toolchain-sdlc-and-dsomm.md#7-devsecops-maturity-model-dsomm-moving-from-level-2-to-level-4) (7.2 and 7.4); L1 to L4 path: [ch02 lesson 03](../02-tools-pipelines-and-secure-sdlc/03-dsomm-path-and-embedding-security.md#4-how-to-go-from-level-1-to-level-4) | [dsomm-assessment](labs/dsomm-assessment/README.md) |
| [CDE 1] Best practices and considerations for Maturity Level 3. | [Lesson 03 section 7.3](03-devsecops-toolchain-sdlc-and-dsomm.md#73-best-practices-and-considerations-at-level-3) | [dsomm-assessment](labs/dsomm-assessment/README.md) |
| [CDE 1] Best practices and considerations for Maturity Level 4. | [Lesson 03 section 7.5](03-devsecops-toolchain-sdlc-and-dsomm.md#75-best-practices-and-considerations-at-level-4) | [dsomm-assessment](labs/dsomm-assessment/README.md) |
| [CDE 1] Security automation and its limits. | [Lesson 03 section 8](03-devsecops-toolchain-sdlc-and-dsomm.md#8-security-automation-and-its-limits) | n/a |
| [CDE 1] DSOMM level 3 and level 4 challenges and solutions. | [Lesson 03 section 9](03-devsecops-toolchain-sdlc-and-dsomm.md#9-dsomm-level-3-and-level-4-challenges-and-solutions) | [dsomm-assessment](labs/dsomm-assessment/README.md) |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| **DevSecOps Maturity Model (DSOMM)**, levels 1 to 4 | The OWASP model (dsomm.owasp.org) has been revised: current versions list more dimensions (for example Build and Deployment, Culture and Organization, Implementation, Information Gathering, Test and Verification) and the level scheme may differ. Learn the course framing for the exam, check the **current** model for real work. The lab uses a simplified list. |
| "Case studies on DevOps of cutting edge technology at Facebook, Amazon and Google" | Practices evolve and public numbers are dated conference claims. Learn the **patterns** (small teams owning services, error budgets, feature flags with staged rollout), not the figures. Facebook is now Meta. |
| "Demo: A full enterprise grade DevSecOps Pipeline" | Tool choices change. Prefer maintained tools, pin versions, sign and verify artifacts (cosign or Notation), and put findings in one place. Docker Content Trust is retired (service shutdown announced for 8 Dec 2026); do not build a new pipeline on it. |
| "Continuous Integration and Continuous Deployment tools" | GitLab CI, GitHub Actions, Jenkins and CircleCI are current. Travis CI is mostly legacy. See [chapter 2](../02-tools-pipelines-and-secure-sdlc/01-tools-of-the-trade.md). |
| "Security as Code (SaC) tools" | Not a standard industry term (you will also hear *policy as code*, *compliance as code*, *detection as code*). Know it as: security checks and rules defined in versioned files. |
| "Security automation and its limits" | Today this also includes AI-assisted triage and code review. They help with noise and speed, but have the same limits (false positives, missed logic flaws) and add new risks (prompt injection in review bots). See the repo's [AI DevSecOps module](../../06-ai-devsecops/cicd/README.md). |
| Blue/Green | Still valid. Canary releases, feature flags and GitOps-style progressive delivery (for example Argo Rollouts, Flagger) are common companions: verify tools at source. |

## Learning order

1. [Lesson 01: DevOps foundations](01-devops-foundations.md). About 2.5 hours.
2. [Lesson 02: CI/CD and deployment strategies](02-cicd-and-deployment-strategies.md), then the [pipeline-design](labs/pipeline-design/README.md) lab. About 4 hours in total.
3. [Lesson 03: toolchain, SDLC and DSOMM](03-devsecops-toolchain-sdlc-and-dsomm.md), then the [dsomm-assessment](labs/dsomm-assessment/README.md) lab. About 4.5 hours.
4. [Lesson 04: enterprise pipeline demo](04-enterprise-devsecops-pipeline-demo.md). About 2 hours.
5. Optional hands-on with real tools: [GitLab CI](real-tools/gitlab-ci.md), [GitHub Actions](real-tools/github-actions.md), [Jenkins](real-tools/jenkins.md).
6. Then [Chapter 2: tools, pipelines and secure SDLC](../02-tools-pipelines-and-secure-sdlc/README.md), which continues the DSOMM path from level 1 to 4 and builds the pipelines in real syntax.

## Lab index

All labs run offline: `.venv/Scripts/python -m pytest devsecops-course/01-devops-devsecops-and-maturity`.

| Lab | What it practises | Tests |
|---|---|---|
| [dsomm-assessment](labs/dsomm-assessment/README.md) | YAML self-assessment against a DSOMM-like activity list: level per dimension, gaps to the next level, roadmap | 15 |
| [pipeline-design](labs/pipeline-design/README.md) | Validate a web-app pipeline design against required security gates; simulate blue/green (health check, flip, rollback) and canary | 22 |

Hedged guides for real tools: [GitLab CI](real-tools/gitlab-ci.md), [GitHub Actions](real-tools/github-actions.md), [Jenkins](real-tools/jenkins.md).

## How the three courses overlap here

The Professional and Expert courses both open with the same DevOps basics (building blocks, CAMS, benefits). They are taught **once** in [Lesson 01](01-devops-foundations.md) and listed twice in the coverage table. The Expert course then adds the **toolchain, secure SDLC and DSOMM L2 to L4** (Lesson 03), while the Professional course adds **CI/CD mechanics, blue/green and the pipeline demo** (Lessons 02 and 04). Chapter 2 continues with the Professional course's tools and DSOMM level 1 to 4 path. The Container Security course (CCSE) does not appear in this chapter; its containers come back in [chapters 9 to 12](../09-container-fundamentals/README.md). For CI runner mechanics and the Equifax case, the sibling [csse chapter 1](../../csse-course/ch1-introduction-to-supply-chain-security/README.md) goes deeper.

## Exam tips

- **Three CI/CD words.** CI = merge and test often. Continuous **delivery** = always releasable, a person presses the button. Continuous **deployment** = no button. Write the full words, since "CD" is ambiguous.
- **CAMS** = Culture, Automation, Measurement, Sharing. Give a security example for each.
- **Blue/green in four verbs:** deploy to idle, check, flip, roll back. The hard part is the shared database.
- **Same artifact everywhere.** Build once, promote the artifact through environments.
- **A gate must be able to fail.** `allow_failure` turns a gate into a report.
- **Five toolchain categories:** repositories, CI/CD, IaC, communication and sharing, Security as Code. Each is also an attack target.
- **DSOMM:** a level is a set of tasks, not a number of tools; do not skip levels; fix the weakest dimension; start non-blocking and tighten.
- **Automation limits:** false positives and negatives, context blindness, speed vs depth, tool trust. Humans still do design, review, risk acceptance.
- **Case studies:** state the pattern, hedge the numbers. Amazon: small teams owning services. Google: SRE and error budgets. Facebook: continuous push and feature flags.

## 15 exam-style questions

<details>
<summary>1. What is DevOps, and what does DevSecOps add?</summary>

DevOps is a way of working in which development and operations share responsibility for building, releasing and running software, using small frequent changes, automation and fast feedback. DevSecOps adds security as a shared responsibility that is checked automatically at every step of the pipeline.
</details>

<details>
<summary>2. Name the three DevOps building blocks and say which to invest in first.</summary>

People, process and technology. Start with people (shared goals and ownership), then process (a short, agreed path with gates), then technology. Tools without the first two become shelfware.
</details>

<details>
<summary>3. What does CAMS stand for? Give a security example for each letter.</summary>

Culture (blameless post-mortems, developers fix their own findings), Automation (scans on every change), Measurement (time to fix, escape rate), Sharing (share findings and fixes so bugs are not repeated).
</details>

<details>
<summary>4. List the benefits of DevOps from the syllabus and pick two that help security.</summary>

Speed, reliability, availability, scalability, automation, cost and visibility. Automation (repeatable security checks) and visibility (shared dashboards, evidence) help security most. Speed without gates is a risk.
</details>

<details>
<summary>5. What is the difference between continuous delivery and continuous deployment?</summary>

Both automate everything up to production. In continuous delivery a person approves the final release; in continuous deployment the release happens automatically when all gates pass. The second moves trust from people to automated checks, so it demands strong tests, gates and automatic rollback.
</details>

<details>
<summary>6. Describe the general workflow of a CI/CD pipeline.</summary>

Commit or merge request, source checks (secrets, lint), build one artifact, test (unit, SAST, SCA), package and store with a unique version, deploy to staging, acceptance and security tests (DAST), release gate (approval or policy), deploy to production with a safe strategy, then verify and monitor with rollback on failure.
</details>

<details>
<summary>7. Explain blue/green deployment, including rollback. What makes it hard?</summary>

Two identical environments, one live. Deploy the new version to the idle one, health check it, flip the router, watch, and flip back if errors rise. The hard parts are the shared database (use expand-then-contract schema changes), sessions and the cost of two environments.
</details>

<details>
<summary>8. How does canary differ from blue/green?</summary>

Canary sends a small share of real traffic to the new version and increases it step by step while watching metrics, stopping at the first sign of trouble. Blue/green switches all traffic at once but can switch back instantly.
</details>

<details>
<summary>9. What does "achieving full automation" mean, and what stays manual?</summary>

No manual, undocumented, repeatable steps between commit and monitored service: build, test, environments, deploy, config, compliance evidence and monitoring are code. Humans still design controls, review risky changes, accept risk (with an expiry) and investigate incidents.
</details>

<details>
<summary>10. Design the stages of a pipeline for a web application and justify the order.</summary>

Secrets scan, SCA, SAST (need only source: cheapest and fastest), build once, image scan, sign, deploy to staging, DAST (needs a running app), deploy to production with approval and blue/green plus automatic rollback. Cheap checks go first so feedback is fast, and scans sit before deploy so they protect something.
</details>

<details>
<summary>11. Name common DevOps challenges and a fix for each of three.</summary>

Culture clash (shared goals and on-call), tool sprawl (a supported paved road), security as a bottleneck (automate routine checks, spend human time on design), finding overload (tune, deduplicate, thresholds), legacy systems (wrap and automate step by step).
</details>

<details>
<summary>12. Summarise what Amazon, Google and Facebook are known for in DevOps, with hedges.</summary>

Amazon: small autonomous teams owning services ("two-pizza", "you build it, you run it") and very frequent deployments. Google: SRE with SLOs and error budgets, blameless post-mortems. Facebook: continuous push and server-side feature flags (Gatekeeper) for staged rollout. Numbers are dated and should be verified.
</details>

<details>
<summary>13. List the five categories of the DevSecOps toolchain and one thing to secure in each.</summary>

Repositories (branch protection, reviews), CI/CD (isolated runners, pinned steps, scoped credentials), IaC (scan and review, protect state), communication and sharing (no secrets in chat, registry access and immutable tags), Security as Code (pin scanners, review rule changes, expiring waivers).
</details>

<details>
<summary>14. How does an organisation move from DSOMM level 2 to level 4?</summary>

Level 2 to 3: make checks mandatory through central templates, broaden coverage (DAST, image and IaC scans), reduce noise, define SLAs and owners, measure. Level 3 to 4: automate response (tickets, fix pull requests), policy as code, signed artifacts with provenance, runtime feedback, risk-based decisions and continuous improvement. Do not skip levels, and check the current model since DSOMM has been revised.
</details>

<details>
<summary>15. What are the limits of security automation?</summary>

False positives and negatives, no business context, coverage gaps (for example DAST without authentication), speed versus depth, alert fatigue, trusting tools that are themselves a supply chain risk, and the fact that automation does not create ownership. Combine it with threat modelling, review and pentests.
</details>

## References

- OWASP DevSecOps Maturity Model (DSOMM): dsomm.owasp.org. OWASP SAMM; NIST SP 800-218 (SSDF); NIST SP 800-204 series.
- *Site Reliability Engineering* (Google, 2016), error budgets and blameless post-mortems. DORA research programme (delivery metrics). *The DevOps Handbook*; *Accelerate*.
- Docs: GitLab CI/CD, GitHub Actions, Jenkins: verify current syntax at each project's documentation.
- Repo: [csse ch1 CI/CD and Equifax](../../csse-course/ch1-introduction-to-supply-chain-security/05-cicd-stages-and-deployment.md), [06 CI/CD module](../../06-ai-devsecops/cicd/README.md), [caisp ch4 DevSecOps](../../caisp-course/ch4-ai-attacks-and-defenses-devops/01-devops-devsecops-and-ai-in-devops.md), [cybersecurity track: vulnerability management](../../cybersecurity-track/08-vulnerability-management/README.md).
