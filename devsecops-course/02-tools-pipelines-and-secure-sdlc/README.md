# Chapter 2: Tools, Pipelines and Secure SDLC

This chapter covers **the tools of the trade** (GitLab/GitHub, Docker, five CI systems, ZAP, Ansible, InSpec), the **secure SDLC with its security gates**, the **DSOMM path from level 1 to level 4**, **embedding security in CI/CD** and the limits of pentests and vulnerability assessments. Four offline labs have tests: **no Docker, CI server, Java, Node or cloud account is needed**.

> **Safety.** Every lab is a simulation: fixture files, fake tool output and an in-memory "web app". Nothing is executed, scanned over a network or sent to a ticket system. Fixtures use FAKE commit SHAs, FAKE demo passwords and `.example` domains.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Tool status is hedged: **verify at the source**.

## Syllabus coverage

Sources: **[CDP 2]** DevSecOps Professional chapter 2 and **[CDP 3]** chapter 3. Every line is listed verbatim and in source order.

| Syllabus item | Where to study | Lab |
|---|---|---|
| [CDP 2] Gitlab/Github | [Lesson 01 section 2](01-tools-of-the-trade.md#2-source-hosting-gitlab-and-github) | [ci-pipeline-multi-platform](labs/ci-pipeline-multi-platform/README.md) |
| [CDP 2] Docker | [Lesson 01 section 3](01-tools-of-the-trade.md#3-docker-in-the-pipeline); repo [csse ch3](../../csse-course/ch3-attacking-container-supply-chain/README.md) | [ci-pipeline-multi-platform](labs/ci-pipeline-multi-platform/README.md) |
| [CDP 2] Gitlab CI/Github Actions/Circle CI/Jenkins/Travis/ | [Lesson 01 section 4](01-tools-of-the-trade.md#4-ci-systems-gitlab-ci-github-actions-circleci-jenkins-travis) (comparison and five syntaxes); [GitLab](real-tools/gitlab-ci.md), [GitHub Actions](real-tools/github-actions.md), [Jenkins](real-tools/jenkins.md) | [ci-pipeline-multi-platform](labs/ci-pipeline-multi-platform/README.md) |
| [CDP 2] OWASP ZAP | [Lesson 01 section 5](01-tools-of-the-trade.md#5-owasp-zap-zap-by-checkmarx); [ch06](../06-dynamic-analysis/README.md) | [complete-cicd-pipeline](labs/complete-cicd-pipeline/README.md) |
| [CDP 2] Ansible | [Lesson 01 section 6](01-tools-of-the-trade.md#6-ansible); [ch08](../08-iac-configuration-and-compliance-as-code/README.md) | n/a |
| [CDP 2] Inspec | [Lesson 01 section 7](01-tools-of-the-trade.md#7-inspec-and-cinc-auditor); [ch08](../08-iac-configuration-and-compliance-as-code/README.md) | n/a |
| [CDP 2] Hands-on Labs: | Labs below | [Lab index](#lab-index) |
| [CDP 2] Building a CI Pipeline using Gitlab CI/Jenkins/Travis and Gitlab/Github Actions | [Lesson 01 section 4.2](01-tools-of-the-trade.md#42-the-same-job-in-five-syntaxes); [GitLab](real-tools/gitlab-ci.md), [GitHub Actions](real-tools/github-actions.md), [Jenkins](real-tools/jenkins.md) | [ci-pipeline-multi-platform](labs/ci-pipeline-multi-platform/README.md) |
| [CDP 2] Use the above tools to create a complete CI/CD pipeline. | [Lesson 03 section 6](03-dsomm-path-and-embedding-security.md#6-using-the-tools-of-the-trade-to-do-these-activities-in-cicd); [Lesson 02 section 4](02-secure-sdlc-and-security-gates.md#4-mapping-the-gates-to-pipeline-jobs) | [complete-cicd-pipeline](labs/complete-cicd-pipeline/README.md), [ci-pipeline-multi-platform](labs/ci-pipeline-multi-platform/README.md) |
| [CDP 2] Using BDD security to codify threats. | [Lesson 03 section 6.2](03-dsomm-path-and-embedding-security.md#62-bdd-security-codify-threats-as-tests) (BDD-Security is legacy) | [bdd-security-codify-threats](labs/bdd-security-codify-threats/README.md) |
| [CDP 2] Note: Once you learn the above tools, you will be able to create DevSecOps Pipelines in Cloud providers like AWS, Azure DevOps etc., | [Lesson 01 section 8](01-tools-of-the-trade.md#8-the-note-cloud-providers) (guidance note) | n/a |
| [CDP 3] What is Secure SDLC | [Lesson 02 section 2](02-secure-sdlc-and-security-gates.md#2-what-is-a-secure-sdlc) | n/a |
| [CDP 3] Secure SDLC Activities and Security Gates | [Lesson 02 section 3](02-secure-sdlc-and-security-gates.md#3-secure-sdlc-activities-and-security-gates) (SVG) | n/a |
| [CDP 3] Security Requirements (Requirements) | [Lesson 02 section 3.1](02-secure-sdlc-and-security-gates.md#31-security-requirements-requirements) | [bdd-security-codify-threats](labs/bdd-security-codify-threats/README.md) |
| [CDP 3] Threat Modelling (Design) | [Lesson 02 section 3.2](02-secure-sdlc-and-security-gates.md#32-threat-modelling-design); repo [threat modelling](../../01-ai-security-fundamentals/03-ai-threat-modeling.md) | n/a |
| [CDP 3] Static Analysis and Secure by Default (Implementation) | [Lesson 02 section 3.3](02-secure-sdlc-and-security-gates.md#33-static-analysis-and-secure-by-default-implementation) | [complete-cicd-pipeline](labs/complete-cicd-pipeline/README.md) |
| [CDP 3] Dynamic Analysis (Testing) | [Lesson 02 section 3.4](02-secure-sdlc-and-security-gates.md#34-dynamic-analysis-testing) | [complete-cicd-pipeline](labs/complete-cicd-pipeline/README.md) |
| [CDP 3] OS Hardening, Web/Application Hardening (Deploy) | [Lesson 02 section 3.5](02-secure-sdlc-and-security-gates.md#35-os-hardening-webapplication-hardening-deploy) | [ci-pipeline-multi-platform](labs/ci-pipeline-multi-platform/README.md) |
| [CDP 3] Security Monitoring/Compliance (Maintain) | [Lesson 02 section 3.6](02-secure-sdlc-and-security-gates.md#36-security-monitoring-and-compliance-maintain) | [manage-findings-automatically](labs/manage-findings-automatically/README.md) |
| [CDP 3] DevSecOps Maturity Model (DSOMM) | [Lesson 03 section 2](03-dsomm-path-and-embedding-security.md#2-dsomm-maturity-levels-and-tasks); link to [ch01](../01-devops-devsecops-and-maturity/03-devsecops-toolchain-sdlc-and-dsomm.md#7-devsecops-maturity-model-dsomm-moving-from-level-2-to-level-4) | n/a |
| [CDP 3] Maturity levels and tasks involved | [Lesson 03 section 2](03-dsomm-path-and-embedding-security.md#2-dsomm-maturity-levels-and-tasks) | n/a |
| [CDP 3] 4-axes in DSOMM | [Lesson 03 section 3](03-dsomm-path-and-embedding-security.md#3-the-4-axes-in-dsomm) (caveat: older axes vs newer dimensions) | n/a |
| [CDP 3] How to go from Maturity Level 1 to Maturity Level 4 | [Lesson 03 section 4](03-dsomm-path-and-embedding-security.md#4-how-to-go-from-level-1-to-level-4) | n/a |
| [CDP 3] Best practices for Maturity Level 1 | [Lesson 03 section 5.1](03-dsomm-path-and-embedding-security.md#51-best-practices-for-maturity-level-1) | n/a |
| [CDP 3] Considerations for Maturity Level 2 | [Lesson 03 section 5.2](03-dsomm-path-and-embedding-security.md#52-considerations-for-maturity-level-2) | n/a |
| [CDP 3] Challenges in Maturity Level 3 | [Lesson 03 section 5.3](03-dsomm-path-and-embedding-security.md#53-challenges-in-maturity-level-3) | [manage-findings-automatically](labs/manage-findings-automatically/README.md) |
| [CDP 3] Dream of achieving Maturity Level 2 | [Lesson 03 section 5.4](03-dsomm-path-and-embedding-security.md#54-the-dream-of-achieving-maturity-level-2) | n/a |
| [CDP 3] Usings tools of the trade to do the above activities in CI/CD | [Lesson 03 section 6.1](03-dsomm-path-and-embedding-security.md#61-activity-to-tool-to-pipeline-job) | [ci-pipeline-multi-platform](labs/ci-pipeline-multi-platform/README.md) |
| [CDP 3] Embedding Security as part of CI/CD pipeline | [Lesson 03 section 7](03-dsomm-path-and-embedding-security.md#7-embedding-security-as-part-of-the-cicd-pipeline) | [ci-pipeline-multi-platform](labs/ci-pipeline-multi-platform/README.md) |
| [CDP 3] DevSecOps and challenges with Pentesting and Vulnerability Assessment. | [Lesson 03 section 8](03-dsomm-path-and-embedding-security.md#8-devsecops-vs-pentesting-and-vulnerability-assessment); repo [VM](../../cybersecurity-track/08-vulnerability-management/README.md), [pentesting](../../cybersecurity-track/09-pentesting-fundamentals/README.md) | n/a |
| [CDP 3] Hands-on Labs: | Labs below | [Lab index](#lab-index) |
| [CDP 3] Create a CI/CD pipeline suitable for modern application. | [Lesson 03 section 6.1](03-dsomm-path-and-embedding-security.md#61-activity-to-tool-to-pipeline-job); [Lesson 02 section 4](02-secure-sdlc-and-security-gates.md#4-mapping-the-gates-to-pipeline-jobs) | [complete-cicd-pipeline](labs/complete-cicd-pipeline/README.md), [ci-pipeline-multi-platform](labs/ci-pipeline-multi-platform/README.md) |
| [CDP 3] Manage the findings in a fully automated pipeline. | [Lesson 03 section 6.3](03-dsomm-path-and-embedding-security.md#63-manage-the-findings-in-a-fully-automated-pipeline) | [manage-findings-automatically](labs/manage-findings-automatically/README.md) |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| **Travis** | Travis CI still exists but lost most of its open-source usage after its 2020-21 pricing changes. Teach it briefly as **legacy**; the lab includes a `.travis.yml` because the syllabus lists it. Prefer GitLab CI, GitHub Actions, CircleCI or Jenkins. |
| **OWASP ZAP** | Now **"ZAP by Checkmarx"** (the core team joined Checkmarx in 2024). Same open-source scanner; baseline, full and API scans plus the Automation Framework. Container images are published under `ghcr.io/zaproxy/zaproxy`: verify names on zaproxy.org. |
| **Inspec** | InSpec 6 and later need a **licence key**. **CINC Auditor** is the license-free community build with profile compatibility. OpenSCAP with SCAP Security Guide is another route. |
| **Ansible** (and "Tower" in the Expert course) | Ansible Tower is now **Ansible Automation Platform (AAP)**; **AWX** is the upstream open-source project. Ansible Vault is still current. |
| **Using BDD security to codify threats** | BDD-Security (ContinuumSecurity, later IriusRisk) appears **unmaintained since about 2022**; Gauntlt is old too. Teach the Gherkin idea; use `behave`, `pytest-bdd`, Cucumber, ZAP Automation Framework tests or plain `pytest`. |
| **GitHub Actions** (not named with a pinning rule) | Pin third-party actions to **full commit SHAs**; tags can be moved. Set least-privilege `permissions:` per workflow. |
| **DevSecOps Maturity Model, "4-axes in DSOMM"** | The older description used four axes (static depth, dynamic depth, intensity, consolidation: verify). **Current versions list more dimensions** (for example Build and Deployment, Culture and Organization, Implementation, Information Gathering, Test and Verification) and 4 to 5 levels. Learn the course framing, check the current model for work. |
| **Security requirements** (implied by "Security Requirements (Requirements)") | OWASP ASVS is the common requirements catalogue; version 5.0 was released in 2025 (verify the current version). |
| **"cloud providers like AWS, Azure DevOps"** | Product names and availability change (for example the status of AWS CodeCommit and Google Cloud Source Repositories). The concepts map one to one; verify each service. |
| **Docker** in CI | Mounting `docker.sock` or using privileged mode on runners is a known risk. Prefer rootless builders (Kaniko, BuildKit) and verify tool status. Docker Content Trust is retired (shutdown announced for 8 Dec 2026): use cosign or Notation. |

## Learning order

1. [Lesson 01: tools of the trade](01-tools-of-the-trade.md), including the five-syntax comparison. About 4 hours.
2. [ci-pipeline-multi-platform](labs/ci-pipeline-multi-platform/README.md) lab. About 2 hours.
3. [Lesson 02: secure SDLC and security gates](02-secure-sdlc-and-security-gates.md) (SVG). About 3 hours.
4. [complete-cicd-pipeline](labs/complete-cicd-pipeline/README.md) lab. About 1.5 hours.
5. [Lesson 03: DSOMM path, tools in CI/CD and embedding security](03-dsomm-path-and-embedding-security.md). About 4 hours.
6. [manage-findings-automatically](labs/manage-findings-automatically/README.md) and [bdd-security-codify-threats](labs/bdd-security-codify-threats/README.md) labs. About 4 hours.
7. Optional hands-on with real tools: [GitLab CI](real-tools/gitlab-ci.md), [GitHub Actions](real-tools/github-actions.md), [Jenkins](real-tools/jenkins.md).
8. Then [Chapter 3: security requirements and threat modeling](../03-security-requirements-and-threat-modeling/README.md).

## Lab index

All labs run offline: `.venv/Scripts/python -m pytest devsecops-course/02-tools-pipelines-and-secure-sdlc`.

| Lab | Course exercise | Tests |
|---|---|---|
| [ci-pipeline-multi-platform](labs/ci-pipeline-multi-platform/README.md) | Building a CI Pipeline using Gitlab CI/Jenkins/Travis and Gitlab/Github Actions (the same pipeline in five syntaxes plus a validator) | 44 |
| [complete-cicd-pipeline](labs/complete-cicd-pipeline/README.md) | Use the above tools to create a complete CI/CD pipeline; Create a CI/CD pipeline suitable for modern application | 14 |
| [manage-findings-automatically](labs/manage-findings-automatically/README.md) | Manage the findings in a fully automated pipeline | 26 |
| [bdd-security-codify-threats](labs/bdd-security-codify-threats/README.md) | Using BDD security to codify threats | 23 |

Hedged guides for real tools: [GitLab CI](real-tools/gitlab-ci.md), [GitHub Actions](real-tools/github-actions.md), [Jenkins](real-tools/jenkins.md).

## How the three courses overlap here

This chapter holds the Professional course's tools and secure SDLC chapters. The Expert course repeats **BDD security to codify threats** (also in [chapter 3](../03-security-requirements-and-threat-modeling/README.md) as part of requirements and threat modelling) and the **DSOMM** (level 2 to 4 is in [chapter 1](../01-devops-devsecops-and-maturity/README.md), level 1 to 4 here). The Container Security course's Docker topics reappear in [chapters 9 to 12](../09-container-fundamentals/README.md), Ansible and InSpec in [chapter 8](../08-iac-configuration-and-compliance-as-code/README.md), ZAP in [chapter 6](../06-dynamic-analysis/README.md), and the sibling csse course has more on pipelines in [csse ch1](../../csse-course/ch1-introduction-to-supply-chain-security/README.md), [ch2](../../csse-course/ch2-attacking-code-and-application-supply-chain/README.md) and [ch6](../../csse-course/ch6-common-defenses-against-supply-chain-attacks/README.md).

## Exam tips

- **Pipeline = ordered jobs in a clean environment.** If you know that, you can move between GitLab CI, GitHub Actions, CircleCI, Jenkins and Travis.
- **Know one keyword in all five:** "run after another job" (`stages`/`needs`/`requires`), "run only on main", "use a secret", "manual approval".
- **Pin everything:** actions to commit SHAs, images to tags or digests. `latest` and `@v4` are not pins.
- **Least-privilege tokens:** read-only `permissions`, OIDC instead of static cloud keys, credentials only in the deploy job.
- **Gates vs reports:** `allow_failure`/`continue-on-error` turns a gate into a report.
- **Secure SDLC table:** six phases, each with an activity, a gate and a tool. Be able to draw it.
- **Requirements as tests:** "cookie must be HttpOnly" becomes a Gherkin scenario; BDD-Security is legacy, the idea is not.
- **Findings workflow:** collect, normalise, deduplicate, waive with expiry, threshold, ticket once.
- **DSOMM:** the course says "4 axes"; say it, then add that the current model uses more dimensions.
- **Pentest vs pipeline:** you need both. State what each misses.

## 15 exam-style questions

<details>
<summary>1. Why does the syllabus list GitLab/GitHub, Docker, CI systems, ZAP, Ansible and InSpec together?</summary>

They cover the whole chain: hosting and review (GitLab/GitHub), packaging (Docker), orchestration (CI systems), dynamic testing (ZAP), configuration and hardening (Ansible) and compliance checks (InSpec). Once you know these, the same concepts map to cloud services such as AWS CodePipeline or Azure DevOps.
</details>

<details>
<summary>2. Translate "run this job only on main, after the tests" into GitLab CI, GitHub Actions and Jenkins.</summary>

GitLab: a later stage plus `rules: - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'`. GitHub Actions: `needs: tests` plus `if: github.ref == 'refs/heads/main'`. Jenkins: a later `stage` with `when { branch 'main' }`.
</details>

<details>
<summary>3. Why should you pin GitHub Actions to commit SHAs?</summary>

A tag or branch can be moved by the action's owner or by an attacker who compromises the repository, silently changing code that runs with your token and secrets. A full 40-character commit SHA is immutable. Keep the version in a comment and use a tool such as Dependabot to update the pin after review.
</details>

<details>
<summary>4. What is a least-privilege token in a pipeline?</summary>

A token that can do only what the job needs: for GitHub, `permissions: contents: read` at the top and extra rights per job only (for example `id-token: write` for OIDC in deploy); no `write-all`; no personal access tokens; credentials bound only in the deploy stage; short-lived OIDC credentials instead of static cloud keys.
</details>

<details>
<summary>5. Why is mounting the Docker socket into a CI job dangerous?</summary>

Access to `/var/run/docker.sock` is root-equivalent on the host: the job can start privileged containers, read other jobs' data and escape. Use rootless builders (Kaniko, BuildKit rootless), ephemeral runners and never run untrusted code with the socket.
</details>

<details>
<summary>6. What is the difference between a ZAP baseline scan and a full scan?</summary>

Baseline: spider plus passive checks only, no attacks: fast enough for every deploy to staging. Full: active attacks as well, slower and riskier: run nightly or weekly against a test environment you own. API scans import an OpenAPI definition.
</details>

<details>
<summary>7. What is Travis CI's status today, and how do you handle it in a course or an interview?</summary>

It is still available but has lost most open-source usage since 2020-21, so treat it as legacy. Show you can read a `.travis.yml` (stages, jobs, encrypted variables) and that you would migrate to a maintained system.
</details>

<details>
<summary>8. Name the six phases of the secure SDLC with one activity and one gate each.</summary>

Requirements: security requirements, ASVS-based acceptance criteria. Design: threat modelling, high threats mitigated. Implementation: SAST, SCA, secrets scan pass. Testing: DAST baseline clean. Deploy: hardening and image scan, signature verified. Maintain: monitoring, compliance checks, SLA on findings.
</details>

<details>
<summary>9. What is a security gate and how do you recognise a fake one?</summary>

A rule that can stop the pipeline (a threshold on findings, a failed signature check). A fake gate is a scan that runs with `allow_failure: true`, has no threshold, or runs after deploy: it reports but protects nothing.
</details>

<details>
<summary>10. Describe the four DSOMM levels and the "4 axes". What is the caveat?</summary>

Levels: basic practices, adoption of basic goals, high adoption, advanced deployment at scale. The older description used four axes about testing depth, frequency and consolidation of results. The OWASP model has been revised: current versions list more dimensions and may use different levels, so check dsomm.owasp.org before applying it at work.
</details>

<details>
<summary>11. How would you take a team from level 1 to level 2 without causing a revolt?</summary>

Add dependency, secret and SAST scans in report-only mode, baseline the existing findings so only new ones count, tune the noisy rules, agree who triages, train developers on the top issues you find, and only then start blocking on critical findings.
</details>

<details>
<summary>12. What does "the dream of achieving Maturity Level 2" mean?</summary>

Our reading: many organisations talk about level 3 or 4 automation without having a solid level 2, meaning basic scans running consistently in pipelines across most teams. Level 2 that actually runs everywhere is a valuable, realistic goal; do not skip levels.
</details>

<details>
<summary>13. How do you manage findings in a fully automated pipeline?</summary>

Collect results in standard formats (SARIF, JSON), normalise severity and fields, deduplicate with a stable fingerprint, apply waivers that expire, compare with break-build thresholds, create each ticket once with owner and SLA due date, list tickets whose finding is gone, and report metrics. A platform such as DefectDojo does this at scale.
</details>

<details>
<summary>14. What is BDD security, and what is the status of the BDD-Security tool?</summary>

Writing security requirements as Gherkin scenarios (Given/When/Then) that run automatically against the app, for example "login must lock after 5 failures". The BDD-Security framework appears unmaintained since about 2022 (Gauntlt is old too). Use behave, pytest-bdd, Cucumber, ZAP automation or plain pytest instead.
</details>

<details>
<summary>15. Why do you still need pentests and vulnerability assessments with a DevSecOps pipeline, and vice versa?</summary>

Pipelines find known patterns early and on every change but miss logic, authorisation and design flaws and give false confidence. Pentests find chained and business-logic attacks but are point-in-time and arrive late; VAs cover infrastructure drift at scale but are noisy. Use all three and feed pentest findings back as rules and regression tests.
</details>

## References

- OWASP DevSecOps Maturity Model (dsomm.owasp.org); OWASP ASVS; OWASP SAMM; NIST SP 800-218 (SSDF); Microsoft SDL; BSIMM.
- Docs (verify current syntax): GitLab CI/CD, GitHub Actions (including security hardening), CircleCI, Jenkins, ZAP (zaproxy.org), Ansible, InSpec and CINC Auditor.
- GitHub docs: "Security hardening for GitHub Actions"; SARIF 2.1.0 specification; npm audit documentation.
- Behave, pytest-bdd and Cucumber documentation for Gherkin runners.
- Repo: [csse ch1 CI/CD](../../csse-course/ch1-introduction-to-supply-chain-security/05-cicd-stages-and-deployment.md), [csse ch2 pipeline privilege escalation and pre-commit](../../csse-course/ch2-attacking-code-and-application-supply-chain/README.md), [06 CI/CD module](../../06-ai-devsecops/cicd/README.md), [caisp ch4 poisoned pipeline execution](../../caisp-course/ch4-ai-attacks-and-defenses-devops/04-pipeline-attacks-and-ppe.md), [threat modelling](../../01-ai-security-fundamentals/03-ai-threat-modeling.md), [vulnerability management](../../cybersecurity-track/08-vulnerability-management/README.md).
