# Chapter 16: API Security, the DevSecOps Way

This chapter puts API security into the delivery pipeline and scales it across many APIs: OWASP ASVS checklists with automated evidence, SCA/SAST/DAST as pipeline gates, a simple CI/CD pipeline, continuous deployment of microservices with admission policies and rollback, and the practices that make API security work at scale. It also covers the Security Champion course's DevSecOps basics and Infrastructure-as-Code/Ansible chapters, mostly by **linking** to the repo's [devsecops-course](../../devsecops-course/README.md), where those topics already have full lessons and labs.

> **Safety.** Every lab is a simulation: JSON fixtures, a pipeline runner whose steps are Python functions (no shell), fictional advisories (`EXAMPLE-2026-NNNN`), FAKE tokens and a FAKE signing key built at runtime. Nothing is deployed or scanned. Only test systems you own or have written permission to test.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Tool status and version numbers are hedged: **verify at the source**.

## Syllabus coverage

Sources: **[CASP 9]** API Security chapter 9 "API Security, the DevSecOps Way", **[CSC 5]** Security Champion chapter 5 "DevSecOps Basics" and **[CSC 6]** Security Champion chapter 6 "Infrastructure as Code and Its Security". Every line is listed verbatim and in source order. Where the courses repeat a topic (ASVS, SCA/SAST/DAST in CI/CD), both rows are kept and point to the same lesson.

| Syllabus item | Where to study | Lab |
|---|---|---|
| [CASP 9] OWASP ASVS Framework | [Lesson 01 section 1](01-owasp-asvs-for-apis.md#1-owasp-asvs-framework-in-five-sentences); full lesson in [ch02](../02-secure-code-review-and-asvs/03-owasp-asvs.md) | [api-asvs-at-scale](labs/api-asvs-at-scale/README.md) |
| [CASP 9] Understanding OWASP ASVS | [Lesson 01 section 2](01-owasp-asvs-for-apis.md#2-understanding-owasp-asvs-from-an-api-point-of-view) | [api-asvs-at-scale](labs/api-asvs-at-scale/README.md) |
| [CASP 9] Using ASVS To Secure Applications and APIs | [Lesson 01 section 3](01-owasp-asvs-for-apis.md#3-using-asvs-to-secure-applications-and-apis) | [api-asvs-at-scale](labs/api-asvs-at-scale/README.md) |
| [CASP 9] Creating Checklists With OWASP ASVS | [Lesson 01 section 4](01-owasp-asvs-for-apis.md#4-creating-checklists-with-owasp-asvs); [ch02 checklist lab](../02-secure-code-review-and-asvs/labs/asvs-checklist-generator/README.md) | [api-asvs-at-scale](labs/api-asvs-at-scale/README.md) |
| [CASP 9] Automated Vulnerability Discovery | [Lesson 02 section 1](02-automated-vulnerability-discovery.md#1-automated-vulnerability-discovery-what-each-technique-sees) | [sca-sast-dast-gates](labs/sca-sast-dast-gates/README.md) |
| [CASP 9] Finding Insecure Dependencies Using Software Component Analysis | [Lesson 02 section 2](02-automated-vulnerability-discovery.md#2-finding-insecure-dependencies-using-software-component-analysis); [devsecops ch04](../../devsecops-course/04-software-component-analysis/README.md) | [sca-sast-dast-gates](labs/sca-sast-dast-gates/README.md) (OSV JSON) |
| [CASP 9] Finding Vulnerabilities in Code Using Static Application Security Testing | [Lesson 02 section 3](02-automated-vulnerability-discovery.md#3-finding-vulnerabilities-in-code-using-static-application-security-testing); [devsecops ch05](../../devsecops-course/05-static-analysis-and-secrets/README.md) | [sca-sast-dast-gates](labs/sca-sast-dast-gates/README.md) (SARIF) |
| [CASP 9] Automating API Attacks Using Dynamic Application Security Testing | [Lesson 02 section 4](02-automated-vulnerability-discovery.md#4-automating-api-attacks-using-dynamic-application-security-testing); [devsecops ch06](../../devsecops-course/06-dynamic-analysis/README.md) | [sca-sast-dast-gates](labs/sca-sast-dast-gates/README.md) (ZAP JSON); [devsecops openapi-zap-api-scan](../../devsecops-course/06-dynamic-analysis/labs/openapi-zap-api-scan/README.md) |
| [CASP 9] Addressing API Security Issues at Scale | [Lesson 03 section 1](03-api-security-at-scale-and-cicd.md#1-addressing-api-security-issues-at-scale) (SVG) | [api-asvs-at-scale](labs/api-asvs-at-scale/README.md) (portfolio, inventory hygiene) |
| [CASP 9] Creating a Simple CI/CD Pipeline | [Lesson 03 section 2](03-api-security-at-scale-and-cicd.md#2-creating-a-simple-cicd-pipeline) | [simple-cicd-pipeline](labs/simple-cicd-pipeline/README.md) |
| [CASP 9] Deploying a Microservice(s) Using Continuous Deployment | [Lesson 03 section 4](03-api-security-at-scale-and-cicd.md#4-deploying-microservices-using-continuous-deployment) | [microservice-continuous-deployment](labs/microservice-continuous-deployment/README.md) |
| [CASP 9] Embedding Software Composition Analysis Into CI/CD Pipeline | [Lesson 03 section 5](03-api-security-at-scale-and-cicd.md#5-embedding-sca-sast-and-dast-into-the-pipeline) | [sca-sast-dast-gates](labs/sca-sast-dast-gates/README.md) |
| [CASP 9] Embedding Static Application Security Testing Into CI/CD Pipeline | [Lesson 03 section 5](03-api-security-at-scale-and-cicd.md#5-embedding-sca-sast-and-dast-into-the-pipeline) | [sca-sast-dast-gates](labs/sca-sast-dast-gates/README.md) |
| [CASP 9] Embedding Dynamic Application Security Testing Into CI/CD Pipeline | [Lesson 03 section 5](03-api-security-at-scale-and-cicd.md#5-embedding-sca-sast-and-dast-into-the-pipeline) | [sca-sast-dast-gates](labs/sca-sast-dast-gates/README.md) |
| [CSC 5] DevOps Building Blocks – People, Process, and Technology | [Lesson 04 section 1](04-devsecops-basics-for-champions.md#1-devops-building-blocks-people-process-and-technology); [devsecops ch01](../../devsecops-course/01-devops-devsecops-and-maturity/01-devops-foundations.md#3-the-building-blocks-people-process-technology) | n/a |
| [CSC 5] DevOps Principles – Culture, Automation, Measurement and Sharing (CAMS) | [Lesson 04 section 2](04-devsecops-basics-for-champions.md#2-devops-principles-cams); [devsecops ch01](../../devsecops-course/01-devops-devsecops-and-maturity/01-devops-foundations.md#4-cams-the-four-principles) | n/a |
| [CSC 5] Benefits of DevOps – Speed, Reliability, Availability, Scalability, Automation, Cost, and Visibility | [Lesson 04 section 3](04-devsecops-basics-for-champions.md#3-benefits-of-devops); [devsecops ch01](../../devsecops-course/01-devops-devsecops-and-maturity/01-devops-foundations.md#5-benefits-of-devops) | n/a |
| [CSC 5] Overview of the DevSecOps critical toolchain | [Lesson 04 section 4](04-devsecops-basics-for-champions.md#4-overview-of-the-devsecops-critical-toolchain); [devsecops ch01 lesson 03](../../devsecops-course/01-devops-devsecops-and-maturity/03-devsecops-toolchain-sdlc-and-dsomm.md#2-the-devsecops-critical-toolchain) | n/a |
| [CSC 5] Repository management tools | [Lesson 04 section 4.1](04-devsecops-basics-for-champions.md#41-repository-management-tools) | n/a |
| [CSC 5] Continuous Integration and Continuous Deployment tools | [Lesson 04 section 4.2](04-devsecops-basics-for-champions.md#42-continuous-integration-and-continuous-deployment-tools) | [simple-cicd-pipeline](labs/simple-cicd-pipeline/README.md) |
| [CSC 5] Artifact Management Tools | [Lesson 04 section 4.3](04-devsecops-basics-for-champions.md#43-artifact-management-tools) | [csse ch6 harbor-registry-policy](../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/harbor-registry-policy/README.md) |
| [CSC 5] Infrastructure as Code (IaC) tools | [Lesson 04 section 4.4](04-devsecops-basics-for-champions.md#44-infrastructure-as-code-iac-tools); [lesson 05](05-iac-and-ansible-for-champions.md) | n/a |
| [CSC 5] Distributed and Scalable Infrastructure | [Lesson 04 section 4.5](04-devsecops-basics-for-champions.md#45-distributed-and-scalable-infrastructure) | n/a |
| [CSC 5] Monitoring and Logging tools | [Lesson 04 section 4.6](04-devsecops-basics-for-champions.md#46-monitoring-and-logging-tools); [ch15 lesson 04](../15-implementing-api-security-mechanisms/04-logging-and-monitoring.md) | [ch15 secure-logging-syslog-elk](../15-implementing-api-security-mechanisms/labs/secure-logging-syslog-elk/README.md) |
| [CSC 5] Communication and sharing tools | [Lesson 04 section 4.7](04-devsecops-basics-for-champions.md#47-communication-and-sharing-tools) | n/a |
| [CSC 5] Common Challenges faced when using the DevOps principles | [Lesson 04 section 5](04-devsecops-basics-for-champions.md#5-common-challenges-faced-when-using-the-devops-principles); [devsecops ch01](../../devsecops-course/01-devops-devsecops-and-maturity/01-devops-foundations.md#6-common-challenges-and-what-to-do) | n/a |
| [CSC 5] Secure SDLC | [Lesson 04 section 6](04-devsecops-basics-for-champions.md#6-secure-sdlc); [devsecops ch02 lesson 02](../../devsecops-course/02-tools-pipelines-and-secure-sdlc/02-secure-sdlc-and-security-gates.md) | n/a |
| [CSC 5] Overview of secure SDLC and CI/CD | [Lesson 04 section 6.1](04-devsecops-basics-for-champions.md#61-overview-of-secure-sdlc-and-cicd) | n/a |
| [CSC 5] Review of security activities in secure SDLC | [Lesson 04 section 6.2](04-devsecops-basics-for-champions.md#62-review-of-security-activities-in-secure-sdlc) | n/a |
| [CSC 5] Continuous Integration and Continuous Deployment | [Lesson 04 section 6.3](04-devsecops-basics-for-champions.md#63-continuous-integration-and-continuous-deployment); [lesson 03 section 3](03-api-security-at-scale-and-cicd.md#3-continuous-integration-vs-continuous-delivery-vs-continuous-deployment) | [simple-cicd-pipeline](labs/simple-cicd-pipeline/README.md), [microservice-continuous-deployment](labs/microservice-continuous-deployment/README.md) |
| [CSC 5] Working with docker commands | [Lesson 04 section 7](04-devsecops-basics-for-champions.md#7-working-with-docker-commands) | [devsecops ch09 docker-command](../../devsecops-course/09-container-fundamentals/labs/docker-command/README.md) |
| [CSC 5] Manage Data in Docker | [Lesson 04 section 8](04-devsecops-basics-for-champions.md#8-managing-data-in-docker) | [devsecops ch09 manage-data](../../devsecops-course/09-container-fundamentals/labs/manage-data/README.md) |
| [CSC 5] Working With GitLab CI/CD | [Lesson 04 section 9](04-devsecops-basics-for-champions.md#9-working-with-gitlab-cicd); [devsecops GitLab guide](../../devsecops-course/02-tools-pipelines-and-secure-sdlc/real-tools/gitlab-ci.md) | [simple-cicd-pipeline](labs/simple-cicd-pipeline/README.md), [csse ch1 gitlab-ci-stages](../../csse-course/ch1-introduction-to-supply-chain-security/labs/gitlab-ci-stages/README.md) |
| [CSC 5] Integrating Software Component Analysis (SCA) in CI/CD pipeline | [Lesson 04 section 10](04-devsecops-basics-for-champions.md#10-integrating-sca-sast-and-dast-in-the-cicd-pipeline); [lesson 03 section 5](03-api-security-at-scale-and-cicd.md#5-embedding-sca-sast-and-dast-into-the-pipeline) | [sca-sast-dast-gates](labs/sca-sast-dast-gates/README.md) |
| [CSC 5] Integrating Static Application Security Testing (SAST) in CI/CD pipeline | [Lesson 04 section 10](04-devsecops-basics-for-champions.md#10-integrating-sca-sast-and-dast-in-the-cicd-pipeline) | [sca-sast-dast-gates](labs/sca-sast-dast-gates/README.md) |
| [CSC 5] Integrating Dynamic Application Security Testing (DAST) in CI/CD pipeline | [Lesson 04 section 10](04-devsecops-basics-for-champions.md#10-integrating-sca-sast-and-dast-in-the-cicd-pipeline) | [sca-sast-dast-gates](labs/sca-sast-dast-gates/README.md) |
| [CSC 6] Infrastructure as Code and its benefits | [Lesson 05 section 1](05-iac-and-ansible-for-champions.md#1-infrastructure-as-code-and-its-benefits); [devsecops ch08](../../devsecops-course/08-iac-configuration-and-compliance-as-code/01-iac-and-configuration-management.md) | n/a |
| [CSC 6] Platform + Infrastructure Definition + Configuration Management | [Lesson 05 section 2](05-iac-and-ansible-for-champions.md#2-platform--infrastructure-definition--configuration-management) | n/a |
| [CSC 6] Introduction to Ansible | [Lesson 05 section 3](05-iac-and-ansible-for-champions.md#3-introduction-to-ansible); [devsecops ch08 lesson 02](../../devsecops-course/08-iac-configuration-and-compliance-as-code/02-ansible-and-ansible-security.md) | n/a |
| [CSC 6] Benefits of Ansible | [Lesson 05 section 4](05-iac-and-ansible-for-champions.md#4-benefits-of-ansible) | n/a |
| [CSC 6] Modules, tasks, roles, and Playbooks | [Lesson 05 section 5](05-iac-and-ansible-for-champions.md#5-modules-tasks-roles-and-playbooks) | n/a |
| [CSC 6] Tools and Services that help to achieve IaC | [Lesson 05 section 6](05-iac-and-ansible-for-champions.md#6-tools-and-services-that-help-to-achieve-iac) | n/a |
| [CSC 6] Working with Ansible | [Lesson 05 section 7](05-iac-and-ansible-for-champions.md#7-working-with-ansible) | [devsecops ch08 docker-and-ansible](../../devsecops-course/08-iac-configuration-and-compliance-as-code/labs/docker-and-ansible/README.md) |
| [CSC 6] Using Ansible to harden Infrastructure | [Lesson 05 section 8](05-iac-and-ansible-for-champions.md#8-using-ansible-to-harden-infrastructure) | [devsecops ch08 ansible-golden-image-hardening](../../devsecops-course/08-iac-configuration-and-compliance-as-code/labs/ansible-golden-image-hardening/README.md), [ansible-pci-dss-hardening](../../devsecops-course/08-iac-configuration-and-compliance-as-code/labs/ansible-pci-dss-hardening/README.md) |
| [CSC 6] Working with Ansible Playbooks | [Lesson 05 section 9](05-iac-and-ansible-for-champions.md#9-working-with-ansible-playbooks) | [devsecops ch08 docker-and-ansible](../../devsecops-course/08-iac-configuration-and-compliance-as-code/labs/docker-and-ansible/README.md) (playbook linter) |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| **OWASP ASVS** (no version) | **ASVS 5.0.0** (May 2025) renumbered requirements and chapters (17 chapters, including V4 API and Web Service, V9 Self-contained Tokens, V10 OAuth and OIDC). Keep your own ids mapped to ASVS ids. |
| SAST tools | **Semgrep** (the **Opengrep** fork appeared in 2025), CodeQL, Bandit, SonarQube. Use SARIF output. |
| SCA tools | osv-scanner, pip-audit, npm audit, Trivy, Grype, Snyk; **OWASP Dependency-Check needs an NVD API key**. Prioritise with CISA KEV and EPSS. |
| DAST (ZAP) | **ZAP by Checkmarx**; ZAP API scan with OpenAPI and the Automation Framework. GitLab's DAST analyzer is now browser-based (verify). Burp Suite DAST (formerly Enterprise), Dastardly, Nuclei. |
| **Ansible Tower** | Now **Ansible Automation Platform**; **AWX** is upstream. Hardening collections such as `devsec.hardening` (verify). |
| **Terraform** as the IaC tool | Terraform is BSL-licensed since 2023; **OpenTofu** is the open-source fork. tfsec was merged into **Trivy**. |
| Continuous deployment without supply-chain controls | Sign images (**cosign/Sigstore**), attach SBOMs, enforce with admission policies (Kyverno, Gatekeeper); SLSA provenance. |
| Image-based secrets in CI | Use **OIDC** federation from CI to clouds and Vault/OpenBao instead of long-lived keys. |

## How the three courses overlap here

- **ASVS** appears in CASP 9 and in CSC 2. The full ASVS lesson and checklist lab live in [chapter 02](../02-secure-code-review-and-asvs/README.md); this chapter adds the API, multi-API and pipeline-evidence angle.
- **SCA/SAST/DAST in CI/CD** appears in CASP 9 ("Embedding ...") and CSC 5 ("Integrating ..."): both rows point to the same lesson and the same [sca-sast-dast-gates lab](labs/sca-sast-dast-gates/README.md).
- **DevSecOps basics (CSC 5)** and **IaC/Ansible (CSC 6)** are already taught in depth in the repo's [devsecops-course](../../devsecops-course/README.md) chapters 01, 02, 04, 05, 06, 08 and 09, and in [csse-course](../../csse-course/README.md) chapters 1 and 2. Lessons 04 and 05 summarise them and link each item; no lab is duplicated.

## Learning order

1. [Lesson 01](01-owasp-asvs-for-apis.md) (after chapter 02's ASVS lesson), then the [api-asvs-at-scale lab](labs/api-asvs-at-scale/README.md). About 1.5 hours.
2. [Lesson 02](02-automated-vulnerability-discovery.md). About 1 hour.
3. [Lesson 03](03-api-security-at-scale-and-cicd.md), then the [simple-cicd-pipeline](labs/simple-cicd-pipeline/README.md), [sca-sast-dast-gates](labs/sca-sast-dast-gates/README.md) and [microservice-continuous-deployment](labs/microservice-continuous-deployment/README.md) labs. About 3.5 hours.
4. [Lesson 04](04-devsecops-basics-for-champions.md) and the linked devsecops Docker and GitLab labs you have not done yet. About 1 hour plus labs.
5. [Lesson 05](05-iac-and-ansible-for-champions.md) and the linked devsecops ch08 Ansible labs. About 45 minutes plus labs.

## Lab index

All labs run offline: `.venv/Scripts/python -m pytest appsec-course/16-api-security-the-devsecops-way -q -p no:cacheprovider`.

| Lab | Course exercise | Tests |
|---|---|---|
| [api-asvs-at-scale](labs/api-asvs-at-scale/README.md) | Creating checklists with ASVS; addressing API security at scale | 8 |
| [simple-cicd-pipeline](labs/simple-cicd-pipeline/README.md) | Creating a simple CI/CD pipeline; working with GitLab CI/CD | 8 |
| [microservice-continuous-deployment](labs/microservice-continuous-deployment/README.md) | Deploying microservices using continuous deployment | 8 |
| [sca-sast-dast-gates](labs/sca-sast-dast-gates/README.md) | Embedding / integrating SCA, SAST and DAST into CI/CD | 9 |

Linked labs elsewhere in the repo (not duplicated): Docker [docker-command](../../devsecops-course/09-container-fundamentals/labs/docker-command/README.md) and [manage-data](../../devsecops-course/09-container-fundamentals/labs/manage-data/README.md); GitLab [gitlab-ci-stages](../../csse-course/ch1-introduction-to-supply-chain-security/labs/gitlab-ci-stages/README.md); Ansible [docker-and-ansible](../../devsecops-course/08-iac-configuration-and-compliance-as-code/labs/docker-and-ansible/README.md), [ansible-golden-image-hardening](../../devsecops-course/08-iac-configuration-and-compliance-as-code/labs/ansible-golden-image-hardening/README.md), [ansible-pci-dss-hardening](../../devsecops-course/08-iac-configuration-and-compliance-as-code/labs/ansible-pci-dss-hardening/README.md).

## Exam tips

- **ASVS:** three levels, L2 is the usual target, 5.0 renumbered ids. Keep your own ids.
- **SCA finds known CVEs in libraries, SAST finds patterns in your code, DAST finds what fires at runtime.** None finds BOLA reliably: write authorization tests.
- **Gate on what matters:** KEV or fixable HIGH/CRITICAL for SCA, high-confidence rules for SAST, High risk for DAST. Suppressions need owner, reason and expiry.
- **Pipeline security:** protected branches and variables, masked logs, pinned images, OIDC, reviewed pipeline files.
- **CD safety:** digest-pinned signed images, same digest from staging to prod, admission control, canary + automatic rollback.
- **At scale:** inventory first (owner, contract, gateway), then paved roads and champions.
- **CAMS** = Culture, Automation, Measurement, Sharing. Benefits: speed, reliability, availability, scalability, automation, cost, visibility.
- **Ansible:** agentless, SSH, idempotent, YAML playbooks; module < task < play/playbook < role < collection.

## Interview / exam questions

<details>
<summary>1. What is OWASP ASVS and how would you use it for 50 APIs?</summary>

A catalogue of verifiable security requirements with three levels (5.0.0 is current). For 50 APIs: give each a level and feature profile, generate a checklist per API, attach a verification method to each requirement, collect evidence from pipelines automatically, and review a portfolio dashboard. Untested L1 items fail the gate.
</details>

<details>
<summary>2. ASVS vs the OWASP API Security Top 10?</summary>

The Top 10 lists the most common API risks (awareness and prioritisation). ASVS lists the detailed requirements to verify (a standard for building and testing). Map each Top 10 risk to ASVS requirements and tests.
</details>

<details>
<summary>3. What do SCA, SAST and DAST each find, and what do they all miss?</summary>

SCA: known vulnerabilities in dependencies. SAST: insecure patterns in source code. DAST: vulnerabilities observable on the running API. All miss most business-logic and authorization flaws such as BOLA, which need tests built from the permission matrix and manual testing.
</details>

<details>
<summary>4. How do you prioritise hundreds of SCA findings?</summary>

Known exploited (CISA KEV) first, then high EPSS, then severity with a fix available, then reachability of the vulnerable code and internet exposure of the service. Unfixable items get a tracked risk decision.
</details>

<details>
<summary>5. How do you make SAST useful to developers?</summary>

Small set of high-confidence blocking rules, custom rules for your framework's dangerous patterns, results in the merge request (SARIF), quick triage of false positives, warnings for the rest, and metrics on fix time.
</details>

<details>
<summary>6. How do you run DAST against an API in CI?</summary>

Deploy to a staging environment, give the scanner the OpenAPI/GraphQL schema, authenticate it with test users of different roles, run a baseline scan per deploy and a full active scan nightly, fail on High alerts, and publish the report. Only against systems you own or are authorised to test.
</details>

<details>
<summary>7. What makes a security gate trustworthy rather than ignored?</summary>

It fails only on important, high-confidence issues, gives clear fix guidance, is fast, and has a governed exception process (owner, reason, expiry). Everything else becomes a warning and a ticket.
</details>

<details>
<summary>8. Name five ways to secure the CI/CD pipeline itself.</summary>

Protected branches and code review for pipeline files; protected and masked variables, none for forked MRs; OIDC short-lived credentials instead of stored keys; pinned images and actions by digest; isolated runners for deployment; artifact digests and signatures; audit logs.
</details>

<details>
<summary>9. Continuous delivery vs continuous deployment?</summary>

Continuous delivery keeps every passing build releasable and a person approves the release. Continuous deployment releases every passing build automatically, which requires strong automated gates, progressive delivery and automatic rollback.
</details>

<details>
<summary>10. How do you deploy microservices safely with continuous deployment?</summary>

Immutable digest-pinned signed images with SBOMs; admission policies; promote the same digest through environments; deploy in dependency order with backward-compatible APIs; rolling or canary releases with health checks and metric analysis; automatic rollback; GitOps for auditability.
</details>

<details>
<summary>11. What does "API security at scale" require beyond tools?</summary>

A complete API inventory with owners and contracts, gateway-only exposure, paved-road templates and libraries, policy as code, champions in every team, ASVS checklists with automated evidence, and metrics such as coverage and time to remediate.
</details>

<details>
<summary>12. Explain CAMS with a security example for each letter.</summary>

Culture: blameless reviews of security incidents and champions in teams. Automation: SCA/SAST/DAST and IaC scanning in pipelines. Measurement: time to fix critical findings, coverage. Sharing: reusable secure templates and threat-model libraries across teams.
</details>

<details>
<summary>13. What are the DevSecOps toolchain categories?</summary>

Repository management, CI/CD, artifact management, infrastructure as code, distributed and scalable infrastructure (containers, orchestration), monitoring and logging, communication and sharing, plus security-as-code tools across all of them.
</details>

<details>
<summary>14. What are the benefits and risks of Infrastructure as Code?</summary>

Benefits: repeatable, fast, reviewable, versioned, scannable before deploy, rebuildable. Risks: one bad template is copied everywhere, secrets in code or state files, over-privileged pipeline credentials, drift if people still click in consoles. Mitigate with IaC scanners, policy as code and remote encrypted state.
</details>

<details>
<summary>15. How does Ansible help harden infrastructure, and how do you prove it worked?</summary>

Idempotent playbooks and roles apply a baseline (SSH, sysctl, auditd, packages, permissions, firewall) to every host over SSH without agents. Prove it with compliance scans (InSpec/CINC Auditor, OpenSCAP) in the pipeline, keep secrets in Ansible Vault or a secret manager, and lint playbooks.
</details>

## References

- OWASP ASVS 5.0.0; OWASP API Security Top 10 2023; OWASP DevSecOps Guideline; OWASP DSOMM; OWASP SAMM.
- SARIF 2.1.0; OSV schema; ZAP by Checkmarx docs; Semgrep/Opengrep, CodeQL, osv-scanner, Trivy docs; CISA KEV; FIRST EPSS.
- NIST SP 800-218 (SSDF); SLSA; Sigstore; Argo Rollouts; Kyverno; GitLab CI/CD docs; Ansible docs; OpenTofu docs.
- Repo: [devsecops-course](../../devsecops-course/README.md), [csse-course](../../csse-course/README.md), [chapter 02 ASVS](../02-secure-code-review-and-asvs/README.md).

**Next chapter:** [Chapter 17: Agile Communication and Soft Skills](../17-agile-communication-and-soft-skills/README.md)
