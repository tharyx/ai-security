# Chapter 1: Introduction to Supply Chain Security

This chapter gives the map for the whole course: what the software supply chain is, its eight building blocks, a threat model with four SLSA-style families, and how attacks and defenses evolved from 2017 to 2026. The hands-on part covers CI/CD, GitLab stages, continuous deployment and the Equifax case. Four labs run offline.

> **Safety.** Every lab is a simulation: pipelines are parsed and simulated, never executed; the deploy system is in memory; the Equifax data is synthetic (`*.example`). Nothing is scanned or attacked. Never test systems you do not own.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Dates, counts and tool statuses here are hedged: **verify at the source**.

## Syllabus coverage

| Syllabus item | Where to study | Lab |
|---|---|---|
| Course Introduction (About the course, syllabus, and how to approach it) | [Lesson 00 section 2.1](00-how-to-approach-this-course.md#21-course-introduction-about-the-course-syllabus-and-how-to-approach-it); [04 how this course connects](04-how-this-course-connects.md) | n/a |
| About Certification and how to approach it | [Lesson 00 section 2.2](00-how-to-approach-this-course.md#22-about-certification-and-how-to-approach-it) | n/a |
| Course Lab Environment | [Lesson 00 section 2.3](00-how-to-approach-this-course.md#23-course-lab-environment) | [GitLab quickstart](real-tools/gitlab-ci-quickstart.md) |
| Lifetime course support (Mattermost) | [Lesson 00 section 2.4](00-how-to-approach-this-course.md#24-lifetime-course-support-mattermost) | n/a |
| An overview of the Supply Chain Security | [Lesson 01 section 2](01-supply-chain-overview-and-building-blocks.md#2-understand-it-the-supply-chain-from-developer-to-cloud) (with SVG) | n/a |
| Supply Chain Security Building Blocks | [Lesson 01 section 2](01-supply-chain-overview-and-building-blocks.md#2-understand-it-the-supply-chain-from-developer-to-cloud) (table of eight blocks) | n/a |
| &nbsp;&nbsp;Code Creation | [01 section 2.1](01-supply-chain-overview-and-building-blocks.md#21-block-1-code-creation) | n/a |
| &nbsp;&nbsp;Source Code Management (SCM) | [01 section 2.2](01-supply-chain-overview-and-building-blocks.md#22-block-2-source-code-management-scm) | n/a |
| &nbsp;&nbsp;Internal and external (third-party) software inventory | [01 section 2.3](01-supply-chain-overview-and-building-blocks.md#23-block-3-internal-and-external-third-party-software-inventory) | [equifax-case-study](labs/equifax-case-study/README.md) |
| &nbsp;&nbsp;Build system (CI/CD) | [01 section 2.4](01-supply-chain-overview-and-building-blocks.md#24-block-4-build-system-cicd); [05](05-cicd-stages-and-deployment.md) | [how-cicd-works](labs/how-cicd-works/README.md) |
| &nbsp;&nbsp;Application | [01 section 2.5](01-supply-chain-overview-and-building-blocks.md#25-block-5-application) | n/a |
| &nbsp;&nbsp;Containers | [01 section 2.6](01-supply-chain-overview-and-building-blocks.md#26-block-6-containers) | n/a (chapter 3 labs) |
| &nbsp;&nbsp;Clusters | [01 section 2.7](01-supply-chain-overview-and-building-blocks.md#27-block-7-clusters) | n/a (chapter 4 labs) |
| &nbsp;&nbsp;Cloud | [01 section 2.8](01-supply-chain-overview-and-building-blocks.md#28-block-8-cloud) | n/a (chapter 5 labs) |
| Threat Model of Software Supply Chain | [Lesson 02](02-threat-model-of-the-software-supply-chain.md) (with SVG) | n/a |
| &nbsp;&nbsp;Overview of Code Creation (SCM, CI/CD and Application) | [02 section 2.2](02-threat-model-of-the-software-supply-chain.md#22-overview-of-code-creation-scm-cicd-and-application) | [how-cicd-works](labs/how-cicd-works/README.md) |
| &nbsp;&nbsp;Overview of Containers | [02 section 2.3](02-threat-model-of-the-software-supply-chain.md#23-overview-of-containers) | n/a |
| &nbsp;&nbsp;Overview of Clusters | [02 section 2.4](02-threat-model-of-the-software-supply-chain.md#24-overview-of-clusters) | n/a |
| &nbsp;&nbsp;Overview of Cloud | [02 section 2.5](02-threat-model-of-the-software-supply-chain.md#25-overview-of-cloud) | n/a |
| Evolution of Software Supply Chain Security | [Lesson 03](03-evolution-of-supply-chain-attacks.md) (timeline SVG and table) | [equifax-case-study](labs/equifax-case-study/README.md) |
| Hands-On Exercise: | Labs below | [Lab index](#lab-index) |
| &nbsp;&nbsp;Learn how to use our browser-based lab environment | [05 section 2.1](05-cicd-stages-and-deployment.md#21-learn-how-to-use-the-browser-based-lab-environment); [00 section 2.3](00-how-to-approach-this-course.md#23-course-lab-environment) | [GitLab quickstart](real-tools/gitlab-ci-quickstart.md) |
| &nbsp;&nbsp;How CI/CD Works | [05 section 2.2](05-cicd-stages-and-deployment.md#22-how-cicd-works) | [how-cicd-works](labs/how-cicd-works/README.md) |
| &nbsp;&nbsp;Working with Gitlab CI/CD | [05 section 2.3](05-cicd-stages-and-deployment.md#23-working-with-gitlab-cicd) | [gitlab-ci-stages](labs/gitlab-ci-stages/README.md), [GitLab quickstart](real-tools/gitlab-ci-quickstart.md) |
| &nbsp;&nbsp;Understanding Stages in CI/CD Pipelines | [05 section 2.4](05-cicd-stages-and-deployment.md#24-understanding-stages-in-cicd-pipelines) | [gitlab-ci-stages](labs/gitlab-ci-stages/README.md) |
| &nbsp;&nbsp;Continuous Deployment | [05 section 2.5](05-cicd-stages-and-deployment.md#25-continuous-deployment) | [continuous-deployment](labs/continuous-deployment/README.md) |
| &nbsp;&nbsp;How the Equifax Hack Happened | [05 section 2.6](05-cicd-stages-and-deployment.md#26-how-the-equifax-hack-happened); [03](03-evolution-of-supply-chain-attacks.md) | [equifax-case-study](labs/equifax-case-study/README.md) |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| Course material dated about 2021 to 2022 | Study the syllabus term for the exam and the current term for work. Incidents continued: xz-utils and polyfill.io (2024), tj-actions and Shai-Hulud (2025), Mini Shai-Hulud (2026). |
| Evolution stops around SolarWinds and Codecov | Add 3CX (2023), xz-utils, polyfill.io, tj-actions, Shai-Hulud worms and slopsquatting. See [lesson 03](03-evolution-of-supply-chain-attacks.md). |
| Regulation: US EO 14028 as the driver | Still important (SBOM, NIST SSDF). Also: the EU Cyber Resilience Act (Reg. 2024/2847) with vulnerability and incident reporting from **11 Sept 2026** and most duties from **11 Dec 2027**. Check US updates (for example EO 14306 of June 2025). |
| NIST SSDF | SP 800-218 v1.1 (Feb 2022) is final; a Rev.1 (v1.2) draft was published for comment in Dec 2025. Verify the current status. |
| "NIST C-SRM" | The standard is **C-SCRM**, NIST SP 800-161 Rev.1 (May 2022). |
| SLSA levels | SLSA v1.0 (Apr 2023) defines the **Build track**, levels 0 to 3. Old v0.1 material had levels 1 to 4. |
| Docker Content Trust (if mentioned) | Retired (announced 29 Jul 2025; the Notary service shuts down 8 Dec 2026). Use cosign or Notation. |
| GitLab CI keywords from tutorials | Older keywords (`only`/`except`) were replaced by `rules`; runner registration tokens are being replaced by authentication tokens. Check the GitLab docs for your version. |
| Equifax numbers | Counts and dates differ by source (about 147 million people is the commonly cited figure). Cite the primary reports. |

## Learning order

1. [Lesson 00](00-how-to-approach-this-course.md): study plan and lab setup. 45 minutes.
2. [Lesson 01](01-supply-chain-overview-and-building-blocks.md): the eight blocks. 3 hours. Draw the SVG from memory.
3. [Lesson 02](02-threat-model-of-the-software-supply-chain.md): threat model. 3 hours.
4. [Lesson 03](03-evolution-of-supply-chain-attacks.md): timeline. 2 hours.
5. [Lesson 05](05-cicd-stages-and-deployment.md) with labs [how-cicd-works](labs/how-cicd-works/README.md), [gitlab-ci-stages](labs/gitlab-ci-stages/README.md), [continuous-deployment](labs/continuous-deployment/README.md), [equifax-case-study](labs/equifax-case-study/README.md). About 5 hours.
6. [GitLab quickstart](real-tools/gitlab-ci-quickstart.md) in your course lab. 1 hour.
7. [Lesson 04](04-how-this-course-connects.md), then the repo [06-ai-devsecops/cicd](../../06-ai-devsecops/cicd/README.md) and on to chapter 2.

## Lab index

Run all: `.venv/Scripts/python -m pytest csse-course/ch1-introduction-to-supply-chain-security`.

| Lab | Course exercise | Tests |
|---|---|---|
| [how-cicd-works](labs/how-cicd-works/README.md) | How CI/CD Works | 23 |
| [gitlab-ci-stages](labs/gitlab-ci-stages/README.md) | Working with Gitlab CI/CD; Understanding Stages in CI/CD Pipelines | 10 |
| [continuous-deployment](labs/continuous-deployment/README.md) | Continuous Deployment | 19 |
| [equifax-case-study](labs/equifax-case-study/README.md) | How the Equifax Hack Happened | 22 |

Real-tool guide (hedged, never needed by tests): [GitLab CI quickstart](real-tools/gitlab-ci-quickstart.md).

## Exam tips

- **Draw the chain.** Developer, SCM, inventory, build, application, containers, clusters, cloud. Then put one attack and one control on each block.
- **Four families:** source, dependency, build, distribution. Every attack fits one.
- **Know the lesson of each incident**, not only the name: SolarWinds = build trust; Codecov = CI secrets and remote scripts; event-stream and xz-utils = maintainer trust; dependency confusion = namespaces; tj-actions = pin to SHA; Equifax = inventory and patching.
- **Signature is not safety.** It proves who signed, not what the code does.
- **Stages protect only if they come before deploy** and are blocking.
- **Secrets never live in YAML.** Masked, protected variables, or OIDC.
- **Hedge numbers:** "about 147 million", "100,000+ sites", "as reported".
- **Dates:** EU CRA reporting 11 Sept 2026; main obligations 11 Dec 2027.

## 15 exam-style questions

<details>
<summary>1. Define the software supply chain and supply chain security.</summary>

All people, systems and components that touch software from writing to running in production: developers, SCM, dependencies, build systems, artifacts, containers, clusters and cloud. Security means production runs exactly what you intended: reviewed source, known dependencies, a trusted builder, and untampered delivery.
</details>

<details>
<summary>2. List the building blocks and one attack per block.</summary>

Code creation (leaked secret, insecure AI code), SCM (stolen token, no review), inventory (typosquat, unknown vulnerable library), build/CI (poisoned pipeline, leaked CI variables), application (artifact swapped, stolen signing key), containers (malicious base image), clusters (over-privileged CI service account), cloud (long-lived keys, risky IaC module).
</details>

<details>
<summary>3. What are the four SLSA-style threat families?</summary>

Source, dependency, build and distribution threats, with people and credentials cutting across them.
</details>

<details>
<summary>4. Why is the CI/CD system such an attractive target?</summary>

It holds secrets, runs code from many sources, has network access and produces what customers run. One compromise can taint every artifact.
</details>

<details>
<summary>5. What happened at SolarWinds, and what does it teach?</summary>

Attackers compromised the build system and inserted a backdoor into updates that were then signed and delivered. Lesson: protect and verify the build itself (hardened builders, provenance), not only the source.
</details>

<details>
<summary>6. What happened at Codecov?</summary>

The Bash Uploader script was altered (using credentials obtained from a Docker image creation process) and sent CI environment variables to the attacker; found in April 2021. Lesson: do not pipe remote scripts into a shell in CI, verify checksums, minimize secrets in CI.
</details>

<details>
<summary>7. Explain dependency confusion.</summary>

A build tool is tricked into taking a public package with the same name as an internal one, often because the public version number is higher. Fix: scoped namespaces, registry rules that route internal names to the internal registry, pinned hashes.
</details>

<details>
<summary>8. What is special about xz-utils (CVE-2024-3094)?</summary>

A long social-engineering campaign gave the attacker maintainer trust, and the backdoor sat in release tarballs, not plainly in source. It was found by chance. Lessons: maintainer health, compare release artifacts to source, reproducible builds, defense in depth.
</details>

<details>
<summary>9. What happened with tj-actions/changed-files (CVE-2025-30066)?</summary>

Version tags were repointed to malicious code that printed CI secrets into logs. Fix: pin actions to a full commit SHA, restrict allowed actions, rotate exposed secrets, avoid secrets in workflows that run third-party code.
</details>

<details>
<summary>10. How do Shai-Hulud-style worms spread, and how do you reduce risk?</summary>

They steal publish tokens and secrets, then publish infected versions of the victim's other packages. Reduce risk with short-lived or trusted-publishing credentials, 2FA, keeping secrets off developer machines, install-script restrictions and a delay before adopting brand-new versions.
</details>

<details>
<summary>11. How did Equifax happen, in supply-chain terms?</summary>

A known, patched Struts flaw (CVE-2017-5638) stayed in an internet-facing application. The component was not found in time because of incomplete inventory and patching and a scan that missed it. Controls: complete inventory with owners, advisory matching, patch SLAs, verified rescans.
</details>

<details>
<summary>12. Continuous delivery versus continuous deployment?</summary>

Delivery: every good build can be released, a human decides when. Deployment: every build that passes the gates is released automatically.
</details>

<details>
<summary>13. How do you protect a production deploy in GitLab?</summary>

Run it only on a protected branch, with `rules` and `when: manual`, a protected environment requiring approval from someone other than the author, protected variables or OIDC for credentials, promotion of the same artifact digest, health checks and a rollback plan.
</details>

<details>
<summary>14. Why must a security stage come before deploy, and what is wrong with `allow_failure: true` on it?</summary>

A scan after deploy finds problems when they are already in production. With `allow_failure: true` the pipeline continues on findings, so the scan only advises and is not a gate.
</details>

<details>
<summary>15. What changes on 11 September 2026 under the EU Cyber Resilience Act?</summary>

Manufacturers must start reporting actively exploited vulnerabilities and severe incidents to the authorities (first notice within 24 hours). Most other obligations apply from 11 December 2027. Verify details in Regulation (EU) 2024/2847.
</details>

## References

- Your course portal (primary source) and the repo [06-ai-devsecops/cicd](../../06-ai-devsecops/cicd/README.md).
- SLSA <https://slsa.dev> · NIST SSDF SP 800-218 · NIST C-SCRM SP 800-161 Rev.1 · OWASP SCVS · OWASP Top 10 CI/CD Security Risks · OpenSSF Scorecard.
- GitLab CI/CD docs <https://docs.gitlab.com/ee/ci/>.
- Public incident write-ups and NVD entries for CVE-2017-5638, CVE-2024-3094, CVE-2025-30066. EU CRA: Regulation (EU) 2024/2847 on EUR-Lex.
- Always verify numbers and dates at the source.
