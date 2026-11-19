# Chapter 7: Managing a Secure Software Supply Chain Program

This chapter turns the attacks and defenses of chapters 1 to 6 into a **program**: how to see (and not see) supply chain attacks, how to vet components of every kind and automate it, which standards to follow, which best practices to adopt, and how to run vulnerability management with SLAs, exceptions and KPIs. Six labs run offline.

> **Safety.** Every lab is a simulation: fixture registries, fictional package names, fake keys, `.example` domains, no network and no Docker. The real-tool guides in [real-tools](real-tools/README.md) are hedged and never needed by the tests. Only scan systems you own.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Standards change often: **verify at the source**.

## Syllabus coverage

| Syllabus item | Where to study | Lab |
|---|---|---|
| Problems with current Supply Chain Attack Visibility | [Lesson 01](01-supply-chain-attack-visibility.md) | n/a |
| Detection of only known vulnerabilities | [01 section 2](01-supply-chain-attack-visibility.md#2-detection-of-only-known-vulnerabilities) | [defectdojo-basics](labs/defectdojo-basics/README.md) (import, dedup) |
| Detection of unknown vulnerabilities | [01 section 3](01-supply-chain-attack-visibility.md#3-detection-of-unknown-vulnerabilities) | [oss-vetting-process](labs/oss-vetting-process/README.md) (heuristics), [slsa-level-2](labs/slsa-level-2/README.md) (provenance) |
| Creating a vetting process for software components (Commercial, Open Source, Third Party, and Proprietary Code) used throughout SDLC | [02 sections 1 to 3](02-vetting-process-and-automation.md#1-four-kinds-of-component-four-kinds-of-evidence); repo [CAISP lesson 02](../../caisp-course/ch6-supply-chain-attacks-in-ai/02-vetting-software-frameworks.md); diagram [intake workflow](../../images/csse-ch7-vetting-intake-workflow.svg) | [oss-vetting-process](labs/oss-vetting-process/README.md) |
| Automation of vetting and third-party code | [02 section 4](02-vetting-process-and-automation.md#4-automation-of-vetting-and-third-party-code); repo [CI/CD labs](../../06-ai-devsecops/cicd/README.md) | [oss-vetting-process](labs/oss-vetting-process/README.md), [slsa-level-1](labs/slsa-level-1/README.md) (pipeline YAML analysis) |
| Software Supply Chain Industry Standards and Best Practices | [Lesson 03](03-standards-and-frameworks.md) and [Lesson 04](04-best-practices-sbom-scorecard-and-badge.md) | n/a |
| NIST C-SRM or SLSA | [03 section 1](03-standards-and-frameworks.md) (C-SRM is really **C-SCRM**, SP 800-161r1) and [03 section 2](03-standards-and-frameworks.md#2-slsa-supply-chain-levels-for-software-artifacts) (SLSA); diagram [SLSA levels](../../images/csse-ch7-slsa-build-levels.svg) | [slsa-level-1](labs/slsa-level-1/README.md), [slsa-level-2](labs/slsa-level-2/README.md) |
| NIST SSDF | [03 section 3](03-standards-and-frameworks.md#3-nist-ssdf-sp-800-218) | [vuln-management-defectdojo](labs/vuln-management-defectdojo/README.md) (RV practices) |
| Software Component Verification Standard (SCVS) | [03 section 4](03-standards-and-frameworks.md#4-owasp-software-component-verification-standard-scvs); repo [CAISP SCVS](../../caisp-course/ch6-supply-chain-attacks-in-ai/03-supply-chain-frameworks-slsa-and-scvs.md) | n/a |
| Secure Supply Chain Consumption Framework (S2C2F) | [03 section 5](03-standards-and-frameworks.md#5-s2c2f-secure-supply-chain-consumption-framework) | [oss-vetting-process](labs/oss-vetting-process/README.md) |
| Supply Chain Integrity Model | [03 section 6](03-standards-and-frameworks.md#6-supply-chain-integrity-model-scim-and-integrity-models-in-general) (hedged SCIM; in-toto concepts) | [slsa-level-2](labs/slsa-level-2/README.md) |
| Software Supply Chain Best Practices | [Lesson 04](04-best-practices-sbom-scorecard-and-badge.md) and [Lesson 05](05-program-management.md) | n/a |
| SBOM | [04 section 1](04-best-practices-sbom-scorecard-and-badge.md#1-sbom); repo [CAISP sbom-and-mlbom](../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/sbom-and-mlbom/) | [defectdojo-basics](labs/defectdojo-basics/README.md) |
| CycloneDX | [04 section 2](04-best-practices-sbom-scorecard-and-badge.md#2-cyclonedx-and-how-it-compares-with-spdx) | [real-tools](real-tools/scorecard-sbom-and-badge.md) (Syft, cdxgen) |
| OpenSSF  – Automated | [04 section 3](04-best-practices-sbom-scorecard-and-badge.md) (Scorecard checks) | [oss-vetting-process](labs/oss-vetting-process/README.md) (Scorecard-like score) |
| Core Infrastructure Initiative  – Self Assessment | [04 section 4](04-best-practices-sbom-scorecard-and-badge.md#4-core-infrastructure-initiative-self-assessment-the-best-practices-badge) (now the OpenSSF Best Practices Badge) | [real-tools](real-tools/scorecard-sbom-and-badge.md) |
| Hands-On Exercises: | Labs below | [Lab index](#lab-index) |
| Achieving SLSA Level 1 using GitLab/Github | [03 section 2](03-standards-and-frameworks.md#2-slsa-supply-chain-levels-for-software-artifacts) | [slsa-level-1](labs/slsa-level-1/README.md); real guide [slsa-github-gitlab](real-tools/slsa-github-gitlab.md) |
| Achieving SLSA Level 2 using GitLab/github | [03 section 2](03-standards-and-frameworks.md#2-slsa-supply-chain-levels-for-software-artifacts) | [slsa-level-2](labs/slsa-level-2/README.md); real guide [slsa-github-gitlab](real-tools/slsa-github-gitlab.md) |
| Establish a vetting process for open-source components | [02](02-vetting-process-and-automation.md) | [oss-vetting-process](labs/oss-vetting-process/README.md) |
| Working with Defect Dojo | [04 section 5](04-best-practices-sbom-scorecard-and-badge.md#5-defectdojo-as-the-findings-hub) | [defectdojo-basics](labs/defectdojo-basics/README.md); real guide [defectdojo](real-tools/defectdojo.md) |
| Vulnerability Management With DefectDojo | [Lesson 05](05-program-management.md); repo [cybersecurity-track 08](../../cybersecurity-track/08-vulnerability-management/README.md) | [vuln-management-defectdojo](labs/vuln-management-defectdojo/README.md) |
| Handling Dependency Hell | [02 section 5](02-vetting-process-and-automation.md#5-dependency-hell-and-the-security-trade-off) | [dependency-hell](labs/dependency-hell/README.md) |

Program management (roles, KPIs, SLAs, exceptions, EO 14028, EU CRA) is in [Lesson 05](05-program-management.md) and links to [08-ai-compliance control mapping and evidence](../../08-ai-compliance/03-control-mapping-and-evidence.md).

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| "NIST C-SRM" | The framework is **C-SCRM** (Cybersecurity Supply Chain Risk Management), **NIST SP 800-161 Rev.1** (May 2022). Check NIST for updates. It is a supplier-risk *program* guide, not the same thing as SLSA. |
| "NIST C-SRM **or** SLSA" as alternatives | They answer different questions: C-SCRM is organizational risk management; SLSA is build integrity. Use both. |
| "SLSA" levels from 2021 material (levels 1 to 4) | SLSA **v1.0 (Apr 2023)** has a **Build track L0 to L3**. Later versions (v1.1 and beyond) add refinements and possibly other tracks (for example Source): verify at slsa.dev. Provenance is an in-toto Statement v1 with a SLSA provenance v1 predicate. |
| "NIST SSDF" | **SP 800-218 v1.1** is final (Feb 2022). **SP 800-218 Rev.1 (SSDF v1.2)** was released as an initial public draft on **17 Dec 2025**: check whether it has been finalized. **SP 800-218A** covers generative AI development. The CISA secure software development attestation form (2024) is tied to the US federal requirement; EO 14306 (June 2025) amended parts of the earlier cyber orders, so verify what is in force. |
| "Supply Chain Integrity Model" | A Microsoft-originated model (SCIM); status unverified here, so treat it as a concept. Do not confuse it with the identity protocol SCIM or with IETF SCITT. in-toto layouts and attestations are the practical, maintained way to teach integrity models. |
| "S2C2F" | Microsoft's framework, **donated to the OpenSSF in 2022**: look for it under OpenSSF now. |
| "Core Infrastructure Initiative: Self Assessment" | The **CII Best Practices Badge** is now the **OpenSSF Best Practices Badge** (bestpractices.dev); levels passing, silver, gold (and newer baseline tiers: verify). |
| "OpenSSF - Automated" | Means **OpenSSF Scorecard**, with automated checks. The Scorecard check list grows over time. |
| "SBOM" and "CycloneDX" (2021 versions) | CycloneDX is now also **ECMA-424** and has newer spec versions (1.5, 1.6 and later: verify the latest). **SPDX 3.0** (2024) is the newest SPDX. NTIA minimum elements are from 2021; CISA proposed an update in 2025: verify. |
| "Working with Defect Dojo" (old UI screenshots) | DefectDojo is maintained; UI and Docker start-up steps change by release. Use the current docs; the concepts (product, engagement, test, finding, dedup, SLA) are stable. |
| Regulation not in the syllabus | **EU Cyber Resilience Act** (Reg. 2024/2847): reporting duties from **11 Sept 2026**, most obligations from **11 Dec 2027**. **EO 14028** drove SBOMs and attestations. See [Lesson 05](05-program-management.md). |
| Tools named in older labs | Check maintenance before relying on any single-maintainer tool; maintained examples: Syft, Trivy, Grype, OSV-Scanner, cdxgen, GuardDog, TruffleHog, cosign, DefectDojo. |

## Learning order

1. [Lesson 01](01-supply-chain-attack-visibility.md) (known vs unknown). About 3 hours.
2. [Lesson 02](02-vetting-process-and-automation.md), then labs [oss-vetting-process](labs/oss-vetting-process/README.md) and [dependency-hell](labs/dependency-hell/README.md). About 6 hours.
3. [Lesson 03](03-standards-and-frameworks.md), then [slsa-level-1](labs/slsa-level-1/README.md) and [slsa-level-2](labs/slsa-level-2/README.md). About 5 hours.
4. [Lesson 04](04-best-practices-sbom-scorecard-and-badge.md), then [defectdojo-basics](labs/defectdojo-basics/README.md). About 4 hours.
5. [Lesson 05](05-program-management.md), then [vuln-management-defectdojo](labs/vuln-management-defectdojo/README.md). About 4 hours.
6. Read the repo [cybersecurity-track 08](../../cybersecurity-track/08-vulnerability-management/README.md) and [08-ai-compliance](../../08-ai-compliance/README.md) in parallel. Cross-check with [chapter 6 of this course](../ch6-common-defenses-against-supply-chain-attacks/README.md) (common defenses).

## Lab index

All labs run offline: `.venv/Scripts/python -m pytest csse-course/ch7-managing-a-secure-software-supply-chain-program`.

| Lab | Course exercise | Tests |
|---|---|---|
| [slsa-level-1](labs/slsa-level-1/README.md) | Achieving SLSA Level 1 using GitLab/Github | 18 |
| [slsa-level-2](labs/slsa-level-2/README.md) | Achieving SLSA Level 2 using GitLab/github | 16 |
| [oss-vetting-process](labs/oss-vetting-process/README.md) | Establish a vetting process for open-source components | 26 |
| [defectdojo-basics](labs/defectdojo-basics/README.md) | Working with Defect Dojo | 18 |
| [vuln-management-defectdojo](labs/vuln-management-defectdojo/README.md) | Vulnerability Management With DefectDojo | 21 |
| [dependency-hell](labs/dependency-hell/README.md) | Handling Dependency Hell | 34 |

Diagrams: [known vs unknown](../../images/csse-ch7-known-vs-unknown.svg), [intake workflow](../../images/csse-ch7-vetting-intake-workflow.svg), [SLSA levels](../../images/csse-ch7-slsa-build-levels.svg), [DefectDojo model](../../images/csse-ch7-defectdojo-model.svg).

## Exam tips

- **Known vs unknown:** a clean scan means "nothing known", not "safe". Name at least five controls for the unknown (behaviour, heuristics, provenance, reproducible builds, cooldown).
- **Say C-SCRM, SP 800-161 Rev.1.** Then say it is a program framework, not build integrity.
- **SLSA in one breath:** L0 none, L1 provenance exists, L2 hosted builder plus signed provenance, L3 hardened builds. It is about build integrity, not code quality.
- **SSDF:** v1.1 final, v1.2 is a draft (Dec 2025), 800-218A for GenAI; groups PO, PS, PW, RV; the CISA form is an attestation, not a certificate.
- **S2C2F is for consumers of open source; SLSA is for producers.** SCVS has three levels; the Badge has passing, silver, gold.
- **SCIM:** hedge it, then explain integrity models through in-toto (layout, functionaries, links, inspections).
- **CycloneDX vs SPDX:** security-first vs license-first; both fine; VEX removes false positives.
- **Pin does not equal safe.** A pin adds a limit and can freeze a vulnerable version; the clean fix is to upgrade the lagging dependent.
- **Exceptions expire**, and the SLA clock does not reset.
- **Dates:** CRA reporting 11 Sept 2026, main obligations 11 Dec 2027. Hedge: "as reported, verify".

## 15 exam-style questions

<details>
<summary>1. Why can a vulnerability scanner not protect you from xz-utils-style attacks?</summary>

It only matches inventory against known advisories. The xz backdoor had no CVE when shipped, came from a trusted maintainer, and lived in the release build rather than the visible source. Controls that could help: comparing release artifacts with source (reproducibility), provenance, maintainer-change signals, fewer dependencies in critical processes, and runtime anomaly detection.
</details>

<details>
<summary>2. List controls that address unknown supply chain threats.</summary>

Behavioural analysis of installs, malicious-package heuristics, release diffing, provenance and signature policy, reproducible builds, ownership and maintainer monitoring, a cooldown before adopting new versions, and containment (least privilege CI, short-lived tokens, egress control, no install scripts by default).
</details>

<details>
<summary>3. What are the four component types in a vetting process and what extra evidence does each need?</summary>

Open source (Scorecard, advisories, maintainers, license); commercial (vendor SBOM, PSIRT process, attestations, contract terms); third party custom code (contract security clauses, SBOM per delivery, your own SAST and SCA on it); proprietary (enforced review, SAST gate, signed builds and provenance).
</details>

<details>
<summary>4. Describe an automated intake workflow and what stays manual.</summary>

Request form, triage by type and tier, automated checks (score, license, vulnerabilities, maintainer health, malicious heuristics, type checks), decision (approve, conditional, reject) and an audit record. Humans handle justification, exceptions, legal license questions and conditional follow-up. Re-vet on new versions, advisories and maintainer changes.
</details>

<details>
<summary>5. What does "NIST C-SRM" refer to?</summary>

C-SCRM, Cybersecurity Supply Chain Risk Management, in NIST SP 800-161 Rev.1 (May 2022). It guides organizations to manage supplier and supply chain risk at enterprise, mission and operational levels and ties to SP 800-53 controls.
</details>

<details>
<summary>6. State the SLSA v1.0 Build levels.</summary>

L0 no guarantees; L1 provenance exists; L2 hosted build platform that signs provenance; L3 hardened, isolated builds where build steps cannot forge provenance. Check later versions for refinements.
</details>

<details>
<summary>7. What must a consumer verify for SLSA L2 provenance?</summary>

The signature, that the builder identity is on an allowlist, that the subject digest matches the artifact, and that the source repository and ref are the expected ones. Unsigned or self-attested provenance is only L1.
</details>

<details>
<summary>8. What is the status of NIST SSDF and what is the CISA attestation?</summary>

SP 800-218 v1.1 is final (Feb 2022). SP 800-218 Rev.1 (v1.2) was an initial public draft on 17 Dec 2025. SP 800-218A covers GenAI. The CISA Secure Software Development Attestation Form lets a producer attest to a subset of practices (secure environments, trusted source supply chain, provenance of components, vulnerability checks) for US federal customers; EO 14306 (2025) changed parts of the earlier orders, so verify the current requirement.
</details>

<details>
<summary>9. Compare SCVS and S2C2F.</summary>

SCVS is a set of verification requirements for components and supply chain controls with three levels, used to assess a project or vendor. S2C2F is a practice and maturity model (eight practice areas, four levels) for consuming open source safely, donated to OpenSSF in 2022.
</details>

<details>
<summary>10. What is the Supply Chain Integrity Model, and how do you explain integrity models in general?</summary>

SCIM is a Microsoft-originated proposal (hedge: verify status; not the identity protocol SCIM). The general idea is shown by in-toto: a signed layout defines steps and authorized actors, each step emits signed evidence with input and output hashes, and the consumer verifies the whole chain and fails closed on any gap.
</details>

<details>
<summary>11. CycloneDX or SPDX, and what is VEX?</summary>

Both are accepted. CycloneDX (also ECMA-424) is security-oriented and supports VEX, SaaSBOM, CBOM and ML-BOM. SPDX (ISO/IEC 5962:2021 for 2.2.1; 3.0 released 2024) is strong on licenses. VEX states whether a product is actually affected by a CVE in a component, cutting false positives.
</details>

<details>
<summary>12. Name ten OpenSSF Scorecard checks and the Best Practices Badge levels.</summary>

Binary-Artifacts, Branch-Protection, CI-Tests, Code-Review, Dangerous-Workflow, Dependency-Update-Tool, Fuzzing, License, Maintained, Pinned-Dependencies, SAST, Security-Policy, Signed-Releases, Token-Permissions, Vulnerabilities, among others. The Best Practices Badge (formerly CII) has passing, silver and gold levels and is a self-assessment.
</details>

<details>
<summary>13. How does DefectDojo organize and deduplicate results?</summary>

Product, engagement, test, finding. Importers per scanner normalize results; deduplication uses a per-scanner hash of selected fields or the scanner's own id, scoped to an engagement or a product. Reimport closes findings that disappear and reopens regressions.
</details>

<details>
<summary>14. Design SLAs, exceptions and KPIs for vulnerability management.</summary>

Example SLAs: Critical 7 days, High 30, Medium 90, Low 120, with KEV or very high EPSS pulled forward. Risk acceptance needs justification, compensating controls, a different approver, an expiry, and no acceptance of known-exploited issues without an exception board; expiry reactivates the finding without resetting its SLA clock. KPIs: MTTR and SLA compliance by severity, overdue criticals, exception age, SBOM and provenance coverage, time to answer "do we use X?".
</details>

<details>
<summary>15. A diamond dependency forces a choice between a vulnerable old version and a breaking upgrade. What do you do, and which regulations care?</summary>

First look for the clean fix: upgrade the dependent that lags. Otherwise override to the fixed version, run its tests, and record an expiring exception; plan replacement if abandoned. Pinning alone cannot satisfy incompatible ranges and may freeze a vulnerable version, and vendoring makes you own patching. EO 14028-driven attestations and the EU CRA (reporting from 11 Sept 2026, most obligations from 11 Dec 2027) both expect documented vulnerability handling and component due diligence.
</details>

## References

- NIST SP 800-161 Rev.1; SP 800-218 and the Rev.1 draft; SP 800-218A (csrc.nist.gov). CISA Secure Software Development Attestation Form; EO 14028; EO 14306.
- SLSA (slsa.dev) and slsa-github-generator; in-toto (in-toto.io); Sigstore (sigstore.dev).
- OWASP SCVS; OpenSSF S2C2F, Scorecard and Best Practices Badge (bestpractices.dev).
- CycloneDX (cyclonedx.org), ECMA-424; SPDX (spdx.dev); NTIA minimum elements (2021).
- DefectDojo documentation (docs.defectdojo.com).
- Regulation (EU) 2024/2847 (Cyber Resilience Act).
- In this repo: [CAISP chapter 6](../../caisp-course/ch6-supply-chain-attacks-in-ai/README.md), [CMCPSE chapter 6](../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/README.md), [06-ai-devsecops/cicd](../../06-ai-devsecops/cicd/README.md), [cybersecurity-track 08](../../cybersecurity-track/08-vulnerability-management/README.md), [08-ai-compliance](../../08-ai-compliance/README.md).
