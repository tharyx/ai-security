# Lesson 07: Compliance and Governance of Supply Chain Risk

> **Chapter:** 6 · Common Defenses Against Supply Chain Attacks · **Time:** ~4 hours
> **You will:** connect the technical controls to the rules and frameworks that ask for them (EO 14028, NIST SSDF, EU Cyber Resilience Act, SLSA, SCVS, C-SCRM), and collect evidence automatically.

| | |
|---|---|
| **Prerequisites** | Lessons [01](01-proving-integrity-with-cryptography.md) to [06](06-automating-controls-in-ci-cd.md); [Chapter 1](../ch1-introduction-to-supply-chain-security/README.md) |
| **Related repo lessons** | [07 AI governance](../../07-ai-governance/README.md) · [08 AI compliance](../../08-ai-compliance/README.md) (evidence collection) · [risk management track](../../cybersecurity-track/04-risk-management-and-iso27001/README.md) |
| **Labs** | [syft-in-cicd](labs/syft-in-cicd/README.md) and [cosign-container-signing](labs/cosign-container-signing/README.md) produce evidence (SBOM, signature, attestation); [false-positive-analysis](labs/false-positive-analysis/README.md) produces exception records |
| **Syllabus line** | Compliance and Governance of Supply Chain Risk |

> **Dates, numbers and legal text change. Verify at source before you cite them. This lesson is not legal advice.**

## 1. Why governance

Controls without governance decay: scanners get turned off, exceptions pile up, nobody owns a risk. Governance turns controls into **policy, ownership, evidence and review**. Regulation increasingly asks for it explicitly.

## 2. The rules and frameworks to know (verify details)

| Item | What it is | What it asks for in practice |
|---|---|---|
| **US Executive Order 14028** (May 2021) | drove federal software supply-chain requirements: SBOM, secure development practices, attestation | vendors selling to US federal agencies provide a **secure software development attestation** (the CISA common form, based on NIST SSDF practices) and may be asked for SBOMs. EO 14306 (June 2025) amended parts of the earlier cyber orders; check the current state of the attestation requirements. |
| **NIST SSDF, SP 800-218** | Secure Software Development Framework: practice groups to Prepare the Organization, Protect the Software, Produce Well-Secured Software, Respond to Vulnerabilities | **v1.1** is final (Feb 2022). **SP 800-218 Rev. 1 (SSDF v1.2)** had an initial public draft in Dec 2025; check status. SP 800-218A adds GenAI practices. |
| **NIST SP 800-161 Rev. 1 (C-SCRM)** | Cybersecurity Supply Chain Risk Management guidance (the syllabus's "C-SRM" means C-SCRM). May 2022; check for updates. | supplier risk assessment, contract clauses, monitoring |
| **EU Cyber Resilience Act (Regulation 2024/2847)** | horizontal security requirements for products with digital elements sold in the EU | manufacturers must report **actively exploited vulnerabilities and severe incidents** to ENISA/CSIRTs (early warning within 24 hours) **from 11 Sept 2026**; **most other obligations apply from 11 Dec 2027**: security by design, vulnerability handling, **SBOM-like documentation of components**, support periods, CE marking. Open-source stewards have lighter duties. Verify the text and standards under development. |
| **NIS2 (EU)** | cybersecurity duties for essential/important entities, including supply-chain security measures | supplier risk in governance and incident handling |
| **SLSA** | Supply-chain Levels for Software Artifacts (v1.0 Build track L0 to L3; check for later versions) | provenance, hosted build, hardened builds |
| **OWASP SCVS** | Software Component Verification Standard: levels of requirements across inventory, SBOM, build environment, package management, component analysis, pedigree and provenance | a checklist for auditing dependency practice |
| **OpenSSF Scorecard, Best Practices Badge** | automated repo practice checks; the badge is the successor of the CII (Core Infrastructure Initiative) Best Practices self-assessment | evidence for open-source project health |
| **OpenSSF S2C2F** (donated by Microsoft in 2022) | Secure Supply Chain Consumption Framework: how to consume open source safely, with maturity levels | policy for dependency intake |
| **CISA SBOM minimum elements** | NTIA 2021 baseline; an updated proposal in 2025 (verify) | which fields an SBOM must have |
| **ISO/IEC 27001, SOC 2** | general ISMS and assurance frameworks that include supplier management | auditors ask for supplier lists, reviews and evidence |

**Reading the "Supply Chain Integrity Model" and similar names in course material.** Microsoft described an integrity model concept (SCIM), and many organizations use their own integrity models; where a course uses a specific one, follow its definition and map it to SLSA and in-toto (provenance of every step).

## 3. A governance structure that works

1. **Policy**: a short supply-chain security policy (approved sources, required SBOM, signing, license, vulnerability SLAs).
2. **Ownership**: a product owner per asset, a security champion per team, a platform team that runs the pipeline controls.
3. **Standards as code**: the policy is enforced by the pipeline and the registry (see [lesson 06](06-automating-controls-in-ci-cd.md)), not by a PDF.
4. **Vendor and supplier risk**: questionnaires are weak; prefer evidence (SBOMs, attestations, vulnerability disclosure policy, patch history, SLSA/Scorecard signals) and contract clauses (breach notice, SBOM delivery, vulnerability response times).
5. **Exceptions**: recorded with owner, reason and expiry; reviewed regularly ([false-positive-analysis](labs/false-positive-analysis/README.md)).
6. **Metrics** (examples): percentage of builds with a signed SBOM; mean time to patch a critical dependency; number of artifacts deployed without verified signatures (target zero); number of expired exceptions; dependency update lag; findings by age.
7. **Incident readiness**: a playbook for "a dependency is compromised" and "our signing key leaked" with the inventory as the first tool.
8. **Review cycle**: quarterly control review, annual policy review, and a check after major public incidents.

## 4. Evidence automation

Auditors and customers ask for proof. Collect it as a by-product of the pipeline:

| Evidence | Produced by |
|---|---|
| SBOM per release | [syft-in-cicd](labs/syft-in-cicd/README.md) |
| Signature and provenance for each artifact | [cosign-container-signing](labs/cosign-container-signing/README.md) |
| Vulnerability scan results and gate decisions | scanners plus findings store |
| Approvals and change records | merge requests, deployment approvals |
| Exceptions register | suppression files |
| License report | license scanner output |

Store evidence immutably and link it to the artifact digest. The same pattern is used for AI systems in [08 AI compliance](../../08-ai-compliance/README.md).

## 5. How chapter 6 maps to these asks

| Requirement theme | Chapter 6 lesson and lab |
|---|---|
| Know your components (SBOM, inventory) | [lesson 04](04-asset-inventory-and-sboms.md); syft labs |
| Verify what you consume | [lesson 02](02-evaluating-dependencies-before-use.md); guarddog, packj, bomber labs |
| Protect integrity of what you ship | [lesson 01](01-proving-integrity-with-cryptography.md); cosign lab |
| Controlled change | [lesson 03](03-change-control-and-licensed-code.md); harbor lab |
| Find vulnerabilities early | [lesson 06](06-automating-controls-in-ci-cd.md); scanner labs |
| Contain damage | [lesson 05](05-code-isolation-and-sandboxing.md) |
| Report and respond | CRA 24-hour reporting, incident playbook ([chapter 7](../ch7-managing-a-secure-software-supply-chain-program/README.md)) |

## Defend (summary)

Policy plus pipeline enforcement · SBOM, signature, provenance as release evidence · supplier risk based on evidence · exceptions with expiry · metrics and review · a plan for CRA-style vulnerability reporting.

## Hands-on

1. Make a one-page table mapping five of your pipeline controls to SSDF practice groups and to SLSA Build levels.
2. For a product you know, list the CRA duties you would need to prepare before December 2027 and the owner of each.
3. Draft the three SBOM-related contract clauses you would ask a software supplier for.

## Scenarios

- **A customer asks for your SBOM and attestation within two weeks.** What do you need in place? (SBOM generation per release, stored and signed; the attestation form owner; a process to answer questions.)
- **A new critical CVE lands in a library used by 12 products.** What does the CRA-style process require you to be able to do? (Find affected products fast, assess exploitation, notify authorities if actively exploited, ship fixes and tell users.)

## Interview Q&A

<details><summary>What did EO 14028 change for software suppliers?</summary>

It pushed the US federal government to require secure development practices from suppliers, with attestation to NIST SSDF-based practices and SBOM expectations. Details have been updated since, so check current guidance.
</details>

<details><summary>Which two EU Cyber Resilience Act dates should you remember?</summary>

11 September 2026 for reporting of actively exploited vulnerabilities and severe incidents, and 11 December 2027 for most other obligations (verify at source).
</details>

<details><summary>What is the relationship between SSDF, SLSA and SCVS?</summary>

SSDF is a set of secure development practices for organizations, SLSA is a maturity framework for build integrity and provenance, and SCVS is a verification checklist for component management. They overlap and you can map your controls to all three.
</details>

## References

- NIST SP 800-218 (SSDF) and Rev. 1 draft; NIST SP 800-161 Rev. 1; CISA Secure Software Development Attestation Form; EU Regulation 2024/2847 (Cyber Resilience Act); NIS2; SLSA; OWASP SCVS; OpenSSF S2C2F and Scorecard (verify current versions).
- Repo: [08 AI compliance](../../08-ai-compliance/README.md), [07 AI governance](../../07-ai-governance/README.md), [chapter 7](../ch7-managing-a-secure-software-supply-chain-program/README.md).
