# Lesson 03: Software Supply Chain Industry Standards and Best Practices (frameworks)

> **Chapter:** 7 · Managing a Secure Software Supply Chain Program · **Time:** ~5 hours
> **You will:** explain NIST C-SCRM, SLSA, NIST SSDF, OWASP SCVS, S2C2F and the Supply Chain Integrity Model, say when to use each and what its maturity levels are, and run the two SLSA labs.

| | |
|---|---|
| **Prerequisites** | [Lesson 02](02-vetting-process-and-automation.md) |
| **Labs** | [slsa-level-1](labs/slsa-level-1/README.md) · [slsa-level-2](labs/slsa-level-2/README.md) |
| **Syllabus lines** | Software Supply Chain Industry Standards and Best Practices · NIST C-SRM or SLSA · NIST SSDF · Software Component Verification Standard (SCVS) · Secure Supply Chain Consumption Framework (S2C2F) · Supply Chain Integrity Model |
| **Diagram** | [SLSA build levels](../../images/csse-ch7-slsa-build-levels.svg) |
| **Reuse** | [CAISP SLSA and SCVS](../../caisp-course/ch6-supply-chain-attacks-in-ai/03-supply-chain-frameworks-slsa-and-scvs.md) · [CMCPSE frameworks](../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/04-supply-chain-frameworks.md) · [CMCPSE provenance lab](../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/labs/provenance-attestations/README.md) |

> **Hedge.** Standards are revised often. Numbers, level names and dates below are the author's best recollection as of Nov 2026. **Verify at the source** before putting them in a policy or an exam answer.

## Why this matters

Standards give you a shared vocabulary for auditors, customers and your own roadmap. After the SolarWinds build compromise (2020), US Executive Order 14028 (2021) pushed SBOMs and secure-development attestation across government suppliers; the EU Cyber Resilience Act now does something similar for products on the EU market ([lesson 05](05-program-management.md)). You need to know what each framework **is for**.

## Quick map: which standard answers which question

| Question | Framework | Kind |
|---|---|---|
| How does an organization manage supplier and third-party cyber risk? | NIST **C-SCRM** (SP 800-161 Rev.1) | Risk management program guidance and controls |
| How do I prove how my artifacts were built? | **SLSA** | Levels for build integrity |
| What secure development practices must I follow? | NIST **SSDF** (SP 800-218) | Practice catalog |
| How do I verify the components inside my software? | OWASP **SCVS** | Verification requirements, 3 levels |
| How do I safely *consume* open source? | **S2C2F** | Practice and maturity model, 4 levels |
| How do parties exchange integrity claims about artifacts? | Supply Chain Integrity Model (**SCIM**, Microsoft) and **in-toto** concepts | Model and attestation framework |

## 1. NIST C-SRM = C-SCRM (SP 800-161 Rev.1)

The syllabus writes "NIST C-SRM". The real name is **C-SCRM: Cybersecurity Supply Chain Risk Management**. The document is **NIST SP 800-161 Revision 1**, *Cybersecurity Supply Chain Risk Management Practices for Systems and Organizations* (May 2022). Check NIST's site for later updates.

| Aspect | What to know |
|---|---|
| **Scope** | All suppliers of ICT and OT: hardware, software, services. Software supply chain security is one part of it. |
| **Three levels** | Enterprise (strategy, policy), mission/business process (plans, requirements), operational (system-level controls). |
| **Process** | Frame, Assess, Respond, Monitor (aligned with NIST's risk management approach). |
| **Artifacts** | A C-SCRM strategy and implementation plan, policies, supplier criticality analysis, supplier assessments, contract requirements. |
| **Controls** | Supply-chain-focused guidance mapped onto SP 800-53 controls (for example the SR control family). |
| **Maturity** | The publication describes foundational, sustaining and enhancing implementation levels for practices (verify the exact wording). |
| **When to use** | You buy or build for US federal customers, or you need a board-level supplier-risk program. It is a program framework, **not** a build-integrity spec. |

Related, same family: NIST SP 800-53 Rev.5 (SR family), NIST CSF 2.0 (a "Govern" function with a supply chain risk management category), and SP 800-218 below.

## 2. SLSA: Supply-chain Levels for Software Artifacts

SLSA ("salsa") is a framework of incremental guarantees about **how an artifact was produced**. Hosted at the OpenSSF.

| Item | Detail (verify at slsa.dev) |
|---|---|
| **Version** | **v1.0** (Apr 2023) defines a **Build track**. Later versions (v1.1 and beyond) refine wording and may add other tracks such as Source: check the current spec. v0.1 had levels 1 to 4; v1.0 renumbered. |
| **Level 0** | No guarantees. |
| **Level 1** | The build is scripted/automated and **provenance exists**: what was built, from which source, by which process. It can be unsigned and forged. |
| **Level 2** | The build runs on a **hosted build platform** that **generates and signs** the provenance. Consumers can detect tampering after the build. |
| **Level 3** | **Hardened builds**: runs are isolated from each other, signing material is unreachable by build steps, so even a malicious build step cannot forge provenance. |
| **Provenance format** | An in-toto **Statement v1** carrying a SLSA **provenance v1** predicate (`buildDefinition`: build type, external and internal parameters, resolved dependencies; `runDetails`: builder id, metadata). |
| **Verification** | Check signature, builder identity against an allowlist, subject digest against the artifact, and source repo/ref against expectation. Tools: `slsa-verifier`, `gh attestation verify`, cosign. |
| **When to use** | Any organization shipping software or images. Start at L1 everywhere, L2 for released artifacts, L3 for critical ones, using a platform that provides it. |

How real pipelines get there (hedged):
- **GitHub:** the `slsa-github-generator` reusable workflows (generic, container, language-specific) aim at L3; GitHub's artifact attestations (`actions/attest-build-provenance`, verified with `gh attestation verify`) give signed provenance via Sigstore. Check the docs for the level each gives.
- **GitLab:** the runner can emit artifact metadata (provenance-style statements), and newer GitLab versions add signing options. Check the GitLab docs for the current feature and its level.

Labs: [slsa-level-1](labs/slsa-level-1/README.md) (generate and check) and [slsa-level-2](labs/slsa-level-2/README.md) (sign and verify with an HMAC twin). The syllabus's "Level 1/2" labs correspond to the Build track.

**Exam trap:** SLSA does not say the software is *secure*. It says how it was built. A malicious maintainer's build can have perfect provenance.

## 3. NIST SSDF (SP 800-218)

The **Secure Software Development Framework** is a catalog of secure development practices, outcome-based and language-neutral.

| Item | Detail |
|---|---|
| **v1.1 (final, Feb 2022)** | Four groups: **PO** Prepare the Organization, **PS** Protect the Software, **PW** Produce Well-Secured Software, **RV** Respond to Vulnerabilities. About 19 practices, each with tasks and references to other standards. |
| **v1.2 (draft)** | **SP 800-218 Rev.1** initial public draft was released on 17 Dec 2025 (SSDF v1.2). Draft: do not treat it as final; check status and changes. |
| **SP 800-218A** | Community profile adding practices for **generative AI and dual-use foundation models** development. |
| **Maturity** | SSDF has no levels. Organizations use implementation tiers or their own scale; the CISA form below is attestation (yes/no), not maturity. |
| **CISA attestation** | The **Secure Software Development Attestation Form** (2024, under OMB memos M-22-18 and M-23-16) lets a software producer attest to a subset of SSDF practices for federal customers: secure development environments, trusted source code supply chain, provenance of internal and third-party components, and vulnerability checking and response. Executive Order 14306 (June 2025) amended parts of the earlier cyber orders; verify the current status of the attestation requirement. |
| **When to use** | Selling to US government, or as your secure-SDLC checklist. Map your own SDLC controls to SSDF practices. |

Where each lab fits: PW.4 (reuse well-secured software: [vetting lab](labs/oss-vetting-process/README.md)), PS.3 (archive and protect releases, provenance: SLSA labs), RV.1 to RV.3 (identify, analyze, remediate vulnerabilities: [vuln management lab](labs/vuln-management-defectdojo/README.md)).

## 4. OWASP Software Component Verification Standard (SCVS)

A community standard of **verification requirements** for software components and their supply chain.

| Item | Detail (verify on owasp.org) |
|---|---|
| **Control families** | Inventory; Software Bill of Materials; Build Environment; Package Management; Component Analysis; Pedigree and Provenance. |
| **Levels** | **Level 1** (baseline for most software), **Level 2** (more rigorous: sensitive or business-critical), **Level 3** (highest assurance: critical infrastructure and high risk). Each requirement is tagged with the levels it applies to. |
| **Use** | A checklist for assessing a project, a vendor or your own pipeline. Good for turning "do we manage components well?" into testable items. |
| **When to use** | Internal maturity assessment and supplier audits. Fine-grained component checks, while SLSA is about build integrity and SSDF about practices. |

See also [CAISP SCVS lesson](../../caisp-course/ch6-supply-chain-attacks-in-ai/03-supply-chain-frameworks-slsa-and-scvs.md).

## 5. S2C2F: Secure Supply Chain Consumption Framework

Written by Microsoft and **donated to the OpenSSF in 2022** (supply chain integrity work). It is about **consuming open source safely**, not about producing it.

| Item | Detail (verify at the OpenSSF project page) |
|---|---|
| **Eight practice areas** | Ingest, Inventory, Update, Enforce, Audit, Scan, Rebuild, Fix and Upstream. |
| **Four maturity levels** | **Level 1** minimum hygiene (use a package manager, local copy of ingested OSS, inventory); **Level 2** secure consumption and faster response (update, scan for known vulns, enforce); **Level 3** malware defense and zero-day detection (audit and verify, scan for malware, rebuild); **Level 4** advanced threat defense (deeper analysis, validate provenance, fix and contribute upstream). |
| **Threats it targets** | Compromised or malicious packages, dependency confusion, typosquats, upstream compromise, vulnerable dependencies. |
| **When to use** | As a roadmap for your open-source consumption program: it maps straight onto the vetting process of [lesson 02](02-vetting-process-and-automation.md) (local mirror = Ingest, SBOM = Inventory, Dependabot = Update, allowlist = Enforce). |

## 6. Supply Chain Integrity Model (SCIM) and integrity models in general

**Hedge:** "Supply Chain Integrity Model" is the name of a Microsoft-originated proposal (SCIM). The author could not verify its current status, so use it as a concept and check Microsoft's and OpenSSF's pages for the latest. Do not confuse it with the identity provisioning protocol also called SCIM (System for Cross-domain Identity Management), nor with the IETF **SCITT** (Supply Chain Integrity, Transparency and Trust) work on transparency logs for signed statements.

The idea shared by all of these: **supply chain parties exchange signed, machine-readable claims (attestations) about artifacts, and a consumer applies policy to them.**

### 6.1 in-toto as the worked example

| in-toto concept | Meaning |
|---|---|
| **Layout** | The expected supply chain, signed by the project owner: the **steps** (clone, build, test, package), who (which **functionary** key) may perform each step, and what each must take in and produce. |
| **Link / attestation** | Evidence a functionary produces for a step: materials in, products out, with hashes, signed. Modern in-toto uses **attestations** in the Statement format (also used by SLSA). |
| **Inspection** | A check the *consumer* runs on the final product (for example: does the unpacked tarball match what the build produced?). |
| **Verification** | Apply the layout to the collected evidence: right steps, right signers, products of step N equal materials of step N+1. Any gap fails the check. |

Why it matters: a stolen token or a swapped file between "build" and "release" breaks the chain of hashes. This is the same mechanism behind SLSA provenance ([lab 2](labs/slsa-level-2/README.md) verifies one link of such a chain).

### 6.2 Generic integrity-model checklist

1. Define the expected steps and who may perform them.
2. Make each step emit signed evidence with input and output hashes.
3. Store evidence somewhere tamper-evident (transparency log).
4. Verify policy at the consumption point, **fail closed**.
5. Plan for key and identity compromise (short-lived keys, revocation).

## 7. Choosing and combining

| If you need to... | Start with |
|---|---|
| Answer an enterprise questionnaire or federal customer | SSDF + C-SCRM mapping |
| Prove build integrity for released artifacts | SLSA (L2 now, L3 for crown jewels) |
| Harden how you pull in open source | S2C2F + vetting process |
| Assess a project or vendor in detail | SCVS |
| Share integrity claims between teams or companies | in-toto attestations (and SCIM as a model) |

They overlap on purpose: map once, reuse the evidence ([control mapping and evidence](../../08-ai-compliance/03-control-mapping-and-evidence.md)).

## 8. Real-world scenarios

1. **Federal customer asks for an attestation.** *Investigate:* which SSDF practices you can evidence today. *Fix:* map SDLC controls to SSDF, collect evidence (branch protection settings, SBOMs, scan reports, provenance), have an executive sign the attestation, record gaps with dates.
2. **Customer asks "SLSA level?".** *Answer honestly:* per pipeline and per artifact; "L2 for container images from GitHub Actions with attestations verified at deploy; L1 for desktop installers". A single number for a company is a red flag.
3. **Provenance exists but nobody checks it.** *Fix:* the verification policy (builder allowlist, repo, digest) must run in the deploy path (admission or release gate).

## 9. Common mistakes

- Claiming "SLSA L3" because a tool is installed, without verifying the builder is isolated.
- Producing provenance that no consumer verifies.
- Treating SSDF as a certification (it is a framework; the attestation is a producer's statement).
- Confusing C-SCRM (supplier risk program) with SLSA (build integrity).
- Quoting SSDF v1.2 as final while it is a draft.

## 10. Interview Q&A

<details><summary><b>Q1. What is "NIST C-SRM"?</b></summary>
It is C-SCRM, Cybersecurity Supply Chain Risk Management, in NIST SP 800-161 Rev.1 (May 2022): a program-level guide for managing supplier and supply chain cyber risk across enterprise, mission and operational levels, with controls aligned to SP 800-53.
</details>

<details><summary><b>Q2. Summarize SLSA Build levels.</b></summary>
L0 nothing. L1 provenance exists. L2 hosted build platform plus signed provenance. L3 hardened builds where build steps cannot forge provenance. It describes build integrity, not code quality.
</details>

<details><summary><b>Q3. How is SSDF different from SLSA?</b></summary>
SSDF is a broad catalog of secure development practices (PO, PS, PW, RV). SLSA is specific to artifact build integrity and provenance. SLSA evidence supports some SSDF practices.
</details>

<details><summary><b>Q4. What is S2C2F for, and what are its levels?</b></summary>
A framework for safely consuming open source. Eight practice areas and four levels, from basic ingest and inventory (L1) to advanced threat defense (L4). Donated to OpenSSF in 2022.
</details>

<details><summary><b>Q5. What does in-toto add that a signature alone does not?</b></summary>
A signed layout of expected steps and authorized actors, evidence per step with hashes, and a verification that the chain of products and materials is intact. A signature only says who signed one thing.
</details>

## 11. Checklist

- [ ] I can say what "C-SRM" in the syllabus really is.
- [ ] I can describe SLSA L0 to L3 and what each stops.
- [ ] I can explain SSDF v1.1 vs the v1.2 draft and the CISA form.
- [ ] I can state SCVS and S2C2F levels and when to use each.
- [ ] I can hedge SCIM correctly and explain integrity models with in-toto.

## 12. References

- NIST SP 800-161 Rev.1; NIST SP 800-218 and the SP 800-218 Rev.1 draft; NIST SP 800-218A (csrc.nist.gov).
- SLSA specification (slsa.dev); slsa-framework/slsa-github-generator; slsa-verifier.
- OWASP SCVS (owasp.org/www-project-software-component-verification-standard).
- OpenSSF S2C2F (github.com/ossf/s2c2f).
- in-toto (in-toto.io); Sigstore (sigstore.dev); IETF SCITT working group.
- CISA Secure Software Development Attestation Form; OMB M-22-18 and M-23-16.
- Next: [Lesson 04](04-best-practices-sbom-scorecard-and-badge.md).
