# Chapter 6: Supply Chain Security and Governance of MCP

> **Time:** ~20 hours. **You will:** map the MCP supply chain and its incidents, vet third-party servers, generate SBOMs, provenance and signatures, apply SLSA, SCVS and OpenSSF practices, map NIST AI RMF and ISO 42001 to MCP deployments, understand the EU AI Act and US rules for MCP operators, build a compliance posture, and recognise emerging MCP threats.

## Syllabus coverage

Every syllabus line of the chapter, in course order.

| Syllabus item | Where to study | Lab |
|---|---|---|
| Overview of the MCP Supply Chain | [01 MCP supply chain overview](01-mcp-supply-chain-overview.md); [CAISP ch6 lesson 01](../../caisp-course/ch6-supply-chain-attacks-in-ai/01-supply-chain-overview-and-ai-attacks.md) | [backdoor-mcp-package](labs/backdoor-mcp-package/README.md) |
| &nbsp;&nbsp;Components and stages of the MCP supply chain | [01, section 2](01-mcp-supply-chain-overview.md#2-the-stages-of-the-mcp-supply-chain) | inventory your own host config (exercise in 01) |
| &nbsp;&nbsp;Third-party MCP package registries and their risks | [01, section 3](01-mcp-supply-chain-overview.md#3-third-party-mcp-registries-and-their-risks) | n/a |
| &nbsp;&nbsp;Attack vectors introduced by the MCP supply chain | [01, section 4](01-mcp-supply-chain-overview.md#4-attack-vectors-introduced-by-the-mcp-supply-chain) | [backdoor-mcp-package](labs/backdoor-mcp-package/README.md) |
| &nbsp;&nbsp;Real-world supply chain incidents relevant to MCP | [01, section 5](01-mcp-supply-chain-overview.md#5-real-world-incidents-relevant-to-mcp) (postmark-mcp, mcp-remote CVE-2025-6514, Inspector, Filesystem server) | [backdoor-mcp-package](labs/backdoor-mcp-package/README.md) |
| Vetting and Managing Third-Party MCP Servers | [02 Vetting third-party MCP servers](02-vetting-third-party-mcp-servers.md); [CAISP ch6 lesson 02](../../caisp-course/ch6-supply-chain-attacks-in-ai/02-vetting-software-frameworks.md) | [sbom-mcp-server](labs/sbom-mcp-server/README.md), [backdoor-mcp-package](labs/backdoor-mcp-package/README.md); [CAISP package-vetting](../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/package-vetting/) |
| &nbsp;&nbsp;Creating a vetting process for third-party MCP packages | [02, section 1](02-vetting-third-party-mcp-servers.md#1-creating-a-vetting-process-for-third-party-mcp-packages) | write a tier-3 vetting plan (interview question in 02) |
| &nbsp;&nbsp;Dependency analysis and risk scoring | [02, section 2](02-vetting-third-party-mcp-servers.md#2-dependency-analysis-and-risk-scoring) | [sbom-mcp-server](labs/sbom-mcp-server/README.md) (`analyze_sbom`) |
| &nbsp;&nbsp;Scanning MCP server packages for known vulnerabilities | [02, section 3](02-vetting-third-party-mcp-servers.md#3-scanning-mcp-server-packages-for-known-vulnerabilities); [ch5 lesson 05](../ch5-devsecops-for-mcp-security/05-cicd-integration-and-policy-as-code.md) | [sbom-mcp-server](labs/sbom-mcp-server/README.md); [CAISP third-party-vulns](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/third-party-vulns/README.md) |
| &nbsp;&nbsp;Dependency pinning and version locking for MCP servers | [02, section 4](02-vetting-third-party-mcp-servers.md#4-dependency-pinning-and-version-locking-for-mcp-servers) | [backdoor-mcp-package](labs/backdoor-mcp-package/README.md) (`verify_pin`, `check_host_config`) |
| &nbsp;&nbsp;Mitigating dependency confusion in MCP ecosystems | [02, section 5](02-vetting-third-party-mcp-servers.md#5-mitigating-dependency-confusion-in-mcp-ecosystems) | registry check in [sbom-mcp-server](labs/sbom-mcp-server/README.md); [CAISP package-vetting](../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/package-vetting/) (`depconfusion.py`) |
| &nbsp;&nbsp;Automating the vetting of third-party MCP components | [02, section 6](02-vetting-third-party-mcp-servers.md#6-automating-the-vetting-of-third-party-mcp-components) | [ch5 mcp-cicd-pipeline](../ch5-devsecops-for-mcp-security/labs/mcp-cicd-pipeline/README.md) |
| Transparency and Integrity in the MCP Supply Chain | [03 Transparency and integrity](03-transparency-and-integrity.md); [CAISP ch6 lesson 04](../../caisp-course/ch6-supply-chain-attacks-in-ai/04-transparency-and-integrity-sbom-mlbom-signing.md) | [sbom-mcp-server](labs/sbom-mcp-server/README.md), [provenance-attestations](labs/provenance-attestations/README.md), [sign-verify-mcp-build](labs/sign-verify-mcp-build/README.md) |
| &nbsp;&nbsp;Generating Software Bill of Materials (SBOMs) for MCP servers | [03, section 2](03-transparency-and-integrity.md#2-generating-sboms-for-mcp-servers) | [sbom-mcp-server](labs/sbom-mcp-server/README.md) |
| &nbsp;&nbsp;Provenance and attestations for MCP server builds | [03, section 3](03-transparency-and-integrity.md#3-provenance-and-attestations-for-mcp-server-builds) | [provenance-attestations](labs/provenance-attestations/README.md) |
| &nbsp;&nbsp;MCP server signing: concepts and implementation | [03, section 4](03-transparency-and-integrity.md#4-mcp-server-signing-concepts-and-implementation) | [sign-verify-mcp-build](labs/sign-verify-mcp-build/README.md) (offline twin plus hedged cosign commands) |
| &nbsp;&nbsp;Model Cards and MLBOMs in agentic contexts | [03, section 5](03-transparency-and-integrity.md#5-model-cards-and-mlboms-in-agentic-contexts); repo: [07 lesson 05](../../07-ai-governance/05-model-cards-data-documentation-and-transparency.md) | MCP BOM fields in the lesson; [CAISP sbom-and-mlbom](../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/sbom-and-mlbom/) |
| &nbsp;&nbsp;Verifying integrity of third-party MCP servers before deployment | [03, section 6](03-transparency-and-integrity.md#6-verifying-integrity-of-third-party-mcp-servers-before-deployment) | [sign-verify-mcp-build](labs/sign-verify-mcp-build/README.md), [provenance-attestations](labs/provenance-attestations/README.md), [backdoor-mcp-package](labs/backdoor-mcp-package/README.md) |
| Supply Chain Security Frameworks | [04 Supply chain security frameworks](04-supply-chain-frameworks.md); [CAISP ch6 lesson 03](../../caisp-course/ch6-supply-chain-attacks-in-ai/03-supply-chain-frameworks-slsa-and-scvs.md) | self-assessment (exercise in 04) |
| &nbsp;&nbsp;SLSA (Supply chain Levels for Software Artifacts) for MCP builds | [04, section 1](04-supply-chain-frameworks.md#1-slsa-for-mcp-builds) | [provenance-attestations](labs/provenance-attestations/README.md) |
| &nbsp;&nbsp;Software Component Verification Standard (SCVS) | [04, section 2](04-supply-chain-frameworks.md#2-software-component-verification-standard-scvs) | self-assessment table |
| &nbsp;&nbsp;OpenSSF best practices for MCP server maintainers | [04, section 3](04-supply-chain-frameworks.md#3-openssf-best-practices-for-mcp-server-maintainers) | maintainer checklist; optional Scorecard run |
| AI Governance Frameworks | [05 AI governance frameworks applied to MCP](05-ai-governance-frameworks.md); [CAISP ch7 lesson 02](../../caisp-course/ch7-emerging-threats-governance-compliance/02-governance-standards-and-frameworks.md); repo: [07 AI governance](../../07-ai-governance/README.md) | mapping exercise in 05 |
| &nbsp;&nbsp;Standards, guidelines, and frameworks applicable to MCP | [05, section 2](05-ai-governance-frameworks.md#2-standards-guidelines-and-frameworks-applicable-to-mcp) | n/a |
| &nbsp;&nbsp;NIST AI Risk Management Framework (RMF) | [05, section 3](05-ai-governance-frameworks.md#3-nist-ai-rmf-applied-to-mcp) (function to MCP control table); repo: [07 lesson 03](../../07-ai-governance/03-ai-risk-management.md) | fill the table for your deployment |
| &nbsp;&nbsp;ISO/IEC 42001 | [05, section 4](05-ai-governance-frameworks.md#4-isoiec-42001-applied-to-mcp) (Annex A themes to MCP); repo: [07 lesson 04](../../07-ai-governance/04-iso-42001-ai-management-system.md) | evidence exercise in 05 |
| &nbsp;&nbsp;Other emerging standards and guidelines | [05, section 5](05-ai-governance-frameworks.md#5-other-emerging-standards-and-guidelines-watch-list) | n/a |
| &nbsp;&nbsp;Applying governance frameworks to MCP deployments specifically | [05, section 6](05-ai-governance-frameworks.md#6-applying-governance-frameworks-to-mcp-deployments-specifically) | [compliance checklist](mcp-compliance-checklist.md) |
| Compliance and Regulation | [06 Compliance and regulation](06-compliance-and-regulation.md); repo: [08 AI compliance](../../08-ai-compliance/README.md) | [checklist](mcp-compliance-checklist.md) |
| &nbsp;&nbsp;EU AI Act implications for MCP server operators | [06, section 1](06-compliance-and-regulation.md#1-eu-ai-act-implications-for-mcp-server-operators); [CAISP ch7 lesson 03](../../caisp-course/ch7-emerging-threats-governance-compliance/03-eu-ai-act-summary.md); repo: [08 lesson 01](../../08-ai-compliance/01-eu-ai-act.md) | classification memo exercise |
| &nbsp;&nbsp;US AI legislation and executive orders | [06, section 2](06-compliance-and-regulation.md#2-us-ai-legislation-and-executive-orders); [CAISP ch7 lesson 04](../../caisp-course/ch7-emerging-threats-governance-compliance/04-us-ai-legislation.md) | n/a |
| &nbsp;&nbsp;Building an organizational compliance posture for MCP | [06, section 3](06-compliance-and-regulation.md#3-building-an-organizational-compliance-posture-for-mcp) | n/a |
| &nbsp;&nbsp;Compliance checklists for MCP deployment | [06, section 4](06-compliance-and-regulation.md#4-compliance-checklists-for-mcp-deployment) and [mcp-compliance-checklist.md](mcp-compliance-checklist.md) | fill the checklist for the `notes-mcp` fixture |
| Emerging Threats in MCP | [07 Emerging threats in MCP](07-emerging-threats-in-mcp.md); [CAISP ch7 lesson 01](../../caisp-course/ch7-emerging-threats-governance-compliance/01-emerging-threats-in-ai.md) | [CAISP ai-worm-simulation](../../caisp-course/ch7-emerging-threats-governance-compliance/labs/ai-worm-simulation/) |
| &nbsp;&nbsp;Agentic worms propagating autonomously through MCP chains | [07, section 1](07-emerging-threats-in-mcp.md#1-agentic-worms-propagating-through-mcp-chains) | [CAISP ai-worm-simulation](../../caisp-course/ch7-emerging-threats-governance-compliance/labs/ai-worm-simulation/) |
| &nbsp;&nbsp;Shadow MCP servers in enterprise environments | [07, section 2](07-emerging-threats-in-mcp.md#2-shadow-mcp-servers-in-enterprise-environments-owasp-mcp09); repo: [04 secure-operations](../../04-mcp-security/secure-operations/README.md) | endpoint sweep sketch in 07; secure-operations lab |
| &nbsp;&nbsp;Malicious MCP registries and package poisoning | [07, section 3](07-emerging-threats-in-mcp.md#3-malicious-mcp-registries-and-package-poisoning) | [backdoor-mcp-package](labs/backdoor-mcp-package/README.md) |
| &nbsp;&nbsp;AI-assisted exploitation targeting MCP deployments | [07, section 4](07-emerging-threats-in-mcp.md#4-ai-assisted-exploitation-targeting-mcp-deployments-forward-looking) | n/a |
| Hands-on Exercises: | see the lab index below | |
| &nbsp;&nbsp;Backdoor injection into a simulated third-party MCP server package | [01](01-mcp-supply-chain-overview.md), [02](02-vetting-third-party-mcp-servers.md) | [backdoor-mcp-package](labs/backdoor-mcp-package/README.md) |
| &nbsp;&nbsp;Generate an SBOM for an MCP server and analyze its components | [03, section 2](03-transparency-and-integrity.md#2-generating-sboms-for-mcp-servers) | [sbom-mcp-server](labs/sbom-mcp-server/README.md) |
| &nbsp;&nbsp;Sign an MCP server build and verify its integrity on deployment | [03, section 4](03-transparency-and-integrity.md#4-mcp-server-signing-concepts-and-implementation) | [sign-verify-mcp-build](labs/sign-verify-mcp-build/README.md) |
| &nbsp;&nbsp;Create provenance attestations for an MCP server CI/CD pipeline | [03, section 3](03-transparency-and-integrity.md#3-provenance-and-attestations-for-mcp-server-builds) | [provenance-attestations](labs/provenance-attestations/README.md) |

## Lab index

| Lab | Course exercise | Offline | What it proves | Reuses |
|---|---|---|---|---|
| [backdoor-mcp-package](labs/backdoor-mcp-package/README.md) | Backdoor injection into a simulated package | yes (recording transport, canary) | diff review, behavior test, egress allowlist and pinning each catch a postmark-style backdoor | [04 secure-operations](../../04-mcp-security/secure-operations/README.md) (tampered package), [CAISP package-vetting](../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/package-vetting/) |
| [sbom-mcp-server](labs/sbom-mcp-server/README.md) | Generate and analyze an SBOM | yes | CycloneDX-style SBOM; vulnerabilities, licenses, unpinned, registry, depth, risk score | [CAISP sbom-and-mlbom](../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/sbom-and-mlbom/) |
| [sign-verify-mcp-build](labs/sign-verify-mcp-build/README.md) | Sign a build and verify on deploy | yes (HMAC twin; real cosign hedged) | tampering, extra files, rollback and forged manifests are refused | [CAISP model-signing](../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/model-signing/) |
| [provenance-attestations](labs/provenance-attestations/README.md) | Create provenance attestations | yes | in-toto/SLSA statement in a DSSE envelope; deploy gate checks builder, repo, ref, digest | [ch5 mcp-cicd-pipeline](../ch5-devsecops-for-mcp-security/labs/mcp-cicd-pipeline/README.md) |

Run all of them:

```text
.venv/Scripts/python -m pytest cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp -v
```

## Learning order

1. [01](01-mcp-supply-chain-overview.md): stages, registries, incidents (postmark-mcp first). Then the [backdoor lab](labs/backdoor-mcp-package/README.md).
2. [02](02-vetting-third-party-mcp-servers.md), then the [SBOM lab](labs/sbom-mcp-server/README.md).
3. [03](03-transparency-and-integrity.md), then the [signing](labs/sign-verify-mcp-build/README.md) and [provenance](labs/provenance-attestations/README.md) labs.
4. [04](04-supply-chain-frameworks.md): self-assess against SLSA, SCVS and the maintainer checklist.
5. [05](05-ai-governance-frameworks.md): fill the NIST AI RMF table.
6. [06](06-compliance-and-regulation.md) and the [checklist](mcp-compliance-checklist.md): write a classification memo.
7. [07](07-emerging-threats-in-mcp.md).
8. The Q&As below.

## Exam tips for this chapter

- **postmark-mcp** is the anchor case: fake npm package, 15 clean versions, v1.0.16 BCC'd every email to the attacker, reported by Koi Security (Sept 2025). Know the lesson: pin, diff, behavior-test, egress allowlist; a description pin would not have caught it.
- **SBOM vs provenance vs signature:** what is inside, who built it, is it unchanged and from whom.
- **Signing is not vetting.** A signed backdoor is still a backdoor. Keyless verification needs identity and issuer.
- **SLSA Build levels 1 to 3** and what the L3 isolation adds; **SCVS** has three levels and six families.
- **NIST AI RMF:** Govern, Map, Measure, Manage. **ISO 42001:** a certifiable AI management system with Annex A controls. They are different things.
- **EU AI Act:** an MCP server is usually a component; obligations attach to the AI system's provider and deployer; know the Omnibus dates (2 Dec 2027 stand-alone, 2 Aug 2028 embedded) and hedge ("verify").
- **US:** no comprehensive federal statute; executive orders cannot repeal state law.
- **Shadow MCP = MCP09;** detect by endpoint config, process, network, repo and identity discovery.

## 15 exam-style questions

<details><summary>1. Name the stages of the MCP supply chain and one risk at each.</summary>

Source (compromised maintainer), dependencies (vulnerable or confused packages), build (poisoned CI), package (artifact differs from the repo), registry (impersonation, no security scan), install and launch (unpinned `npx`/`uvx` in host config), runtime update (rug pull, remote server changes), agent use (poisoned descriptions and results).
</details>

<details><summary>2. What happened in the postmark-mcp incident and what were the lessons?</summary>

As reported by Koi Security and Snyk (Sept 2025), a fake npm package impersonating Postmark behaved normally for about fifteen versions; v1.0.16 added a BCC to the attacker on every email; it was removed from npm. Lessons: pin exact versions, diff updates, test behavior, restrict egress (recipient domains), verify the publisher. The tool description did not change, so description pinning alone would not catch it.
</details>

<details><summary>3. What does the official MCP Registry verify and what does it not?</summary>

It verifies ownership of a namespace and lists server metadata. Security scanning is left to package registries and aggregators (verify the current state). A verified name is not proof that the code is safe.
</details>

<details><summary>4. Why is `npx -y some-mcp@latest` in a host config risky?</summary>

It downloads and runs the newest unreviewed code on every start, with the user's rights and credentials, and `-y` skips the confirmation. Pin an exact version (or a local mirror copy), verify the hash or signature, and review updates.
</details>

<details><summary>5. How would you design a vetting process for a third-party MCP server?</summary>

Intake form, impact tiering, identity and provenance checks, automated technical checks (SBOM, advisories, licenses, install scripts, tool inventory and description scan, SAST, sandbox behavior test), a decision with concrete conditions (pin, sandbox, egress allowlist, scoped token), registration in the inventory, re-vetting on every change, offboarding.
</details>

<details><summary>6. What goes into a dependency risk score and what are its limits?</summary>

Known vulnerabilities by severity, unpinned or unhashed components, registry not on the allowlist, license problems, transitive depth, plus server-level factors such as the power it holds. It is a triage aid: a zero score does not prove safety (postmark-mcp had no known CVE).
</details>

<details><summary>7. What is dependency confusion and how does it apply to MCP?</summary>

A build resolves an internal package name from the public index where an attacker registered a same-named, higher-versioned package. In MCP, host configs often use bare names and internal servers have guessable names. Use scoped names, point scopes at the internal registry, lock with hashes, allowlist packages, and register the names publicly.
</details>

<details><summary>8. Compare an SBOM and a provenance attestation.</summary>

An SBOM lists components (what is inside). Provenance records which builder built which artifact digest from which source, with which inputs (where, how and by whom). Both should be signed and stored with the release.
</details>

<details><summary>9. What does a deploy gate check in a SLSA-style provenance?</summary>

Valid signature from a trusted key or identity; the artifact digest equals a subject digest; the builder id is trusted; the source repository and ref are the expected ones; the build workflow is the expected one; materials are pinned by digest.
</details>

<details><summary>10. Does a valid signature mean an MCP server is safe? How do you verify keyless cosign signatures properly?</summary>

No. It proves integrity and who signed, not intent. For keyless verification require the expected certificate identity and OIDC issuer; otherwise any validly signed artifact, even the attacker's own, passes.
</details>

<details><summary>11. What are the SLSA build levels and what does an MCP team get at each?</summary>

L1: provenance exists. L2: hosted build with signed provenance. L3: hardened, isolated build platform where user build steps cannot forge provenance. SLSA covers the path from source to artifact, not code quality. (Verify the current version.)
</details>

<details><summary>12. Map the four NIST AI RMF functions to MCP controls.</summary>

Govern: policy, ownership, approvals, vendor due diligence. Map: inventory, data flows, threat models, impact assessment. Measure: pentests, fuzzing, injection tests, scans, metrics. Manage: risk register, gateway policy, incident response, patching, kill switch, decommissioning.
</details>

<details><summary>13. Is an MCP server an AI system under the EU AI Act? When do obligations reach its operator?</summary>

Usually it is a component of an AI system, not one itself, unless it embeds a model. Obligations attach to the provider and deployer of the overall system; they reach a server operator through contracts and cooperation duties for high-risk systems (Article 25), through transparency duties if it generates content, and through other law (GDPR, CRA, NIS2). Under the Digital Omnibus, stand-alone high-risk obligations apply from 2 Dec 2027 and embedded from 2 Aug 2028 (verify).
</details>

<details><summary>14. How do you detect shadow MCP servers?</summary>

Combine endpoint config scans, process and network discovery, repository and package-log searches, OAuth and SaaS connector reviews, and cloud exposure scans; diff the results against the inventory. Then offer an approved catalogue so people do not need to go around you.
</details>

<details><summary>15. Describe how an agentic worm could spread through MCP and how to break it.</summary>

Hidden instructions in content (mail, ticket) are read through a tool, the agent obeys, and writes the same instruction to a place other agents read. Break it with injection screening and content labelling, least privilege (separate read and write agents), human approval for sending or posting, outbound rate limits and duplicate-content detection, audit alerts on fan-out, and a kill switch.
</details>

## References

- Lessons 01 to 07 and the [compliance checklist](mcp-compliance-checklist.md).
- Reports on postmark-mcp (Koi Security, Snyk), CVE-2025-6514 (JFrog), CVE-2025-49596 (Oligo): secondary sources; verify at the originals.
- slsa.dev, OWASP SCVS, openssf.org, sigstore.dev, cyclonedx.org, NIST AI RMF, ISO/IEC 42001, EUR-Lex (AI Act and Digital Omnibus). Verify current versions.
- Previous chapter: [5 DevSecOps for MCP security](../ch5-devsecops-for-mcp-security/README.md).
