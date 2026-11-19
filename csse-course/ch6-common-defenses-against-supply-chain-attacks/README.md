# Chapter 6: Common Defenses Against Supply Chain Attacks

This chapter is the defender's toolbox: prove integrity with cryptography (signing, TUF), vet dependencies, control change, keep an asset inventory and SBOMs, isolate code, automate controls in CI/CD (SCA, SAST, IaC, DAST, fuzzing) and run governance. Twenty labs, one per course exercise, run offline as **twins** and each README has a **hedged guide to the real tool**.

> **Safety.** Twins use fixtures only: FAKE keys (some match real key *formats* so the rules can be tested), harmless canary strings instead of malware, `.example` domains, fictional advisory ids. The only network code is a local server bound to `127.0.0.1` in the DAST lab (started and stopped inside the tests, with a scope guard). Tests never need Docker, Kubernetes, a network or a cloud account. Use real tools only on systems you own.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Tool behavior, versions and laws change: **verify at the source**.

## Syllabus coverage

| Syllabus item | Where to study | Lab |
|---|---|---|
| Prove the sanity of the software components using Cryptography | [Lesson 01 section 1](01-proving-integrity-with-cryptography.md#1-prove-the-sanity-of-the-software-components-using-cryptography) | [cosign-container-signing](labs/cosign-container-signing/README.md) |
| Code Signing | [Lesson 01 section 2](01-proving-integrity-with-cryptography.md#2-code-signing) | n/a |
| Component Signing | [Lesson 01 section 3](01-proving-integrity-with-cryptography.md#3-component-signing); repo [CAISP model-signing](../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/model-signing) | [cosign-container-signing](labs/cosign-container-signing/README.md) |
| Artifact Signing | [Lesson 01 section 4](01-proving-integrity-with-cryptography.md#4-artifact-signing); repo [CMCPSE sign-verify-mcp-build](../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/labs/sign-verify-mcp-build), [provenance-attestations](../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/labs/provenance-attestations) | [cosign-container-signing](labs/cosign-container-signing/README.md) |
| The Update Framework | [Lesson 01 section 5](01-proving-integrity-with-cryptography.md#5-the-update-framework) (roles, thresholds, Uptane; SVG) | n/a (concept; see the SVG) |
| Evaluate dependencies before use | [Lesson 02](02-evaluating-dependencies-before-use.md); repo [CAISP package-vetting](../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/package-vetting), [CAASE skill-vetting](../../caase-course/ch4-computer-use-browser-and-coding-agents/labs/skill-vetting) | [guarddog-malicious-package](labs/guarddog-malicious-package/README.md), [packj-risk-scoring](labs/packj-risk-scoring/README.md) |
| Analyze the security and compliance of dependencies | [Lesson 02 section 1](02-evaluating-dependencies-before-use.md#1-analyze-the-security-and-compliance-of-dependencies) (OpenSSF Scorecard, licenses, maintainers) | [packj-risk-scoring](labs/packj-risk-scoring/README.md), [bomber-sbom-scan](labs/bomber-sbom-scan/README.md) |
| Implement integrity checks or policies | [Lesson 02 section 2](02-evaluating-dependencies-before-use.md#2-implement-integrity-checks-or-policies) | [guarddog-malicious-package](labs/guarddog-malicious-package/README.md); repo [package-vetting](../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/package-vetting) (hash pinning) |
| Implement Change Control | [Lesson 03 section 1](03-change-control-and-licensed-code.md#1-implement-change-control); repo [06 cicd](../../06-ai-devsecops/cicd/README.md) | [harbor-registry-policy](labs/harbor-registry-policy/README.md) |
| Protected Branches | [Lesson 03 section 1](03-change-control-and-licensed-code.md#11-protected-branches) (CODEOWNERS, required reviews, signed commits) | [syft-in-cicd](labs/syft-in-cicd/README.md) (pipeline lint) |
| Licensed Code | [Lesson 03 section 2](03-change-control-and-licensed-code.md#2-licensed-code) (license compliance, copyleft) | [syft-app-sbom](labs/syft-app-sbom/README.md) (license fields) |
| Configuration management and change control | [Lesson 03 section 3](03-change-control-and-licensed-code.md#3-configuration-management-and-change-control); repo [06 terraform](../../06-ai-devsecops/terraform/README.md) | [harbor-registry-policy](labs/harbor-registry-policy/README.md) (immutable tags) |
| Create Asset Inventory | [Lesson 04 section 1](04-asset-inventory-and-sboms.md#1-create-asset-inventory) | [syft-app-sbom](labs/syft-app-sbom/README.md), [syft-container-sbom](labs/syft-container-sbom/README.md) |
| Generate a Software Bill Of Materials | [Lesson 04 section 2](04-asset-inventory-and-sboms.md#2-generate-a-software-bill-of-materials); repo [CAISP sbom-and-mlbom](../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/sbom-and-mlbom), [CMCPSE sbom-mcp-server](../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/labs/sbom-mcp-server) | [syft-app-sbom](labs/syft-app-sbom/README.md), [syft-container-sbom](labs/syft-container-sbom/README.md) |
| Application SBOM | [Lesson 04 section 2.2](04-asset-inventory-and-sboms.md#22-application-sbom) | [syft-app-sbom](labs/syft-app-sbom/README.md) |
| Container SBOM | [Lesson 04 section 2.3](04-asset-inventory-and-sboms.md#23-container-sbom) | [syft-container-sbom](labs/syft-container-sbom/README.md), [tern-layer-sbom](labs/tern-layer-sbom/README.md) |
| Hosts SBOM | [Lesson 04 section 2.4](04-asset-inventory-and-sboms.md#24-hosts-sbom) | [syft-container-sbom](labs/syft-container-sbom/README.md) (dpkg/apk database parsing is the same idea) |
| Code Isolation and Sandboxing | [Lesson 05](05-code-isolation-and-sandboxing.md); repo [06 docker](../../06-ai-devsecops/docker/README.md), [06 runtime security](../../06-ai-devsecops/runtime-security/README.md), [CAASE workspace-escape](../../caase-course/ch4-computer-use-browser-and-coding-agents/labs/workspace-escape) | [kubescape-manifest-scan](labs/kubescape-manifest-scan/README.md), [yarahunter-malware-scan](labs/yarahunter-malware-scan/README.md) |
| Automation of Common Controls in CI/CD | [Lesson 06 section 1](06-automating-controls-in-ci-cd.md#1-automation-of-common-controls-in-cicd) (GitLab-style, SVG) | [syft-in-cicd](labs/syft-in-cicd/README.md) |
| Software Component Analysis of Code, and Containers | [Lesson 06 section 2](06-automating-controls-in-ci-cd.md#2-software-component-analysis-of-code-and-containers) | [trivy-docker-scan](labs/trivy-docker-scan/README.md), [snyk-container-scan](labs/snyk-container-scan/README.md), [bomber-sbom-scan](labs/bomber-sbom-scan/README.md) |
| Static Security Analysis of Application Code, Infrastructure as Code | [Lesson 06 section 3](06-automating-controls-in-ci-cd.md#3-static-security-analysis-of-application-code-infrastructure-as-code) | [sast-in-pipeline](labs/sast-in-pipeline/README.md), [kubescape-manifest-scan](labs/kubescape-manifest-scan/README.md), [kubescape-helm-scan](labs/kubescape-helm-scan/README.md) |
| Dynamic Security Analysis of Applications, APIs, Containers, and Clusters | [Lesson 06 section 4](06-automating-controls-in-ci-cd.md#4-dynamic-security-analysis-of-applications-apis-containers-and-clusters) | [dast-in-pipeline](labs/dast-in-pipeline/README.md), [kubiscan-rbac](labs/kubiscan-rbac/README.md) |
| Detecting Unexpected Behaviors Through Fuzz Testing | [Lesson 06 section 5](06-automating-controls-in-ci-cd.md#5-detecting-unexpected-behaviors-through-fuzz-testing); repo [CMCPSE fuzz-mcp-tools](../../cmcpse-course/ch5-devsecops-for-mcp-security/README.md) | n/a (repo lab above) |
| Compliance and Governance of Supply Chain Risk | [Lesson 07](07-compliance-and-governance-of-supply-chain-risk.md) (EO 14028, SSDF, EU CRA dates) | [syft-in-cicd](labs/syft-in-cicd/README.md), [cosign-container-signing](labs/cosign-container-signing/README.md) (evidence) |
| Hands-On Exercises: | Labs below | [Lab index](#lab-index) |
| Generate the SBOM for Application using Syft | [04 section 2.2](04-asset-inventory-and-sboms.md#22-application-sbom) | [syft-app-sbom](labs/syft-app-sbom/README.md) |
| Generate the SBOM for Docker Image using Syft | [04 section 2.3](04-asset-inventory-and-sboms.md#23-container-sbom) | [syft-container-sbom](labs/syft-container-sbom/README.md) |
| Create an SBOM with Tern | [04 section 2.3](04-asset-inventory-and-sboms.md#23-container-sbom) (Tern: check maintenance status) | [tern-layer-sbom](labs/tern-layer-sbom/README.md) |
| Identify malicious Package using guarddog | [02 section 1](02-evaluating-dependencies-before-use.md#1-analyze-the-security-and-compliance-of-dependencies) | [guarddog-malicious-package](labs/guarddog-malicious-package/README.md) |
| Finding Risky Packages using packj | [02 section 1](02-evaluating-dependencies-before-use.md#1-analyze-the-security-and-compliance-of-dependencies) (packj: check maintenance status) | [packj-risk-scoring](labs/packj-risk-scoring/README.md) |
| Secrets Scanning using Trivy | [06 section 3.1](06-automating-controls-in-ci-cd.md#31-application-code-sast-and-secrets) | [trivy-secrets-scan](labs/trivy-secrets-scan/README.md) |
| Secrets Scanning using TruffleHog | [06 section 3.1](06-automating-controls-in-ci-cd.md#31-application-code-sast-and-secrets) | [trufflehog-secrets-scan](labs/trufflehog-secrets-scan/README.md) |
| False Positive Analysis (FPA) | [06 section 1.2](06-automating-controls-in-ci-cd.md#12-gating-rules-that-work) | [false-positive-analysis](labs/false-positive-analysis/README.md) |
| Container Registry using Harbor | [03 section 1](03-change-control-and-licensed-code.md#11-protected-branches) (registry-side controls); [real-tools/harbor.md](real-tools/harbor.md) | [harbor-registry-policy](labs/harbor-registry-policy/README.md) |
| Container Vulnerability Scanning using Snyk | [06 section 2](06-automating-controls-in-ci-cd.md#2-software-component-analysis-of-code-and-containers) | [snyk-container-scan](labs/snyk-container-scan/README.md) |
| Scanning Docker for Vulnerabilities with Trivy | [06 section 2](06-automating-controls-in-ci-cd.md#2-software-component-analysis-of-code-and-containers) | [trivy-docker-scan](labs/trivy-docker-scan/README.md) |
| Signing Container Images for Trust | [01 section 4](01-proving-integrity-with-cryptography.md#4-artifact-signing) (Docker Content Trust is retired) | [cosign-container-signing](labs/cosign-container-signing/README.md) |
| Container Malware Scanning using YaraHunter | [05 section 5](05-code-isolation-and-sandboxing.md#5-runtime-detection-complements-isolation) (YaraHunter: check maintenance status) | [yarahunter-malware-scan](labs/yarahunter-malware-scan/README.md) |
| Find Misconfigured RBAC Using KubiScan | [06 section 3.2](06-automating-controls-in-ci-cd.md#32-infrastructure-as-code-iac-kubernetes-and-helm); [chapter 4](../ch4-attacking-kubernetes-cluster-supply-chain/README.md) (KubiScan: check maintenance status) | [kubiscan-rbac](labs/kubiscan-rbac/README.md) |
| Finding Misconfigurations Using Kubescape | [06 section 3.2](06-automating-controls-in-ci-cd.md#32-infrastructure-as-code-iac-kubernetes-and-helm); repo [06 kubernetes](../../06-ai-devsecops/kubernetes/README.md) | [kubescape-manifest-scan](labs/kubescape-manifest-scan/README.md) |
| Finding Helm Charts Misconfigurations using Kubescape | [06 section 3.2](06-automating-controls-in-ci-cd.md#32-infrastructure-as-code-iac-kubernetes-and-helm) | [kubescape-helm-scan](labs/kubescape-helm-scan/README.md) |
| How to Embed Syft into CI/CD pipeline | [06 section 1.1](06-automating-controls-in-ci-cd.md#11-a-gitlab-style-layout); [real-tools/gitlab.md](real-tools/gitlab.md) | [syft-in-cicd](labs/syft-in-cicd/README.md) |
| Scan SBOM for Vulnerabilities using bomber | [04 section 2.5](04-asset-inventory-and-sboms.md#25-operating-sboms) (bomber: check maintenance status) | [bomber-sbom-scan](labs/bomber-sbom-scan/README.md) |
| Implement SAST as part DevOps pipelines | [06 section 3.1](06-automating-controls-in-ci-cd.md#31-application-code-sast-and-secrets) | [sast-in-pipeline](labs/sast-in-pipeline/README.md) |
| Implement DAST as part DevOps pipelines | [06 section 4](06-automating-controls-in-ci-cd.md#4-dynamic-security-analysis-of-applications-apis-containers-and-clusters) | [dast-in-pipeline](labs/dast-in-pipeline/README.md) |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| Container image signing (Docker Content Trust / Notary) | **Docker Content Trust (Notary v1) is retired**: Docker announced on 29 Jul 2025 that the Notary v1 service shuts down on **8 Dec 2026**. Use **Sigstore cosign** (keyless or key-based) or **Notation** (Notary Project). Sign **digests**; pin signer identity. |
| **Tern** | Check the repository's maintenance status. Use **Syft** or **cdxgen** (Syft JSON includes layer information). |
| **packj** | Check the repository's maintenance status. Use **GuardDog** (maintained by Datadog), **OpenSSF Scorecard** and **OSV-Scanner**. |
| **YaraHunter** | Check the repository's maintenance status. Use **ClamAV** or `yara` over extracted layers, Falco for runtime behavior, and Trivy for vulnerabilities and secrets. |
| **KubiScan** | Check the repository's maintenance status. Use **kubectl-who-can**, **rbac-tool**, **Kubescape**, `kubectl auth can-i --list`. |
| **bomber** | Check the repository's maintenance status. Use **Grype**, **OSV-Scanner** or **Trivy** (`trivy sbom`). |
| kube-hunter style cluster recon | No longer actively developed; Aqua recommends **Trivy** (`trivy k8s`). Kubescape is the CNCF alternative. |
| PodSecurityPolicy in Kubernetes isolation | **Removed in Kubernetes 1.25**. Use Pod Security Admission, ValidatingAdmissionPolicy (CEL), Kyverno or OPA Gatekeeper. |
| Helm charts and Tiller | Tiller (Helm 2) is long gone. **Helm 4** was released in Nov 2025 (WASM plugin system, server-side apply by default); Helm 3 security fixes end around early 2027. Verify. |
| SBOM formats and rules | **CycloneDX** (also Ecma-424) and **SPDX 3.0**. NTIA 2021 minimum elements; CISA proposed an update in 2025. VEX reduces noise. |
| "SLSA Level 1/2" | SLSA v1.0 (Apr 2023) defines the **Build track L0 to L3**; check for v1.1 or later. |
| "NIST SSDF" | v1.1 final (SP 800-218, Feb 2022); **Rev. 1 (SSDF v1.2) draft** published Dec 2025. "NIST C-SRM" means **C-SCRM, SP 800-161 Rev. 1**. |
| CII Best Practices self-assessment | Now the **OpenSSF Best Practices Badge**; **OpenSSF Scorecard** automates repository checks. |
| Regulation (not in the syllabus) | **US EO 14028** (2021) drove SBOM and attestation; EO 14306 (Jun 2025) amended parts of the cyber orders. **EU Cyber Resilience Act** (Reg. 2024/2847): 24-hour reporting of exploited vulnerabilities from **11 Sept 2026**, most duties from **11 Dec 2027**. |
| Incidents in older course material | Add **xz-utils** (2024, maintainer social engineering), **polyfill.io** (2024), **tj-actions/changed-files** (2025, mutable tags), **Shai-Hulud** npm worms (2025-2026), slopsquatting, repojacking. |
| GitHub Actions pinning | Pin actions to a **full commit SHA**; GitHub added policy support for enforcing SHA pinning (verify). Use immutable releases where offered. |

## Learning order

1. [Lesson 01](01-proving-integrity-with-cryptography.md) then [cosign-container-signing](labs/cosign-container-signing/README.md). About 7 hours.
2. [Lesson 02](02-evaluating-dependencies-before-use.md) then [guarddog](labs/guarddog-malicious-package/README.md), [packj](labs/packj-risk-scoring/README.md). About 6 hours.
3. [Lesson 03](03-change-control-and-licensed-code.md) then [harbor-registry-policy](labs/harbor-registry-policy/README.md). About 4 hours.
4. [Lesson 04](04-asset-inventory-and-sboms.md) then [syft-app-sbom](labs/syft-app-sbom/README.md), [syft-container-sbom](labs/syft-container-sbom/README.md), [tern-layer-sbom](labs/tern-layer-sbom/README.md), [bomber-sbom-scan](labs/bomber-sbom-scan/README.md). About 8 hours.
5. [Lesson 05](05-code-isolation-and-sandboxing.md) then [yarahunter-malware-scan](labs/yarahunter-malware-scan/README.md). About 5 hours.
6. [Lesson 06](06-automating-controls-in-ci-cd.md) then [syft-in-cicd](labs/syft-in-cicd/README.md), [trivy-secrets-scan](labs/trivy-secrets-scan/README.md), [trufflehog-secrets-scan](labs/trufflehog-secrets-scan/README.md), [false-positive-analysis](labs/false-positive-analysis/README.md), [trivy-docker-scan](labs/trivy-docker-scan/README.md), [snyk-container-scan](labs/snyk-container-scan/README.md), [kubiscan-rbac](labs/kubiscan-rbac/README.md), [kubescape-manifest-scan](labs/kubescape-manifest-scan/README.md), [kubescape-helm-scan](labs/kubescape-helm-scan/README.md), [sast-in-pipeline](labs/sast-in-pipeline/README.md), [dast-in-pipeline](labs/dast-in-pipeline/README.md). About 14 hours.
7. [Lesson 07](07-compliance-and-governance-of-supply-chain-risk.md). About 4 hours.
8. Optional: [real-tools](real-tools/README.md) on your course lab or a test system. Then [Chapter 7](../ch7-managing-a-secure-software-supply-chain-program/README.md).

## Lab index

All labs run offline: `.venv/Scripts/python -m pytest csse-course/ch6-common-defenses-against-supply-chain-attacks`.

| Lab | Course exercise | Tests |
|---|---|---|
| [syft-app-sbom](labs/syft-app-sbom/README.md) | Generate the SBOM for Application using Syft | 8 |
| [syft-container-sbom](labs/syft-container-sbom/README.md) | Generate the SBOM for Docker Image using Syft | 8 |
| [tern-layer-sbom](labs/tern-layer-sbom/README.md) | Create an SBOM with Tern | 7 |
| [guarddog-malicious-package](labs/guarddog-malicious-package/README.md) | Identify malicious Package using guarddog | 9 |
| [packj-risk-scoring](labs/packj-risk-scoring/README.md) | Finding Risky Packages using packj | 8 |
| [trivy-secrets-scan](labs/trivy-secrets-scan/README.md) | Secrets Scanning using Trivy | 8 |
| [trufflehog-secrets-scan](labs/trufflehog-secrets-scan/README.md) | Secrets Scanning using TruffleHog | 8 |
| [false-positive-analysis](labs/false-positive-analysis/README.md) | False Positive Analysis (FPA) | 9 |
| [harbor-registry-policy](labs/harbor-registry-policy/README.md) | Container Registry using Harbor | 10 |
| [snyk-container-scan](labs/snyk-container-scan/README.md) | Container Vulnerability Scanning using Snyk | 7 |
| [trivy-docker-scan](labs/trivy-docker-scan/README.md) | Scanning Docker for Vulnerabilities with Trivy | 9 |
| [cosign-container-signing](labs/cosign-container-signing/README.md) | Signing Container Images for Trust | 11 |
| [yarahunter-malware-scan](labs/yarahunter-malware-scan/README.md) | Container Malware Scanning using YaraHunter | 8 |
| [kubiscan-rbac](labs/kubiscan-rbac/README.md) | Find Misconfigured RBAC Using KubiScan | 9 |
| [kubescape-manifest-scan](labs/kubescape-manifest-scan/README.md) | Finding Misconfigurations Using Kubescape | 9 |
| [kubescape-helm-scan](labs/kubescape-helm-scan/README.md) | Finding Helm Charts Misconfigurations using Kubescape | 9 |
| [syft-in-cicd](labs/syft-in-cicd/README.md) | How to Embed Syft into CI/CD pipeline | 10 |
| [bomber-sbom-scan](labs/bomber-sbom-scan/README.md) | Scan SBOM for Vulnerabilities using bomber | 9 |
| [sast-in-pipeline](labs/sast-in-pipeline/README.md) | Implement SAST as part DevOps pipelines | 9 |
| [dast-in-pipeline](labs/dast-in-pipeline/README.md) | Implement DAST as part DevOps pipelines | 9 |

Real-tool guides (hedged): [real-tools](real-tools/README.md) for GitLab, Syft, Trivy, Harbor, Snyk, cosign/Notation, Kubescape, DefectDojo and the maintenance-status table.

## Exam tips

- **Signing proves who, not safe.** Sign digests, verify at deploy, pin signer identity. Name the DCT retirement and the replacements.
- **TUF:** four roles (root, targets, snapshot, timestamp), thresholds, offline root, expiry stops freeze, versions stop rollback, snapshot stops mix-and-match. Mention Uptane for vehicles.
- **Dependencies:** evaluate before use (vulns, malicious behavior, Scorecard, maintainers, license), then enforce (lockfile, hashes, proxy, cooldown, no install scripts).
- **Change control:** protected branches, CODEOWNERS on pipeline and infra, required reviews and checks, signed commits, protected variables, immutable tags.
- **Licenses:** permissive vs weak copyleft vs strong copyleft vs AGPL network clause; inventory from the SBOM; policy in CI.
- **Three SBOMs:** application (lockfile), container (OS packages plus app libs, layers), host (OS and agents). Know CycloneDX vs SPDX, purl, VEX.
- **Pipeline placement:** secrets and SAST pre-merge, SCA and SBOM at build, image scan and signing at package, DAST on a test environment, fuzz short on PR and long nightly.
- **Gate on new serious findings**, with a baseline and expiring exceptions.
- **Governance dates:** EU CRA 11 Sept 2026 (reporting) and 11 Dec 2027 (most duties); SSDF v1.1 final, Rev. 1 draft; EO 14028 attestation. Hedge: "verify at source".
- **Tools to hedge:** Tern, packj, YaraHunter, KubiScan, bomber (check maintenance; name the alternative).

## 15 exam-style questions

<details>
<summary>1. Code signing, component signing and artifact signing: what is the difference?</summary>

Code signing proves the publisher of executables to an OS or user (Authenticode, notarization). Component signing concerns third-party libraries you consume (verify checksums, provenance, registry signatures). Artifact signing covers what you build and deploy (images, charts, SBOMs) with tools like cosign or Notation. Same cryptography, different direction and verification point.
</details>

<details>
<summary>2. Why sign an image digest and not a tag?</summary>

Tags are movable pointers. A signature on the digest binds to exact content, so if an attacker repoints the tag the new digest has no valid signature and verification fails. Verify what the tag resolves to at deploy time.
</details>

<details>
<summary>3. Name the TUF roles and what each protects against.</summary>

Root lists keys and thresholds (offline, key rotation). Targets signs trusted files (arbitrary package attacks), possibly with delegations. Snapshot ties metadata versions together (mix-and-match). Timestamp is online with short expiry (freeze). Version numbers that never decrease stop rollback. A threshold means one stolen key is not enough.
</details>

<details>
<summary>4. Where do you meet Uptane?</summary>

It adapts TUF to automotive ECU updates, with a director repository (which images this vehicle gets) and an image repository, so a compromise of one does not let an attacker install arbitrary firmware.
</details>

<details>
<summary>5. What happened to Docker Content Trust and what replaces it?</summary>

Docker retired the Notary v1 service (announced 29 Jul 2025; shutdown 8 Dec 2026). Use Sigstore cosign (key-based or keyless with identity and issuer pinning) or Notation (Notary Project).
</details>

<details>
<summary>6. How do you evaluate a new dependency?</summary>

Do we need it at all; known vulnerabilities (OSV, Grype); malicious behavior (GuardDog-style); project health (Scorecard: review, branch protection, signed releases, maintained); maintainers and age; capabilities used; license; transitive size. Then record the decision, pin version and hash, and re-scan continuously.
</details>

<details>
<summary>7. Give five integrity controls for dependencies.</summary>

Committed lockfiles with `npm ci`/pinned installs, hash pinning (`pip --require-hashes`), an internal proxy registry with an allow-list, provenance or signature verification where available, SHA-pinned CI actions and digest-pinned base images, a cooldown for new versions, install scripts off by default.
</details>

<details>
<summary>8. What belongs in protected-branch settings?</summary>

No direct pushes, no force-push or deletion, required approvals (not by the author), code-owner approval, required status checks, signed commits, stale approval dismissal, protected tags for releases, and no admin bypass without audit.
</details>

<details>
<summary>9. Why put CI files under CODEOWNERS?</summary>

CI files control what runs with your secrets and what gets deployed. A malicious edit can exfiltrate secrets or ship a backdoor with no change to application code (poisoned pipeline execution).
</details>

<details>
<summary>10. Permissive, weak copyleft, strong copyleft, AGPL: what are the compliance implications?</summary>

Permissive (MIT, Apache) mainly needs notices. Weak copyleft (LGPL, MPL) keeps changes to the licensed component open. Strong copyleft (GPL) can extend to the combined work on distribution. AGPL's network clause can trigger source-offer duties for SaaS. Policy depends on how you distribute; ask legal for edge cases.
</details>

<details>
<summary>11. What is in an asset inventory for the software supply chain, and why?</summary>

Repositories, pipelines and runners, dependencies, artifacts and digests, registries, runtime workloads, identities and secrets, and third parties, each with an owner. It answers "where is this vulnerable component and who owns it" within minutes.
</details>

<details>
<summary>12. Application vs container vs host SBOM?</summary>

Application: libraries from lockfiles at build. Container: OS packages from dpkg/apk/rpm plus app libraries in the image, with layer attribution. Host: OS packages, agents and binaries on servers and nodes. All three are needed; store them by purl and digest, sign them, and re-scan as new CVEs appear.
</details>

<details>
<summary>13. How would you automate SCA, SAST, IaC, DAST and fuzzing in a pipeline?</summary>

Pre-merge: secrets scan, SAST, IaC scan, SCA, license check. Build: SBOM, hash-pinned deps. Package: image scan, malware scan, sign and attest. Deploy to test: DAST and API scan; verify signature at deploy. Fuzz: short on PRs with a corpus, long nightly. Gate on new serious findings, keep an exception file with owner and expiry, send results to one findings store.
</details>

<details>
<summary>14. How do you stop a legacy backlog of findings from blocking every build?</summary>

Baseline the existing findings (line-independent fingerprints) and fail only on new findings above a severity. Track legacy findings with owners and due dates, and make exceptions expire.
</details>

<details>
<summary>15. Which regulations and frameworks should you map supply chain controls to, and what are the key dates?</summary>

US EO 14028 (SBOM and secure development attestation; EO 14306 amended parts in 2025), NIST SSDF SP 800-218 (v1.1 final, Rev. 1 draft Dec 2025), NIST SP 800-161 Rev. 1 (C-SCRM), SLSA, OWASP SCVS, OpenSSF Scorecard and S2C2F, and the EU Cyber Resilience Act (24-hour reporting from 11 Sept 2026; most obligations from 11 Dec 2027). Verify at source.
</details>

## References

- Sigstore, Notary Project, in-toto, SLSA, The Update Framework and Uptane specifications.
- OpenSSF Scorecard, S2C2F and Best Practices Badge; OWASP SCVS; CycloneDX and SPDX; NTIA and CISA SBOM guidance.
- NIST SP 800-218 (SSDF), SP 800-161 Rev. 1; EU Regulation 2024/2847 (CRA); US EO 14028 and EO 14306.
- Tool documentation: Syft, cdxgen, Grype, Trivy, GuardDog, TruffleHog, Harbor, Snyk, Kubescape, OWASP ZAP, Semgrep, DefectDojo.
- Repo: [06 AI DevSecOps](../../06-ai-devsecops/README.md), [CAISP chapter 6](../../caisp-course/ch6-supply-chain-attacks-in-ai/README.md), [CMCPSE chapter 6](../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/README.md), [CAASE chapter 6](../../caase-course/ch6-operationalizing-agentic-ai-security/README.md), [cybersecurity track](../../cybersecurity-track/README.md).
