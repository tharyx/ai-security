# Software Supply Chain Security: Course Companion

A study companion for the **Software Supply Chain Security** expert course, organized exactly like its 7-chapter syllabus.
Every syllabus line points to a lesson that already exists in this repo or to new material here. Check line by line in [SYLLABUS-MAP.md](SYLLABUS-MAP.md).

> Unofficial companion. Your course's videos, browser lab and support community are the primary source. Use this folder to go deeper, practice offline and prepare for interviews.

## Where the syllabus is out of date (Nov 2026)

Parts of this syllabus date from around 2021–22. The lessons teach the syllabus items, so you can pass the exam, **and** what's current, so you're right at work.

| Syllabus says | Current reality |
|---|---|
| Image signing with **Docker Content Trust** | **Retired.** Docker's Notary v1 service shuts down on **8 Dec 2026**. Use **Sigstore cosign** or **Notation** (Notary Project). |
| Recon with **kube-hunter** | No longer actively developed. Use **`trivy k8s`** or **Kubescape**. |
| **Tern, packj, YaraHunter, KubiScan, bomber** | Check each repo's maintenance status first. Maintained alternatives: Syft/cdxgen, GuardDog/osv-scanner, Grype, kubectl-who-can/rbac-tool, Kubescape. |
| Kubernetes admission / pod security | PodSecurityPolicy was **removed in Kubernetes 1.25**. Use Pod Security Admission, ValidatingAdmissionPolicy, Kyverno or Gatekeeper. |
| Helm | **Helm 4** was released in November 2025 (new plugin system, server-side apply). |
| "NIST C-SRM" | Means **C-SCRM, NIST SP 800-161 Rev. 1**. |
| NIST SSDF | **v1.1** is final; **v1.2 (SP 800-218 Rev. 1)** was released as a draft in December 2025. |
| "Core Infrastructure Initiative – Self Assessment" | The CII Best Practices Badge is now the **OpenSSF Best Practices Badge**. |
| Case studies stop around 2021 | Newer ones: **xz-utils** (2024), **polyfill.io** CDN (2024), **tj-actions/changed-files** (2025), the **Shai-Hulud** npm worms (2025–26), slopsquatting. |
| Regulation | The **EU Cyber Resilience Act**: vulnerability reporting within 24 h since **11 Sept 2026**; most other duties from **11 Dec 2027**. |

## Chapters

| # | Chapter | Key labs |
|---|---|---|
| 1 | [Introduction to supply chain security](ch1-introduction-to-supply-chain-security/) | CI/CD runner (GitLab-style), stages, continuous deployment, Equifax case |
| 2 | [Attacking code and application supply chain](ch2-attacking-code-and-application-supply-chain/) | Dependency confusion, GitLab privilege escalation, commit spoofing and signing, typosquatting, Codecov, pre-commit hooks, SCA, SAST, DAST |
| 3 | [Attacking container supply chain](ch3-attacking-container-supply-chain/) | Malicious and backdoored images, registry attacks, Docker daemon, minimal images, typosquatted images |
| 4 | [Attacking Kubernetes / cluster supply chain](ch4-attacking-kubernetes-cluster-supply-chain/) | Secrets, service accounts, NetworkPolicy, recon, Kubelet API, privileged pods, image scanning, manifest analysis |
| 5 | [Attacking cloud supply chain](ch5-attacking-cloud-supply-chain/) | Metadata SSRF (IMDSv1 vs v2), bucket misconfigurations, serverless, deployment services, GKE |
| 6 | [Common defenses](ch6-common-defenses-against-supply-chain-attacks/) | 20 tool exercises: SBOMs, malicious packages, secrets scanning, FPA, Harbor, vulnerability scanning, signing, YARA, RBAC, Kubescape, CI integration, SAST/DAST |
| 7 | [Managing a secure supply chain program](ch7-managing-a-secure-software-supply-chain-program/) | SLSA L1 and L2, OSS vetting process, DefectDojo, vulnerability management, dependency hell |

## How the labs run

| Lab type | Where | Needs |
|---|---|---|
| `labs/…` | Your laptop, offline | `python -m pytest csse-course` (no Docker, Kubernetes or cloud needed) |
| `real-tools/` guides and the "real tool" sections in lab READMEs | Your course lab, or your laptop with Docker | The named tool. Commands are hedged: always check `--help` |

## How this connects to the rest of the repo

| Course chapter | Builds on |
|---|---|
| 1–2 | [06 · cicd](../06-ai-devsecops/cicd/), [CAISP ch4](../caisp-course/ch4-ai-attacks-and-defenses-devops/), [CAISP ch6](../caisp-course/ch6-supply-chain-attacks-in-ai/), [cybersecurity-track · pentesting](../cybersecurity-track/09-pentesting-fundamentals/) |
| 3–4 | [06 · docker](../06-ai-devsecops/docker/), [06 · kubernetes](../06-ai-devsecops/kubernetes/) |
| 5 | [cybersecurity-track · cloud](../cybersecurity-track/10-cloud-security/), [09 · AWS/Azure/GCP](../09-enterprise-architecture/) |
| 6–7 | [CMCPSE ch6](../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/), [cybersecurity-track · vulnerability management](../cybersecurity-track/08-vulnerability-management/), [08 · evidence](../08-ai-compliance/) |
