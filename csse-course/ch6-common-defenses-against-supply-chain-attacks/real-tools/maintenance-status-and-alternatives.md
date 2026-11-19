# Tools to check before you rely on them, and maintained alternatives

The chapter 6 syllabus names several tools whose **maintenance status is uncertain** (as of Nov 2026). **Check the repository before relying on one**: date of the last release and commit, open security issues, whether it supports current formats, who maintains it. If it is stale, use the alternative.

| Syllabus tool | What it did | Status | Maintained alternative(s) | Offline twin |
|---|---|---|---|---|
| **Tern** | layer-by-layer container SBOM | check status | Syft (layer info in JSON), cdxgen, Trivy | [tern-layer-sbom](../labs/tern-layer-sbom/README.md) |
| **packj** | risky-package audit (capabilities, metadata) | check status | GuardDog, OpenSSF Scorecard, OSV-Scanner, deps.dev, Socket-style services | [packj-risk-scoring](../labs/packj-risk-scoring/README.md) |
| **YaraHunter** | YARA-based malware scan of images | check status | Trivy (different scope: vulns, secrets, config), ClamAV, `yara` on extracted layers, Falco (runtime) | [yarahunter-malware-scan](../labs/yarahunter-malware-scan/README.md) |
| **KubiScan** | risky RBAC finder | check status | kubectl-who-can, rbac-tool, Kubescape, `kubectl auth can-i --list` | [kubiscan-rbac](../labs/kubiscan-rbac/README.md) |
| **bomber** | SBOM vulnerability scan | check status | Grype, OSV-Scanner, Trivy (`trivy sbom`), Dependency-Track | [bomber-sbom-scan](../labs/bomber-sbom-scan/README.md) |
| **Docker Content Trust (Notary v1)** | image signing | **retired** (service shutdown announced for 8 Dec 2026) | cosign, Notation | [cosign-container-signing](../labs/cosign-container-signing/README.md) |
| **kube-hunter** (chapter 4) | cluster recon | no longer actively developed | `trivy k8s`, Kubescape | chapter 4 labs |

Maintained and current in this chapter: **GuardDog, Syft, Trivy, TruffleHog, Harbor, Kubescape, DefectDojo, cosign/Sigstore, Notation**.

## A quick "is this tool alive?" checklist

1. Last release within roughly the last 12 months? Last commit within 6?
2. Does it handle current formats (for example CycloneDX 1.5+, OCI image layouts, current lockfile versions)?
3. Are security advisories answered?
4. Is there more than one active maintainer?
5. Does it download code or data from the network at run time (and from where)?
6. Can you replace it without losing your outputs (standard formats such as SARIF, CycloneDX, OSV)?

Treat security tools as supply-chain dependencies themselves: pin versions, verify release signatures when offered, and run them in isolated CI jobs.
