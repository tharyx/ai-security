# Real-tool guides (hedged, optional)

These guides help you repeat the chapter 6 labs with the real tools in your course lab or on your own test systems. **Nothing here is needed by the tests.** Commands and flags change, so treat every command as an example and **verify against the tool's current documentation**. Never paste tokens, keys or passwords into chat, issues or repositories.

| Guide | Tool(s) | Labs it supports | Status (Nov 2026; verify) |
|---|---|---|---|
| [gitlab.md](gitlab.md) | GitLab CI, protected branches/variables | [syft-in-cicd](../labs/syft-in-cicd/README.md), [sast-in-pipeline](../labs/sast-in-pipeline/README.md), [dast-in-pipeline](../labs/dast-in-pipeline/README.md) | maintained |
| [syft.md](syft.md) | Syft, cdxgen, Grype | [syft-app-sbom](../labs/syft-app-sbom/README.md), [syft-container-sbom](../labs/syft-container-sbom/README.md), [bomber-sbom-scan](../labs/bomber-sbom-scan/README.md) | maintained |
| [trivy.md](trivy.md) | Trivy | [trivy-docker-scan](../labs/trivy-docker-scan/README.md), [trivy-secrets-scan](../labs/trivy-secrets-scan/README.md) | maintained |
| [harbor.md](harbor.md) | Harbor | [harbor-registry-policy](../labs/harbor-registry-policy/README.md) | CNCF graduated, maintained |
| [snyk.md](snyk.md) | Snyk | [snyk-container-scan](../labs/snyk-container-scan/README.md) | commercial, account needed |
| [cosign.md](cosign.md) | cosign, Notation | [cosign-container-signing](../labs/cosign-container-signing/README.md) | maintained; **Docker Content Trust retired** |
| [kubescape.md](kubescape.md) | Kubescape, Trivy k8s | [kubescape-manifest-scan](../labs/kubescape-manifest-scan/README.md), [kubescape-helm-scan](../labs/kubescape-helm-scan/README.md) | CNCF, maintained |
| [defectdojo.md](defectdojo.md) | DefectDojo | [false-positive-analysis](../labs/false-positive-analysis/README.md) | maintained |
| [maintenance-status-and-alternatives.md](maintenance-status-and-alternatives.md) | Tern, packj, YaraHunter, KubiScan, bomber | their labs | **check maintenance first**; alternatives listed |

Also named in the syllabus labs and covered with twins plus commands in each lab README: GuardDog ([guarddog lab](../labs/guarddog-malicious-package/README.md)) and TruffleHog ([trufflehog lab](../labs/trufflehog-secrets-scan/README.md)).

## Safety rules for real tools

1. Use **test projects, test registries and disposable clusters** you own. Do not scan third-party systems.
2. Pin tool versions (and container images by digest) in CI.
3. Keep tokens in protected, masked CI variables or a secret manager.
4. Learner laptop with little disk: use small images, delete pulled images (`docker image prune`), and prefer scanning files over running big stacks.
5. Download tools only from the project's official release page or package source, and verify checksums or signatures when offered.
