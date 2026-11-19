# Trivy (hedged)

> Trivy (Aqua Security) is actively maintained and replaces several older tools in the course (for example kube-hunter for cluster checks). Verify flags in the current docs; they change between releases.

## Targets

```text
trivy fs .                                         # a directory: dependencies, and optionally secrets, misconfig, licenses
trivy fs --scanners vuln,secret,misconfig,license .
trivy image <image>@sha256:<digest>                # container image
trivy rootfs /                                     # a root filesystem (host SBOM / scan)
trivy config infra/                                # IaC and Kubernetes manifests
trivy k8s --report summary cluster                 # a live cluster (own cluster only)
trivy sbom sbom.cdx.json                           # scan an existing SBOM
trivy image --format cyclonedx -o image.cdx.json <image>   # generate an SBOM
```

## CI gating

```text
trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 <image>
trivy fs --scanners secret --exit-code 1 .
trivy fs --ignorefile .trivyignore --exit-code 1 .
```

## Practical points

- **Database.** Trivy downloads vulnerability and check databases. Cache them in CI. In air-gapped setups use a mirror and treat a failed DB update as a failure.
- **Pin** the Trivy version or image digest. Treat the tool itself as a supply-chain dependency (security tools have been targeted before; verify releases).
- **Ignore files** need justification and expiry (see [false-positive-analysis](../labs/false-positive-analysis/README.md)).
- **Secrets**: `--scanners secret`; custom rules in a `trivy-secret.yaml`.

## Labs

[trivy-docker-scan](../labs/trivy-docker-scan/README.md) · [trivy-secrets-scan](../labs/trivy-secrets-scan/README.md)
