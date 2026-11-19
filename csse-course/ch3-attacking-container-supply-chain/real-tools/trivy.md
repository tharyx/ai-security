# Real tool guide: Trivy for container images

> **Hedged guide.** Not run by the repo author for this guide. Check `trivy --help` and trivy.dev for current flags and the current vulnerability database behaviour (first run downloads a database, so it needs network).

Trivy (Aqua Security, open source) is a scanner for images, file systems, Git repos, IaC and Kubernetes. It reads images without running them.

## Install (examples)

Package managers (`brew install trivy`, Linux packages), a container image (`aquasec/trivy`), or a release binary. Verify the checksum or signature of the download.

## Core commands

```text
trivy image alpine:3.20                          # OS and language package vulnerabilities
trivy image --severity HIGH,CRITICAL --ignore-unfixed myapp@sha256:<digest>
trivy image --scanners vuln,secret,misconfig myapp:1.0   # also secrets and Dockerfile misconfig
trivy image --format cyclonedx -o sbom.cdx.json myapp:1.0  # SBOM
trivy image --input image.tar                    # scan a docker save tar (offline images)
trivy config Dockerfile                          # misconfiguration checks
trivy fs .                                       # a source directory
trivy image --exit-code 1 --severity CRITICAL myapp:1.0   # fail a CI job
```

## What to look at

- Vulnerabilities by package and fixed version; prioritise reachable, exploited ones ([CVSS, EPSS and KEV prioritiser](../../../cybersecurity-track/08-vulnerability-management/README.md)).
- **Secrets** embedded in layers (keys, tokens).
- **Misconfigurations** (root user, no healthcheck, latest tag).
- The base image and its distribution support status.

## Map to the labs

| Lab | Trivy equivalent |
|---|---|
| malicious-image | `--scanners secret`, plus manual review of entrypoint and history (Trivy is not a malware detector; pair with YARA or runtime detection) |
| secure-mini-image | compare `trivy image` counts for full vs slim vs distroless |
| minimize-misconfigurations | `trivy config Dockerfile` |
| ch4 k8s-image-scanning | `trivy image` on every image in a manifest; `trivy k8s` for clusters ([ch4 trivy-k8s](../../ch4-attacking-kubernetes-cluster-supply-chain/real-tools/trivy-k8s.md)) |

## Alternatives

Grype and Syft (Anchore), Docker Scout, Snyk Container, Clair (Quay), Harbor's built-in scanner (often Trivy). Compare results: scanners disagree on edge cases.

## Cautions

Scanners find **known** issues only. A clean scan does not mean "safe". Keep the database current, scan on a schedule, and re-scan stored images.
