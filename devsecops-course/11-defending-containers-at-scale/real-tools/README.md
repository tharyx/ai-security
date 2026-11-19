# Real tools for chapter 11 (hedged guides)

Everything in the labs is an offline simulation. This page says what to run for real, and where to read more. Tool status and flags change: **verify at the source**. Use only on systems you own.

## Existing guides in this repo (link, do not duplicate)

- [csse ch3 real-tools/docker.md](../../../csse-course/ch3-attacking-container-supply-chain/real-tools/docker.md): `docker info`, inspect, daemon config.
- [csse ch3 real-tools/trivy.md](../../../csse-course/ch3-attacking-container-supply-chain/real-tools/trivy.md): Trivy basics.
- [csse ch3 real-tools/cosign-notation.md](../../../csse-course/ch3-attacking-container-supply-chain/real-tools/cosign-notation.md): signing.

## Tool table

| Job | Tool | Status note (Nov 2026, verify) | Lab |
|---|---|---|---|
| Dockerfile lint | Hadolint | active; static binary | [hadolint](../labs/hadolint-static-analysis/README.md) |
| Image vulnerabilities | Trivy, Grype, Snyk Container, Docker Scout | all active; databases and licences differ | [trivy-vuln-scan](../labs/trivy-vuln-scan/README.md) |
| Image forensics | Dive | active | [dive-dockle](../labs/dive-dockle-forensics/README.md) |
| Image CIS lint | Dockle | check maintenance cadence | [dive-dockle](../labs/dive-dockle-forensics/README.md) |
| Host/daemon CIS audit | docker-bench-security, CIS-CAT | scripts follow a benchmark version | [cis-docker-compliance](../labs/cis-docker-compliance/README.md) |
| Sandboxed runtimes | gVisor (runsc), Kata Containers | active | [03 section 2](../03-daemon-host-and-kernel-hardening.md) |
| Signing | cosign, Notation | current; Docker Content Trust retired | [sign-container-images](../labs/sign-container-images/README.md) |
| Registry | Harbor (CNCF graduated), cloud registries | policies differ | [harbor](../labs/harbor-secure-by-default/README.md) |

## Trivy client/server (concept)

```text
trivy server --listen 127.0.0.1:4954 --token "$TRIVY_TOKEN"
trivy image --server http://127.0.0.1:4954 --token "$TRIVY_TOKEN" IMAGE
```

## docker-bench-security

```text
git clone https://github.com/docker/docker-bench-security.git
sudo sh docker-bench-security/docker-bench-security.sh
```

Reads the real host: run it on your own lab VM first, and compare to the CIS Docker Benchmark version it targets.

## Hadolint in CI (GitHub Actions or GitLab)

```text
hadolint --format sarif Dockerfile > hadolint.sarif   # upload to the code scanning view
```

Pin the action/image by version or digest.
