# Lesson 04: Best Practices for Securing Container Applications

> **Chapter:** 3 · Attacking the Container Supply Chain · **Time:** ~4 hours
> **You will:** apply image-security practices, choose between full, slim, distroless and scratch bases, write multi-stage builds, and secure the Docker daemon.

| | |
|---|---|
| **Prerequisites** | [Lesson 03](03-attacking-the-container-supply-chain.md); [06 Docker](../../06-ai-devsecops/docker/README.md) |
| **Labs** | [secure-mini-image](labs/secure-mini-image/README.md) · [minimize-misconfigurations](labs/minimize-misconfigurations/README.md) · [unsecured-docker-daemon](labs/unsecured-docker-daemon/README.md) |
| **Syllabus lines** | Best practices for securing container applications · Container Image Security · Distroless and scratch image · Multi-stage builds · Securing Docker daemon |
| **Maps to** | NIST SP 800-190 · CIS Docker Benchmark · OWASP Docker Security Cheat Sheet |

## 1. Why it matters

The cheapest defence is **less stuff**. Every package is code you must patch and an attacker may use after a break-in. Many images ship hundreds of packages the app never calls.

## 2. Container image security

| Practice | Why | Check |
|---|---|---|
| **Trusted, minimal base** from a known publisher (Docker Official Images, Verified Publisher, your own hardened base) | Fewer unknowns | Allowlist in CI |
| **Pin by digest**, update by pull request (Renovate, Dependabot) | A tag can move | Linter `DF-001`, `RUN-017` |
| **Non-root numeric `USER`** | Limits every exploit | `DF-003` |
| **No secrets in layers**: use BuildKit `--mount=type=secret`, runtime secret stores | Layers never forget | `DF-004`, `DF-005` |
| **`.dockerignore`** | Keeps `.git`, `.env`, caches out | `DF-012` |
| **Verify downloads** (checksum or signature), no `curl` piped to `sh` | Supply chain | `DF-006`, `DF-007` |
| **Scan** (Trivy, Grype) at build and again on a schedule | New CVEs appear after release | CI gate |
| **SBOM** (Syft, Trivy; CycloneDX or SPDX) stored with the image | Know what is inside when the next CVE lands | [CAISP ch6 SBOM](../../caisp-course/ch6-supply-chain-attacks-in-ai/README.md) |
| **Sign and attest** (cosign/Notation) | Prove who built it | [Lesson 05](05-technologies-for-securing-containerized-applications.md#4-image-signing-and-content-trust) |
| **Rebuild regularly** | Pick up base-image patches | Scheduled pipeline |
| **One process, minimal ports** | Smaller surface | Review `EXPOSE` |
| **Labels** (`org.opencontainers.image.source`, revision) | Traceability | Provenance |

Use the 12-rule [Dockerfile linter from module 06](../../06-ai-devsecops/docker/README.md); the [minimize-misconfigurations lab](labs/minimize-misconfigurations/README.md) wraps it with fix hints.

## 3. Distroless and scratch images

| Base | What it contains | Pros | Cons |
|---|---|---|---|
| **Full** (`python:3.12`) | Whole Debian, compilers, tools | Everything works | Huge surface, many CVEs |
| **Slim** | Debian minus extras | Smaller, familiar | Still has a shell and apt |
| **Alpine** | musl libc, busybox, apk | Tiny | musl differences; still a shell |
| **Distroless** (Google) | Runtime only (language runtime, libc, CA certs, tzdata), **no shell, no package manager** | Few CVEs; attackers lose their toolbox | Harder to debug (use debug tag or ephemeral containers) |
| **scratch** | Empty | Smallest possible; only your static binary | No certs, no shell, no `/etc/passwd`; needs a static build |

Distroless and scratch images do not make an app safe. They remove "living off the land" tools (shell, curl, package manager), which makes post-exploitation harder and findings fewer. The [secure-mini-image lab](labs/secure-mini-image/README.md) compares them with fixture numbers (illustrative, not measurements).

**Debugging without a shell:** `kubectl debug` with an ephemeral container, a `:debug` tag for development only, or `docker cp` and logs.

## 4. Multi-stage builds

Use one stage to build, a second to run. Only files you `COPY --from=build` reach the final image, so compilers, source, caches and build secrets stay behind.

```dockerfile
FROM golang:1.23@sha256:<digest> AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/server /server
USER 65532:65532
ENTRYPOINT ["/server"]
```

Full examples (Go to scratch, Python to distroless) are in [secure-mini-image/examples](labs/secure-mini-image/examples/). A test lints them clean and lints the "bloated" example with six findings. See also the SVG in [06 Docker](../../06-ai-devsecops/docker/README.md).

## 5. Securing the Docker daemon

The daemon runs as root and its API controls the host. Hardening list (mapped to the [daemon auditor](labs/unsecured-docker-daemon/daemon_audit.py)):

| Practice | Setting |
|---|---|
| Do not expose the API; if you must, **TLS with client certificate verification** on 2376 | `"hosts"`, `"tlsverify": true`, `tlscacert`, `tlscert`, `tlskey`. Or use SSH (`docker -H ssh://user@host`) |
| Restrict the Unix socket | mode `0660`, group `docker` kept very small; membership equals root |
| **Rootless mode** or **user namespace remap** | `"userns-remap": "default"` |
| Disable inter-container traffic on the default bridge | `"icc": false` |
| Do not use insecure registries | remove `insecure-registries` |
| Keep default seccomp and AppArmor profiles | never `seccomp=unconfined` daemon-wide |
| Logging on, with rotation | `"log-driver"`, `"log-opts"` |
| `live-restore`, `no-new-privileges` default | availability and privilege |
| Patch Docker Engine, containerd and runc | runtime CVEs are real (CVE-2019-5736, CVE-2024-21626) |
| Audit with **docker-bench-security** or CIS-CAT | Evidence for compliance |
| Audit daemon files and socket with `auditd` | Detect changes |

A rootless setup removes the daemon-as-root problem but has feature limits (some network and storage options); check the docs.

## 6. Hands-on

1. Run `secure-mini-image` and rank the five bases.
2. Rewrite `Dockerfile.bloated` into a multi-stage image and make the linter print zero findings.
3. Run `unsecured-docker-daemon` and fix every finding in `daemon_insecure.json` until it matches `daemon_secure.json`.

## 7. Scenario

A team wants `docker exec sh` access in production, so they refuse distroless. Offer an alternative that keeps debugging possible without shipping a shell. (Ephemeral debug container in Kubernetes, a separate debug image, logs and metrics.)

## 8. Interview Q&A

<details>
<summary>Why do multi-stage builds improve security?</summary>

Build tools, source code and build-time secrets stay in discarded stages. The final image contains only the runtime artifacts, so it is smaller, has fewer CVEs and gives an attacker fewer tools.
</details>

<details>
<summary>Is a distroless image automatically secure?</summary>

No. It lacks a shell and package manager, which shrinks post-exploitation options and CVE counts, but the application and its dependencies can still be vulnerable, and you still need non-root, limits, patching and scanning.
</details>

<details>
<summary>How do you pass a build-time secret without leaving it in a layer?</summary>

Use a BuildKit secret mount (`RUN --mount=type=secret,id=...`); the secret exists only for that step and is not stored in any layer or in `docker history`.
</details>

## 9. References

- Docker docs: multi-stage builds, protect the daemon socket, rootless mode, userns-remap (verify at docs.docker.com).
- GoogleContainerTools/distroless README. CIS Docker Benchmark.
- Repo: [06 Docker](../../06-ai-devsecops/docker/README.md).
