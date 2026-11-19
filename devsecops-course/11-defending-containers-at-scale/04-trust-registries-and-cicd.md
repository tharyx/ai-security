# Lesson 04: Trust, Registries and CI/CD Integration

> **Chapter:** 11 · Defending Containers at Scale · **Time:** ~3 hours
> **You will:** replace Docker Content Trust with cosign or Notation, harden a registry, wire scans and signatures into the pipeline, and use Dive and Dockle as forensic and checklist tools.

| | |
|---|---|
| **Prerequisites** | [Lesson 02](02-secure-images-linting-and-scanning.md); [csse ch6](../../csse-course/ch6-common-defenses-against-supply-chain-attacks/README.md) |
| **Labs** | [sign-container-images](labs/sign-container-images/README.md) · [harbor-secure-by-default](labs/harbor-secure-by-default/README.md) · [dive-dockle-forensics](labs/dive-dockle-forensics/README.md) · [trivy-in-gitlab-ci](labs/trivy-in-gitlab-ci/README.md) |
| **Syllabus lines** | [CCSE 4] Content Trust and Integrity checks · Docker Registry security configurations · Private vs. Public Registries · Authentication and Authorization (RBAC) · Built-in Image scanning capabilities · Policy enforcement · DevOps CI/CD Integration · Docker Tools, Techniques, and Tactics · Tools · Dive (Forensic) · Dockle · Techniques · Tactics · [CDE 7] Content Trust and Integrity checks. |

## 1. Content trust and integrity checks (DCT is retired)

> **Outdated in the syllabus -> current.** The course teaches **Docker Content Trust (DCT)**, built on **Notary v1** (`DOCKER_CONTENT_TRUST=1`, root/targets/snapshot/timestamp keys). Docker announced its retirement on 29 July 2025 and the notary.docker.io service is scheduled to shut down on 8 December 2026 (verify at source). Learn it as legacy for the exam; build new workflows on **cosign (Sigstore)** or **Notation (Notary Project)**.

| | DCT / Notary v1 (legacy) | cosign | Notation |
|---|---|---|---|
| Signs | tag-to-digest mapping | image digest | image digest |
| Keys | root, targets, snapshot, timestamp | your key, KMS, or **keyless** (short-lived cert via OIDC) | X.509 certificates, trust policy |
| Storage | Notary server | signature stored as an OCI artifact next to the image | OCI artifact |
| Log | none | optional transparency log (Rekor) | n/a |

**Integrity checks** in practice: (1) **pin by digest** in deployments; (2) **verify** signature and identity at deploy or admission time (Kubernetes policy controllers; registry policy); (3) sign **SBOMs and provenance** (attestations) too; (4) re-verify after any copy between registries. Signing proves *who built it*, not that it is *safe*: combine with scanning. Lab: [sign-container-images](labs/sign-container-images/README.md); real walk-through: [csse ch6 cosign-container-signing](../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/cosign-container-signing/README.md) and [real-tools/cosign-notation.md](../../csse-course/ch3-attacking-container-supply-chain/real-tools/cosign-notation.md).

## 2. Private vs public registries

| | Public (Docker Hub, GHCR public) | Private (Harbor, cloud registry, Artifactory) |
|---|---|---|
| Who can push | maintainers you do not control | your teams |
| Risk | typosquats, stale or malicious images, rate limits | misconfigured public access, over-broad tokens |
| Practice | allow-list publishers, **mirror** what you use into your own registry, pull through a cache | private by default, TLS, audit logs |

An **open registry** (no auth) is a write target: an attacker can replace an image you deploy ([csse ch3 attack-docker-registry](../../csse-course/ch3-attacking-container-supply-chain/labs/attack-docker-registry/README.md)).

## 3. Registry security

- **Authentication and authorization (RBAC):** SSO for people; **robot accounts** with scoped, short-lived credentials for CI; roles such as pull-only, push, project admin; no shared admin password.
- **Transport and storage:** TLS only; encrypt storage; back up; restrict who can delete.
- **Immutable tags** for release tags so a tag cannot be re-pointed; retention rules for old images.
- **Built-in image scanning:** scan on push and on a schedule (Harbor uses Trivy by default in recent versions; cloud registries have their own; verify).
- **Policy enforcement:** "prevent vulnerable images from running" at a severity, require a **signature**, block unscanned images, allow only listed base images. Enforce in the registry **and** at the cluster (admission control) so a bypass of one is caught by the other.
- **Replication and air gaps:** replicate only verified images.
- **Audit:** pulls, pushes, deletes, policy changes.

Lab: [harbor-secure-by-default](labs/harbor-secure-by-default/README.md); walk-through: [csse ch6 harbor-registry-policy](../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/harbor-registry-policy/README.md).

## 4. DevOps CI/CD integration

A pipeline that builds containers should, in order:

1. lint the Dockerfile (Hadolint) and scan IaC;
2. build with a **rootless/daemonless builder** (BuildKit, kaniko, buildah), not by mounting `docker.sock`;
3. generate an **SBOM**; scan the image (Trivy/Grype); apply the **severity gate**; keep the report as an artifact;
4. **sign** the digest (cosign/Notation) and attach attestations;
5. push to the private registry; registry policy re-checks;
6. deploy by digest; the cluster **verifies** the signature;
7. rescan the running inventory daily (new CVEs), and rebuild base images on a schedule.

Runners are high-value targets: ephemeral runners, least-privilege tokens, no long-lived cloud keys ([csse ch1](../../csse-course/ch1-introduction-to-supply-chain-security/README.md)). Lab: [trivy-in-gitlab-ci](labs/trivy-in-gitlab-ci/README.md). Pipeline theory is in [Chapter 02](../02-tools-pipelines-and-secure-sdlc/README.md).

## 5. Tools, techniques and tactics: Dive and Dockle

The syllabus lists "Tools, Techniques, Tactics" as headings with two tools; here is a practical reading.

**Tools**

- **Dive** (forensic): browse an image **layer by layer**, see which files each layer adds, changes or removes, and the **efficiency** score (wasted bytes). Forensically it finds **removed-but-still-present** files, such as a deleted `.env`, and leftover build tools.
- **Dockle**: image linter that checks CIS Docker image recommendations: non-root user, `HEALTHCHECK`, secrets in `ENV`, setuid files, `ADD`, `sudo`, apt caches, `latest` tag (ids like `CIS-DI-0001`: verify at source). Different from Hadolint: Dockle inspects the **built image**, Hadolint the **Dockerfile text**.

**Techniques** (how you use them): read `docker history --no-trunc`; `docker save` and inspect layer tarballs; diff two image versions; search every layer for secrets, not only the final filesystem; confirm what a "fix" really changed.

**Tactics** (how you apply them): shift left (lint, scan, Dockle in CI), minimal base, a **baseline** of what a good image looks like and alert on drift, **rotate any secret ever found in a layer** (deleting is not fixing), prefer rebuild over patch-in-place, and keep an inventory so you can answer "which running containers contain library X?" in minutes.

Lab: [dive-dockle-forensics](labs/dive-dockle-forensics/README.md).

## 6. Hands-on

1. Sign, verify, then re-point a tag and watch verification fail.
2. Audit the default and hardened Harbor project.
3. Find the deleted secret in the leaky image and say what you would rotate.

## 7. Quick check

1. Why sign a digest, not a tag?
2. Why enforce policy in the registry and the cluster?
3. What is the difference between Dive and Dockle?

## 8. References

- Sigstore cosign: https://docs.sigstore.dev · Notation: https://notaryproject.dev
- Harbor: https://goharbor.io · Dive: https://github.com/wagoodman/dive · Dockle: https://github.com/goodwithtech/dockle
- Docker: Content Trust retirement notice (verify the current status page).
