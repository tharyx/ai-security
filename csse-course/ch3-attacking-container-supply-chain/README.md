# Chapter 3: Attacking the Container Supply Chain

This chapter covers **containers as a supply chain**: what a container is, how the ecosystem is attacked (malicious and backdoored images, typosquatting, insecure registries, misconfigurations, an exposed daemon), and how to defend it (minimal and multi-stage images, a hardened daemon, seccomp, AppArmor, and image signing). Ten labs run offline with fixtures and tests: **Docker is not required**.

> **Safety.** Every lab is a simulation: JSON/YAML fixtures that mirror real formats (image manifest and config, layer listings, `docker inspect`, `daemon.json`, registry API responses), canary strings, `.example` domains and FAKE keys. Nothing is executed, pulled or sent over a network. Never test registries or Docker daemons you do not own.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Tool status and numbers here are hedged: **verify at the source**.

## Syllabus coverage

| Syllabus item | Where to study | Lab |
|---|---|---|
| Introduction to container technology | [Lesson 01](01-introduction-to-container-technology.md); repo [IT fundamentals lesson 04](../../cybersecurity-track/01-it-fundamentals/04-virtualization-containers-cloud-basics.md) | n/a |
| What is a container | [01 section 2](01-introduction-to-container-technology.md#2-what-is-a-container) | [docker-commands](labs/docker-commands/README.md) |
| Basics of container | [01 section 3](01-introduction-to-container-technology.md#3-basics-of-container); repo [06 Docker](../../06-ai-devsecops/docker/README.md) (layers) | [container-snapshots](labs/container-snapshots/README.md) |
| Ways to interact with containers ecosystem | [01 section 4](01-introduction-to-container-technology.md#4-ways-to-interact-with-the-containers-ecosystem) | [docker-commands](labs/docker-commands/README.md) |
| Attack surface of containers and supply chain risks | [Lesson 02](02-attack-surface-and-analysis-of-containers.md) | n/a |
| Overview of container security | [02 section 2](02-attack-surface-and-analysis-of-containers.md#2-overview-of-container-security) | n/a |
| Attack surface of the container ecosystem | [02 section 3](02-attack-surface-and-analysis-of-containers.md#3-attack-surface-of-the-container-ecosystem) (SVG) | [exploit-containerized-app](labs/exploit-containerized-app/README.md) |
| Attack surface analysis using native and third party tools | [02 section 5](02-attack-surface-and-analysis-of-containers.md#5-attack-surface-analysis-with-native-tools); [real-tools/trivy.md](real-tools/trivy.md) | [docker-commands](labs/docker-commands/README.md) |
| Attack surface analysis with native tools | [02 section 5](02-attack-surface-and-analysis-of-containers.md#5-attack-surface-analysis-with-native-tools) | [docker-commands](labs/docker-commands/README.md), [container-snapshots](labs/container-snapshots/README.md) |
| Kernel features: Namespaces, Cgroups, Capabilities | [02 section 4](02-attack-surface-and-analysis-of-containers.md#4-kernel-features-namespaces-cgroups-capabilities) (SVG); repo [05 sandboxing](../../05-agent-security/sandboxing/README.md) | [exploit-containerized-app](labs/exploit-containerized-app/README.md) |
| Attacking Container Supply Chain ecosystem | [Lesson 03](03-attacking-the-container-supply-chain.md) | all attack labs |
| Malicious images | [03 section 2](03-attacking-the-container-supply-chain.md#2-malicious-images) | [malicious-image](labs/malicious-image/README.md), [typosquatting-image](labs/typosquatting-image/README.md) |
| Insecure container registry | [03 section 3](03-attacking-the-container-supply-chain.md#3-insecure-container-registry) | [attack-docker-registry](labs/attack-docker-registry/README.md) |
| Attacking through container misconfigurations | [03 section 4](03-attacking-the-container-supply-chain.md#4-attacking-through-container-misconfigurations) | [exploit-containerized-app](labs/exploit-containerized-app/README.md), [unsecured-docker-daemon](labs/unsecured-docker-daemon/README.md) |
| Best practices for securing container applications | [Lesson 04](04-securing-container-applications.md) | [minimize-misconfigurations](labs/minimize-misconfigurations/README.md) |
| Container Image Security | [04 section 2](04-securing-container-applications.md#2-container-image-security); repo [06 Docker](../../06-ai-devsecops/docker/README.md) | [minimize-misconfigurations](labs/minimize-misconfigurations/README.md) |
| Distroless and scratch image | [04 section 3](04-securing-container-applications.md#3-distroless-and-scratch-images) | [secure-mini-image](labs/secure-mini-image/README.md) |
| Multi-stage builds | [04 section 4](04-securing-container-applications.md#4-multi-stage-builds) | [secure-mini-image](labs/secure-mini-image/README.md) |
| Securing Docker daemon | [04 section 5](04-securing-container-applications.md#5-securing-the-docker-daemon) | [unsecured-docker-daemon](labs/unsecured-docker-daemon/README.md) |
| Technologies and solutions for securing containerized applications | [Lesson 05](05-technologies-for-securing-containerized-applications.md) | n/a |
| Docker host security configurations | [05 section 2](05-technologies-for-securing-containerized-applications.md#2-docker-host-security-configurations) | [unsecured-docker-daemon](labs/unsecured-docker-daemon/README.md), [minimize-misconfigurations](labs/minimize-misconfigurations/README.md) |
| Seccomp | [05 section 3.1](05-technologies-for-securing-containerized-applications.md#31-seccomp) (example [profile](labs/minimize-misconfigurations/profiles/seccomp-web-app.json)) | [minimize-misconfigurations](labs/minimize-misconfigurations/README.md) |
| Apparmour | [05 section 3.2](05-technologies-for-securing-containerized-applications.md#32-apparmor-apparmour-in-the-syllabus) (example [profile](labs/minimize-misconfigurations/profiles/apparmor-web-app)) | [minimize-misconfigurations](labs/minimize-misconfigurations/README.md) |
| Image signing and Content Trust | [05 section 4](05-technologies-for-securing-containerized-applications.md#4-image-signing-and-content-trust) (SVG; DCT legacy, cosign/Notation current); [real-tools/cosign-notation.md](real-tools/cosign-notation.md) | [backdoor-docker-image](labs/backdoor-docker-image/README.md) (digest pin) |
| Hands-On Exercises: | Labs below | [Lab index](#lab-index) |
| Working with docker command | [01 section 4](01-introduction-to-container-technology.md#4-ways-to-interact-with-the-containers-ecosystem); [COMMANDS.md](labs/docker-commands/COMMANDS.md) | [docker-commands](labs/docker-commands/README.md) |
| Creating container snapshots | [01 section 3](01-introduction-to-container-technology.md#3-basics-of-container) | [container-snapshots](labs/container-snapshots/README.md) |
| Malicious container image | [03 section 2](03-attacking-the-container-supply-chain.md#2-malicious-images) | [malicious-image](labs/malicious-image/README.md) |
| Backdooring docker image | [03 section 2.4](03-attacking-the-container-supply-chain.md#24-backdooring-an-image-concept) | [backdoor-docker-image](labs/backdoor-docker-image/README.md) |
| Attacking docker registry | [03 section 3](03-attacking-the-container-supply-chain.md#3-insecure-container-registry) | [attack-docker-registry](labs/attack-docker-registry/README.md) |
| Exploiting containerized apps | [03 section 4](03-attacking-the-container-supply-chain.md#4-attacking-through-container-misconfigurations) | [exploit-containerized-app](labs/exploit-containerized-app/README.md) |
| Unsecured docker daemon | [04 section 5](04-securing-container-applications.md#5-securing-the-docker-daemon) | [unsecured-docker-daemon](labs/unsecured-docker-daemon/README.md) |
| Minimize docker security misconfigurations | [04](04-securing-container-applications.md), [05](05-technologies-for-securing-containerized-applications.md) | [minimize-misconfigurations](labs/minimize-misconfigurations/README.md) |
| Build a secure, miniature image to minimize attack footprint | [04 sections 3 and 4](04-securing-container-applications.md#3-distroless-and-scratch-images) | [secure-mini-image](labs/secure-mini-image/README.md) |
| Typosquatting attack in docker image | [03 section 2.3](03-attacking-the-container-supply-chain.md#23-typosquatting-and-name-confusion) | [typosquatting-image](labs/typosquatting-image/README.md) |
| Backdooring docker image | [03 section 2.4](03-attacking-the-container-supply-chain.md#24-backdooring-an-image-concept) (listed twice in the syllabus; same lab) | [backdoor-docker-image](labs/backdoor-docker-image/README.md) |
| Malicious container image | [03 section 2](03-attacking-the-container-supply-chain.md#2-malicious-images) (listed twice in the syllabus; same lab) | [malicious-image](labs/malicious-image/README.md) |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| **Image signing and Content Trust** (Docker Content Trust) | DCT (Notary v1) is **retired**: announced 29 Jul 2025, the notary.docker.io service shuts down on **8 Dec 2026**. Teach and use **cosign (Sigstore)** and **Notation (Notary Project)**. Learn DCT as legacy for the exam and for old pipelines. |
| "Apparmour" | Spelling: **AppArmor**. SELinux is the RHEL-family equivalent. Kubernetes now has a first-class `appArmorProfile` field (v1.30+, verify). |
| "Docker" as the container runtime | Kubernetes removed dockershim in 1.24 and uses containerd or CRI-O. Docker is still the developer CLI. Podman and rootless modes are common. |
| Third-party tools unnamed | Prefer maintained tools: Trivy, Grype/Syft, Dive, docker-bench-security, Harbor (CNCF graduated). Check each project's maintenance status. |
| Seccomp default profile described as fixed | The default profile evolves with Docker and kernel versions. Check your version's profile. |
| Registry API shown as Docker-only | The registry API is part of the **OCI Distribution Specification**; images follow the OCI Image Specification. |

## Learning order

1. [Lesson 01](01-introduction-to-container-technology.md), then [docker-commands](labs/docker-commands/README.md) and [container-snapshots](labs/container-snapshots/README.md). About 5 hours.
2. [Lesson 02](02-attack-surface-and-analysis-of-containers.md) (kernel features SVG). About 4 hours.
3. [Lesson 03](03-attacking-the-container-supply-chain.md), then [malicious-image](labs/malicious-image/README.md), [backdoor-docker-image](labs/backdoor-docker-image/README.md), [typosquatting-image](labs/typosquatting-image/README.md), [attack-docker-registry](labs/attack-docker-registry/README.md), [exploit-containerized-app](labs/exploit-containerized-app/README.md). About 8 hours.
4. [Lesson 04](04-securing-container-applications.md), then [secure-mini-image](labs/secure-mini-image/README.md), [unsecured-docker-daemon](labs/unsecured-docker-daemon/README.md) and [minimize-misconfigurations](labs/minimize-misconfigurations/README.md). About 6 hours.
5. [Lesson 05](05-technologies-for-securing-containerized-applications.md) and the [cosign/Notation guide](real-tools/cosign-notation.md). About 5 hours.
6. Then [Chapter 4](../ch4-attacking-kubernetes-cluster-supply-chain/README.md).

## Lab index

All labs run offline: `.venv/Scripts/python -m pytest csse-course/ch3-attacking-container-supply-chain`.

| Lab | Course exercise | Tests |
|---|---|---|
| [docker-commands](labs/docker-commands/README.md) | Working with docker command | 10 |
| [container-snapshots](labs/container-snapshots/README.md) | Creating container snapshots | 7 |
| [malicious-image](labs/malicious-image/README.md) | Malicious container image (twice) | 7 |
| [backdoor-docker-image](labs/backdoor-docker-image/README.md) | Backdooring docker image (twice) | 8 |
| [attack-docker-registry](labs/attack-docker-registry/README.md) | Attacking docker registry | 11 |
| [exploit-containerized-app](labs/exploit-containerized-app/README.md) | Exploiting containerized apps | 9 |
| [unsecured-docker-daemon](labs/unsecured-docker-daemon/README.md) | Unsecured docker daemon | 9 |
| [minimize-misconfigurations](labs/minimize-misconfigurations/README.md) | Minimize docker security misconfigurations | 9 |
| [secure-mini-image](labs/secure-mini-image/README.md) | Build a secure, miniature image to minimize attack footprint | 9 |
| [typosquatting-image](labs/typosquatting-image/README.md) | Typosquatting attack in docker image | 14 |

Hedged guides for real tools: [Docker](real-tools/docker.md), [Trivy](real-tools/trivy.md), [cosign and Notation](real-tools/cosign-notation.md).

## Exam tips

- **A container is a process.** Name the three kernel features and what each limits (see, use, do).
- **Tag versus digest.** Every supply chain answer improves with "pin by digest and verify a signature".
- **docker.sock equals root.** So does the `docker` group and an exposed 2375.
- **Dangerous flags:** `--privileged`, `docker.sock`, host mounts, `SYS_ADMIN`, `--pid/--network host`, `seccomp=unconfined`.
- **DCT:** say "legacy, retired, replaced by cosign or Notation" and still explain root, targets, snapshot and timestamp keys.
- **Distroless is not a cure.** It removes tools; it does not patch the app.
- **Layers never forget.** Deleting a secret in a later layer does not remove it.
- **Registry hardening:** auth, TLS, scoped tokens, immutable tags, scanning, audit.
- **Hedge numbers** such as CVE counts, image sizes and seccomp syscall counts.

## 15 exam-style questions

<details>
<summary>1. What is a container and how does it differ from a VM?</summary>

A container is an isolated process on the shared host kernel, built from namespaces (visibility), cgroups (resources) and capabilities/seccomp/LSM (privileges). A VM has its own kernel on a hypervisor, so its isolation boundary is stronger.
</details>

<details>
<summary>2. Name the Linux namespaces and say what each isolates.</summary>

pid (processes), net (network stack), mnt (mounts and root fs), uts (hostname), ipc (shared memory and queues), user (UID mapping), cgroup (cgroup view); newer kernels add time.
</details>

<details>
<summary>3. Why are cgroup limits a security control?</summary>

They stop one container (a miner, a fork bomb, a memory leak) from exhausting the host and affecting others: `--memory`, `--cpus`, `--pids-limit`.
</details>

<details>
<summary>4. Which capability is called "the new root" and what do you do about it?</summary>

CAP_SYS_ADMIN. Drop it, use `--cap-drop ALL` and add back only what is needed, keep default seccomp and AppArmor on.
</details>

<details>
<summary>5. List four signs of a malicious image you can see without running it.</summary>

An entrypoint that downloads and pipes a script to a shell; history steps that download binaries or install cron; unknown hosts and unusual ports; baked-in secrets or SSH keys; hidden binaries; mining strings; root user.
</details>

<details>
<summary>6. How would an attacker backdoor an image that people pull by tag, and how do you detect it?</summary>

Re-push the tag with an extra layer or a changed entrypoint. Detect with digest pins, layer diffs against a good build, SBOM and scan comparison, and signature verification with an expected identity.
</details>

<details>
<summary>7. What can an attacker do against a registry with no authentication?</summary>

Enumerate repositories and tags, read manifests and pull layers (finding secrets), and if pushes are allowed overwrite tags or delete images.
</details>

<details>
<summary>8. Give four hardening controls for a registry.</summary>

Token auth with scopes, TLS, immutable tags, separate pull and push identities, scan on push, signature requirements, audit logging, network restriction, retention rules.
</details>

<details>
<summary>9. Why is mounting docker.sock into a container dangerous?</summary>

It gives the container the daemon's API; it can launch a new privileged container with the host root mounted. The daemon runs as root, so the mounter is effectively root on the host.
</details>

<details>
<summary>10. How do you secure the Docker daemon if remote access is needed?</summary>

Prefer SSH access. If TCP is required, use port 2376 with TLS and client certificate verification, bind to a private address, firewall it, use rootless or userns-remap, and audit with CIS checks.
</details>

<details>
<summary>11. What do distroless and scratch images give you, and what do they not?</summary>

Gives: fewer packages and CVEs, no shell or package manager, smaller size. Does not give: a patched application, runtime limits, or non-root by itself (set USER). Debugging needs ephemeral containers.
</details>

<details>
<summary>12. How do multi-stage builds help security?</summary>

Build tools, source and build secrets stay in earlier stages that are discarded. Only the artifacts you copy reach the final image.
</details>

<details>
<summary>13. Compare seccomp and AppArmor.</summary>

seccomp restricts which system calls a process may make. AppArmor (or SELinux) restricts which files, networks and capabilities it may use. They stack with capabilities and user namespaces.
</details>

<details>
<summary>14. What is the status of Docker Content Trust and what replaces it?</summary>

DCT (Notary v1) is retired; the Notary service shuts down on 8 Dec 2026 (verify at source). Use Sigstore cosign (keyless or KMS keys) or Notation (X.509 and a trust policy), and verify the signer identity at admission.
</details>

<details>
<summary>15. A scan shows zero vulnerabilities in an image. Is it safe to deploy?</summary>

No. Scanners find known CVEs only. Also check provenance and signature, secrets, the entrypoint, runtime configuration (privileges, mounts, limits) and keep scanning, since new CVEs appear later.
</details>

## References

- NIST SP 800-190 Application Container Security Guide; CIS Docker Benchmark; OCI Image and Distribution Specifications.
- Docker documentation (security, seccomp, AppArmor, rootless, Content Trust retirement notice): verify at docs.docker.com.
- Sigstore docs; Notary Project docs; Trivy docs; GoogleContainerTools/distroless.
- Repo: [06 Docker](../../06-ai-devsecops/docker/README.md), [05 sandboxing](../../05-agent-security/sandboxing/README.md), [IT fundamentals lesson 04](../../cybersecurity-track/01-it-fundamentals/04-virtualization-containers-cloud-basics.md).
