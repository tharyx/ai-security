# Chapter 10: Container Reconnaissance and Attacks

This chapter covers **how to map a container environment and how it is attacked**: recon (inventory, images, Dockerfiles, volumes, networks, ports, registries, namespaces/cgroups/capabilities, native and third-party tools), the Container Attack Matrix, image-based and registry-based attacks, container escapes, daemon and kernel attacks, privilege escalation, management tools (Portainer) and OWASP Top 10 in containers. Fifteen labs run **offline with fixtures and tests: Docker is not required**.

> **Source:** unified chapter for **[CCSE 2] Container Reconnaissance** and **[CCSE 3] Attacking Containers and Containerized Apps**.
> **Safety.** Every lab is a simulation or an analysis: JSON/YAML fixtures that mirror real formats, runtime-built canaries (no secret-shaped strings in files), `.example` and documentation addresses, in-process objects, and one localhost-only mock API (the scanner refuses any non-loopback target). The escape analyzer and deepce-lite contain **no exploit code** and tests check that. Never scan or attack systems you do not own.
> **Unofficial companion.** Your course videos and lab environment are the primary source. Tool status and numbers are hedged: **verify at the source**.

## Syllabus coverage

| Syllabus item | Where to study | Lab |
|---|---|---|
| [CCSE 2] Overview of Container Security | [01 section 2](01-container-reconnaissance.md#2-overview-of-container-security); csse [lesson 02](../../csse-course/ch3-attacking-container-supply-chain/02-attack-surface-and-analysis-of-containers.md#2-overview-of-container-security) | n/a |
| [CCSE 2] Attack surface of the container ecosystem | [01 section 3](01-container-reconnaissance.md#3-attack-surface-of-the-container-ecosystem) (SVG) | [recon-builtin-tools](labs/recon-builtin-tools/README.md); csse [exploit-containerized-app](../../csse-course/ch3-attacking-container-supply-chain/labs/exploit-containerized-app/README.md) |
| [CCSE 2] Identifying the components and their security state | [01 section 4](01-container-reconnaissance.md#4-identifying-the-components-and-their-security-state-getting-an-inventory) | [recon-builtin-tools](labs/recon-builtin-tools/README.md) |
| [CCSE 2] Get an inventory of containers | [01 section 4](01-container-reconnaissance.md#4-identifying-the-components-and-their-security-state-getting-an-inventory) | [recon-builtin-tools](labs/recon-builtin-tools/README.md) |
| [CCSE 2] Docker Images | [01 section 5](01-container-reconnaissance.md#5-docker-images-dockerfile-and-environment-variables) | [recon-third-party-image-inspection](labs/recon-third-party-image-inspection/README.md) |
| [CCSE 2] Dockerfile and Environment variables | [01 section 5](01-container-reconnaissance.md#5-docker-images-dockerfile-and-environment-variables); [CH9 writing-dockerfile](../09-container-fundamentals/labs/writing-dockerfile/README.md) | [extract-secrets-from-container](labs/extract-secrets-from-container/README.md) |
| [CCSE 2] Docker volumes | [01 section 6](01-container-reconnaissance.md#6-docker-volumes-networking-and-ports) | [CH9 manage-data](../09-container-fundamentals/labs/manage-data/README.md), [recon-builtin-tools](labs/recon-builtin-tools/README.md) |
| [CCSE 2] Docker Networking | [01 section 6](01-container-reconnaissance.md#6-docker-volumes-networking-and-ports) | [CH9 docker-networking](../09-container-fundamentals/labs/docker-networking/README.md) |
| [CCSE 2] Ports used/Port forwarding | [01 section 6](01-container-reconnaissance.md#6-docker-volumes-networking-and-ports) | [CH9 docker-networking](../09-container-fundamentals/labs/docker-networking/README.md) (exposure) |
| [CCSE 2] Docker Registries | [01 section 7](01-container-reconnaissance.md#7-docker-registries) | [registry-attacks](labs/registry-attacks/README.md); csse [attack-docker-registry](../../csse-course/ch3-attacking-container-supply-chain/labs/attack-docker-registry/README.md) |
| [CCSE 2] Exhaustive review of Namespaces, cgroups and capabilities | [01 section 8.1](01-container-reconnaissance.md#81-exhaustive-review-of-namespaces-cgroups-and-capabilities); csse [kernel-features SVG](../../csse-course/ch3-attacking-container-supply-chain/02-attack-surface-and-analysis-of-containers.md#4-kernel-features-namespaces-cgroups-capabilities); repo [05 sandboxing](../../05-agent-security/sandboxing/README.md) | [deepce-exploitation](labs/deepce-exploitation/README.md) (capability decode) |
| [CCSE 2] Analysis of the attack surface | [01 sections 8 and 9](01-container-reconnaissance.md#9-attack-surface-analysis-with-third-party-tools) | [recon-builtin-tools](labs/recon-builtin-tools/README.md), [recon-third-party-image-inspection](labs/recon-third-party-image-inspection/README.md) |
| [CCSE 2] Using native tools | [01 section 8](01-container-reconnaissance.md#8-attack-surface-analysis-with-native-tools) | [recon-builtin-tools](labs/recon-builtin-tools/README.md), [snapshot-and-restore](labs/snapshot-and-restore/README.md) |
| [CCSE 2] Using third-party tools | [01 section 9](01-container-reconnaissance.md#9-attack-surface-analysis-with-third-party-tools); [real-tools/recon-tools.md](real-tools/recon-tools.md) | [recon-third-party-image-inspection](labs/recon-third-party-image-inspection/README.md) |
| [CCSE 2] Hands-On Exercises: | Labs below | [Lab index](#lab-index) |
| [CCSE 2] Using Built-in Docker Tools for Reconnaissance | [01 section 8](01-container-reconnaissance.md#8-attack-surface-analysis-with-native-tools) | [recon-builtin-tools](labs/recon-builtin-tools/README.md) |
| [CCSE 2] Use Third-party Tools for Image Inspection | [01 section 9](01-container-reconnaissance.md#9-attack-surface-analysis-with-third-party-tools) | [recon-third-party-image-inspection](labs/recon-third-party-image-inspection/README.md) |
| [CCSE 2] Scanning the Remote Host for Unauthenticated Docker API Access | [01 section 7](01-container-reconnaissance.md#7-docker-registries); [03 section 2](03-container-host-daemon-and-kernel-attacks.md#2-unauthenticated-docker-api-and-insecure-endpoint) | [remote-docker-api-scan](labs/remote-docker-api-scan/README.md) (localhost only) |
| [CCSE 2] Identify a Container and Extract Sensitive Information | [02 section 4](02-container-attack-matrix-image-and-registry-attacks.md#4-extracting-passwords-tokens-tls-certs-etc) | [extract-secrets-from-container](labs/extract-secrets-from-container/README.md) |
| [CCSE 2] Create and Restore a Snapshot of the Container for Further Analysis | [01 section 8](01-container-reconnaissance.md#8-attack-surface-analysis-with-native-tools) | [snapshot-and-restore](labs/snapshot-and-restore/README.md); csse [container-snapshots](../../csse-course/ch3-attacking-container-supply-chain/labs/container-snapshots/README.md) |
| [CCSE 3] (Note from the course: every topic/subtopic has an exercise in this module.) | [Topic-to-lab map](#every-ccse-3-topic-has-a-lab) | [container-attack-matrix](labs/container-attack-matrix/README.md) (a test proves every topic has a lab) |
| [CCSE 3] Container Attack Matrix | [02 section 2](02-container-attack-matrix-image-and-registry-attacks.md#2-the-container-attack-matrix) (SVG) | [container-attack-matrix](labs/container-attack-matrix/README.md) |
| [CCSE 3] Image-based attacks | [02 section 3](02-container-attack-matrix-image-and-registry-attacks.md#3-image-based-attacks) | [image-based-attacks](labs/image-based-attacks/README.md) |
| [CCSE 3] Malicious Images | [02 section 3.1](02-container-attack-matrix-image-and-registry-attacks.md#31-malicious-images); csse [lesson 03 section 2](../../csse-course/ch3-attacking-container-supply-chain/03-attacking-the-container-supply-chain.md#2-malicious-images) | csse [malicious-image](../../csse-course/ch3-attacking-container-supply-chain/labs/malicious-image/README.md), csse [backdoor-docker-image](../../csse-course/ch3-attacking-container-supply-chain/labs/backdoor-docker-image/README.md) |
| [CCSE 3] Extracting passwords, tokens, TLS certs, etc. | [02 section 4](02-container-attack-matrix-image-and-registry-attacks.md#4-extracting-passwords-tokens-tls-certs-etc) | [extract-secrets-from-container](labs/extract-secrets-from-container/README.md), [image-based-attacks](labs/image-based-attacks/README.md) |
| [CCSE 3] Exploiting vulnerable components | [02 section 3.2](02-container-attack-matrix-image-and-registry-attacks.md#32-exploiting-vulnerable-components) | [image-based-attacks](labs/image-based-attacks/README.md) |
| [CCSE 3] Registry-based attacks | [02 section 5](02-container-attack-matrix-image-and-registry-attacks.md#5-registry-based-attacks) | [registry-attacks](labs/registry-attacks/README.md) |
| [CCSE 3] Insecure Docker registries | [02 section 5.1](02-container-attack-matrix-image-and-registry-attacks.md#51-insecure-docker-registries) | csse [attack-docker-registry](../../csse-course/ch3-attacking-container-supply-chain/labs/attack-docker-registry/README.md), [registry-attacks](labs/registry-attacks/README.md) |
| [CCSE 3] Open Docker registries | [02 section 5.2](02-container-attack-matrix-image-and-registry-attacks.md#52-open-docker-registries) | [registry-attacks](labs/registry-attacks/README.md) |
| [CCSE 3] Lack of authorization (RBAC) | [02 section 5.3](02-container-attack-matrix-image-and-registry-attacks.md#53-lack-of-authorization-rbac) | [registry-attacks](labs/registry-attacks/README.md) |
| [CCSE 3] Container-based attacks | [03 section 1](03-container-host-daemon-and-kernel-attacks.md#1-container-based-attacks) | [container-escapes](labs/container-escapes/README.md); csse [exploit-containerized-app](../../csse-course/ch3-attacking-container-supply-chain/labs/exploit-containerized-app/README.md) |
| [CCSE 3] Manipulating the privileged mode containers | [03 section 1.1](03-container-host-daemon-and-kernel-attacks.md#11-manipulating-privileged-mode-containers) | [container-escapes](labs/container-escapes/README.md) |
| [CCSE 3] Attacking mounted Docker volumes | [03 section 1.2](03-container-host-daemon-and-kernel-attacks.md#12-attacking-mounted-docker-volumes-and-the-docker-socket) | [container-escapes](labs/container-escapes/README.md), [CH9 manage-data](../09-container-fundamentals/labs/manage-data/README.md) |
| [CCSE 3] Abusing SetUID/SetGID binaries | [03 section 1.3](03-container-host-daemon-and-kernel-attacks.md#13-abusing-setuidsetgid-binaries) | [container-escapes](labs/container-escapes/README.md) |
| [CCSE 3] Exploiting shared namespaces | [03 section 1.4](03-container-host-daemon-and-kernel-attacks.md#14-exploiting-shared-namespaces) | [container-escapes](labs/container-escapes/README.md) |
| [CCSE 3] Attacking Linux capabilities | [03 section 1.5](03-container-host-daemon-and-kernel-attacks.md#15-attacking-linux-capabilities) | [container-escapes](labs/container-escapes/README.md), [deepce-exploitation](labs/deepce-exploitation/README.md) |
| [CCSE 3] Docker host (Daemon) / kernel attacks | [03 sections 2 to 5](03-container-host-daemon-and-kernel-attacks.md#2-unauthenticated-docker-api-and-insecure-endpoint) | [daemon-and-kernel-attacks](labs/daemon-and-kernel-attacks/README.md) |
| [CCSE 3] Exploiting unauthenticated Docker API | [03 section 2](03-container-host-daemon-and-kernel-attacks.md#2-unauthenticated-docker-api-and-insecure-endpoint) | [remote-docker-api-scan](labs/remote-docker-api-scan/README.md); csse [unsecured-docker-daemon](../../csse-course/ch3-attacking-container-supply-chain/labs/unsecured-docker-daemon/README.md) |
| [CCSE 3] Insecure Docker endpoint | [03 section 2](03-container-host-daemon-and-kernel-attacks.md#2-unauthenticated-docker-api-and-insecure-endpoint) | [daemon-and-kernel-attacks](labs/daemon-and-kernel-attacks/README.md) |
| [CCSE 3] Lack of network segregation | [03 section 3](03-container-host-daemon-and-kernel-attacks.md#3-lack-of-network-segregation) | [daemon-and-kernel-attacks](labs/daemon-and-kernel-attacks/README.md), [CH9 docker-networking](../09-container-fundamentals/labs/docker-networking/README.md) |
| [CCSE 3] Denial of service attacks | [03 section 4](03-container-host-daemon-and-kernel-attacks.md#4-denial-of-service-attacks) | [daemon-and-kernel-attacks](labs/daemon-and-kernel-attacks/README.md) |
| [CCSE 3] Kernel exploits | [03 section 5](03-container-host-daemon-and-kernel-attacks.md#5-kernel-exploits) | [daemon-and-kernel-attacks](labs/daemon-and-kernel-attacks/README.md) |
| [CCSE 3] Privilege escalation methods in Docker | [03 section 6](03-container-host-daemon-and-kernel-attacks.md#6-privilege-escalation-methods-in-docker) | [privilege-escalation-and-misconfig](labs/privilege-escalation-and-misconfig/README.md) |
| [CCSE 3] Security misconfigurations | [03 section 6](03-container-host-daemon-and-kernel-attacks.md#security-misconfigurations-the-common-root-cause) | [privilege-escalation-and-misconfig](labs/privilege-escalation-and-misconfig/README.md); csse [minimize-misconfigurations](../../csse-course/ch3-attacking-container-supply-chain/labs/minimize-misconfigurations/README.md) |
| [CCSE 3] Attacking management tools (Portainer) | [04 section 2](04-management-tools-and-owasp-top10.md#2-attacking-management-tools-portainer) | [portainer-attack](labs/portainer-attack/README.md) |
| [CCSE 3] Exploiting OWASP Top 10 issues in containerized apps | [04 section 3](04-management-tools-and-owasp-top10.md#3-owasp-top-10-in-containerized-apps) | [owasp-top10-in-containers](labs/owasp-top10-in-containers/README.md) (SSRF to metadata); csse [dynamic-analysis](../../csse-course/ch2-attacking-code-and-application-supply-chain/labs/dynamic-analysis/README.md) |
| [CCSE 3] Hands-On Exercises: | Labs below | [Lab index](#lab-index) |
| [CCSE 3] Backdooring Docker Image | [02 section 3.1](02-container-attack-matrix-image-and-registry-attacks.md#31-malicious-images) | csse [backdoor-docker-image](../../csse-course/ch3-attacking-container-supply-chain/labs/backdoor-docker-image/README.md) (linked, not duplicated) |
| [CCSE 3] Inspecting Docker Daemon Activity | [04 section 4](04-management-tools-and-owasp-top10.md#4-inspecting-docker-daemon-activity) | [inspect-daemon-activity](labs/inspect-daemon-activity/README.md) |
| [CCSE 3] Malicious Container Image | [02 section 3.1](02-container-attack-matrix-image-and-registry-attacks.md#31-malicious-images) | csse [malicious-image](../../csse-course/ch3-attacking-container-supply-chain/labs/malicious-image/README.md) (linked) |
| [CCSE 3] Exploiting Containerized Apps | [03 section 1](03-container-host-daemon-and-kernel-attacks.md#1-container-based-attacks) | csse [exploit-containerized-app](../../csse-course/ch3-attacking-container-supply-chain/labs/exploit-containerized-app/README.md) (linked), [container-escapes](labs/container-escapes/README.md) |
| [CCSE 3] Unsecured Docker Daemon | [03 section 2](03-container-host-daemon-and-kernel-attacks.md#2-unauthenticated-docker-api-and-insecure-endpoint) | csse [unsecured-docker-daemon](../../csse-course/ch3-attacking-container-supply-chain/labs/unsecured-docker-daemon/README.md) (linked), [daemon-and-kernel-attacks](labs/daemon-and-kernel-attacks/README.md) |
| [CCSE 3] Docker Exploitation using deepce | [03 section 7](03-container-host-daemon-and-kernel-attacks.md#7-deepce-and-similar-tools) | [deepce-exploitation](labs/deepce-exploitation/README.md) (deepce-lite) |
| [CCSE 3] Attacking Misconfigured Docker Registry | [02 section 5](02-container-attack-matrix-image-and-registry-attacks.md#5-registry-based-attacks) | csse [attack-docker-registry](../../csse-course/ch3-attacking-container-supply-chain/labs/attack-docker-registry/README.md) (linked), [registry-attacks](labs/registry-attacks/README.md) |

### Every CCSE 3 topic has a lab

The course notes that **every topic/subtopic has an exercise in this module**. Here is the mapping, one row per topic group. The [container-attack-matrix lab](labs/container-attack-matrix/README.md) holds it as data and a test checks that each folder exists.

| CCSE 3 topic group | Lab (this chapter unless marked csse) |
|---|---|
| Container Attack Matrix | [container-attack-matrix](labs/container-attack-matrix/README.md) |
| Image-based attacks (malicious images, secrets, vulnerable components) | [image-based-attacks](labs/image-based-attacks/README.md), [extract-secrets-from-container](labs/extract-secrets-from-container/README.md), csse malicious-image and backdoor-docker-image |
| Registry-based attacks (insecure, open, no RBAC) | [registry-attacks](labs/registry-attacks/README.md), csse attack-docker-registry |
| Container-based attacks (privileged, volumes, SetUID/SetGID, shared namespaces, capabilities) | [container-escapes](labs/container-escapes/README.md) |
| Docker host (daemon) / kernel attacks (unauthenticated API, insecure endpoint, network segregation, DoS, kernel exploits) | [daemon-and-kernel-attacks](labs/daemon-and-kernel-attacks/README.md), [remote-docker-api-scan](labs/remote-docker-api-scan/README.md) |
| Privilege escalation methods; security misconfigurations | [privilege-escalation-and-misconfig](labs/privilege-escalation-and-misconfig/README.md) |
| Attacking management tools (Portainer) | [portainer-attack](labs/portainer-attack/README.md) |
| Exploiting OWASP Top 10 issues in containerized apps | [owasp-top10-in-containers](labs/owasp-top10-in-containers/README.md) |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| **deepce** as a main exploitation tool | deepce is a community shell script; check its maintenance status before use. Newer or alternative tools: **amicontained**, **CDK**, plus Trivy and **docker-bench-security** for checks. Everything it reports is also visible through `docker inspect`. |
| "Container Attack Matrix" with no name | Know the **Microsoft Threat Matrix for Kubernetes** and the **MITRE ATT&CK Containers matrix**. Both are updated over time; verify current tactics and techniques. |
| **Portainer** as the management-tool example | Same lesson applies to any management UI. Portainer's setup, defaults and editions change: verify the current install and hardening guides. |
| Docker Content Trust as the integrity answer | **DCT (Notary v1) is retired** (announced 29 Jul 2025; notary.docker.io shuts down on 8 Dec 2026). Use **cosign** or **Notation** and pin by digest. |
| Dive, Trivy and similar tools unnamed or old | Check each project's maintenance and licence. **Dockle** and **Hadolint** are image/Dockerfile linters; **Grype/Syft** are SBOM-based. |
| Registry attacks described for "Docker registry" only | The registry API is the **OCI Distribution Specification**; Harbor, GHCR, ECR and others implement it. Concepts transfer. |
| OWASP Top 10 | The labs use the **2021** list; a newer edition may exist: verify at owasp.org. |
| SSRF to metadata shown only for IMDSv1 | **IMDSv2** (token) and **hop limit 1** are the modern defence; other clouds have equivalents. |
| Kernel exploit examples from older years | Examples age quickly. Teach the **method** (version mapping, patch SLA, user-namespace and seccomp mitigations), and use your distro's security tracker for current data. |

## How the three courses overlap here

This chapter holds **CCSE 2 and CCSE 3**. The CDE 7 lines "Vulnerabilities in images", "Denial of service attacks", "Privilege escalation methods in Docker" and "Security misconfigurations" are the **attack** view of topics taught here, and appear again in **chapter 11** (defending containers) with their fixes. The sibling **csse-course ch3** already covers malicious and backdoored images, registries, the unsecured daemon and escape analysis, so five labs are **linked, not duplicated**, and this chapter adds a course-style README to each, plus the labs that csse lacks: recon, secrets, snapshots, image exploit paths, registry RBAC modes, host and kernel, privilege escalation, Portainer, OWASP and SSRF, daemon activity, deepce-lite and the attack matrix.

## Learning order

1. [Lesson 01](01-container-reconnaissance.md), then [recon-builtin-tools](labs/recon-builtin-tools/README.md), [recon-third-party-image-inspection](labs/recon-third-party-image-inspection/README.md), [remote-docker-api-scan](labs/remote-docker-api-scan/README.md), [extract-secrets-from-container](labs/extract-secrets-from-container/README.md), [snapshot-and-restore](labs/snapshot-and-restore/README.md). About 8 hours.
2. [Lesson 02](02-container-attack-matrix-image-and-registry-attacks.md), then [container-attack-matrix](labs/container-attack-matrix/README.md), [image-based-attacks](labs/image-based-attacks/README.md), [registry-attacks](labs/registry-attacks/README.md) and the csse malicious-image, backdoor and registry labs. About 8 hours.
3. [Lesson 03](03-container-host-daemon-and-kernel-attacks.md), then [container-escapes](labs/container-escapes/README.md), [daemon-and-kernel-attacks](labs/daemon-and-kernel-attacks/README.md), [privilege-escalation-and-misconfig](labs/privilege-escalation-and-misconfig/README.md), [deepce-exploitation](labs/deepce-exploitation/README.md). About 8 hours.
4. [Lesson 04](04-management-tools-and-owasp-top10.md), then [portainer-attack](labs/portainer-attack/README.md), [owasp-top10-in-containers](labs/owasp-top10-in-containers/README.md), [inspect-daemon-activity](labs/inspect-daemon-activity/README.md). About 5 hours.
5. Read the [recon tools guide](real-tools/recon-tools.md) and the [hardening guide](real-tools/hardening-registries-daemons-and-ui.md).
6. Then [Chapter 11: defending containers at scale](../11-defending-containers-at-scale/README.md).

## Lab index

All labs run offline: `.venv/Scripts/python -m pytest devsecops-course/10-container-reconnaissance-and-attacks`.

| Lab | Course exercise or topic | Tests |
|---|---|---|
| [recon-builtin-tools](labs/recon-builtin-tools/README.md) | Using Built-in Docker Tools for Reconnaissance | 7 |
| [recon-third-party-image-inspection](labs/recon-third-party-image-inspection/README.md) | Use Third-party Tools for Image Inspection | 7 |
| [remote-docker-api-scan](labs/remote-docker-api-scan/README.md) | Scanning the Remote Host for Unauthenticated Docker API Access (localhost only) | 11 |
| [extract-secrets-from-container](labs/extract-secrets-from-container/README.md) | Identify a Container and Extract Sensitive Information | 9 |
| [snapshot-and-restore](labs/snapshot-and-restore/README.md) | Create and Restore a Snapshot of the Container for Further Analysis | 8 |
| [container-attack-matrix](labs/container-attack-matrix/README.md) | Container Attack Matrix; topic-to-lab check | 8 |
| [image-based-attacks](labs/image-based-attacks/README.md) | Image-based attacks, extracting secrets, vulnerable components | 8 |
| [registry-attacks](labs/registry-attacks/README.md) | Attacking Misconfigured Docker Registry; open registries; RBAC | 8 |
| [container-escapes](labs/container-escapes/README.md) | Container-based attacks (analysis only) | 8 |
| [daemon-and-kernel-attacks](labs/daemon-and-kernel-attacks/README.md) | Daemon, endpoint, network, DoS, kernel | 9 |
| [privilege-escalation-and-misconfig](labs/privilege-escalation-and-misconfig/README.md) | Privilege escalation methods; security misconfigurations | 8 |
| [portainer-attack](labs/portainer-attack/README.md) | Attacking management tools (Portainer) | 8 |
| [owasp-top10-in-containers](labs/owasp-top10-in-containers/README.md) | OWASP Top 10 in containerized apps, SSRF to metadata | 9 |
| [inspect-daemon-activity](labs/inspect-daemon-activity/README.md) | Inspecting Docker Daemon Activity | 8 |
| [deepce-exploitation](labs/deepce-exploitation/README.md) | Docker Exploitation using deepce (deepce-lite) | 8 |

Linked from csse ch3 (not duplicated): [backdoor-docker-image](../../csse-course/ch3-attacking-container-supply-chain/labs/backdoor-docker-image/README.md), [malicious-image](../../csse-course/ch3-attacking-container-supply-chain/labs/malicious-image/README.md), [attack-docker-registry](../../csse-course/ch3-attacking-container-supply-chain/labs/attack-docker-registry/README.md), [unsecured-docker-daemon](../../csse-course/ch3-attacking-container-supply-chain/labs/unsecured-docker-daemon/README.md), [exploit-containerized-app](../../csse-course/ch3-attacking-container-supply-chain/labs/exploit-containerized-app/README.md).

Hedged guides for real tools: [recon tools](real-tools/recon-tools.md), [hardening registries, daemons and UIs](real-tools/hardening-registries-daemons-and-ui.md).

## Exam tips

- **Recon order:** inventory (`ps -a`, `inspect`, `info`), images and history, env and secrets, volumes, networks and ports, registries, then namespaces, cgroups and capabilities.
- **The three inspect fields that find most problems:** `Privileged`/`CapAdd`, `Binds`/`Mounts`, `Env`.
- **docker.sock equals root.** So does the `docker` group and an open port 2375. Read-only `:ro` on the socket does not help.
- **`--privileged`:** all capabilities, all devices, no seccomp/AppArmor. Know the escape-enabling list: privileged, socket, host mounts, SetUID, shared PID/NET/IPC, `SYS_ADMIN`, `SYS_PTRACE`, `DAC_READ_SEARCH`.
- **Shared kernel:** kernel exploits and DoS (no cgroup limits, fork bomb) hit every container. Mitigate with patches, limits, userns and sandboxed runtimes.
- **Registry attacks:** open catalog, tag overwrite, secrets in configs; fix with TLS, auth, **RBAC**, immutable tags, scan on push, signing.
- **Authentication is not authorization:** say it for registries and for UIs.
- **Management UI = daemon with a login page.** Blast radius answers.
- **SSRF to metadata:** IMDSv2 plus hop limit 1; a string blocklist is bypassable.
- **Attack matrix:** name Microsoft's Kubernetes matrix and MITRE ATT&CK Containers; give tactics in order.
- **Ethics:** scan only what you own; labs use localhost.

## 15 exam-style questions

<details>
<summary>1. What is the goal of container reconnaissance and what do you produce?</summary>

A complete inventory of containers (and the host, images, volumes, networks, ports, registries) with a security state for each and a ranked list of what to fix first. It answers: who runs it, with which privileges, what it can touch, who can reach it and what it knows.
</details>

<details>
<summary>2. Which `docker inspect` fields do you check first and why?</summary>

`HostConfig.Privileged`, `CapAdd`/`CapDrop` and `SecurityOpt` (privilege), `Binds`/`Mounts` (host access, including docker.sock), `NetworkMode`/`PidMode`/`IpcMode` (shared namespaces), `Memory`/`PidsLimit` (DoS), `Config.User` (root) and `Config.Env` (secrets).
</details>

<details>
<summary>3. How can you tell from inside a container whether a namespace is shared with the host?</summary>

Compare the links in `/proc/<pid>/ns` of the container process with those of the host (identical target means shared), and check `NetworkMode`, `PidMode`, `IpcMode` in inspect. Seeing the host's init as PID 1 means the host PID namespace is shared.
</details>

<details>
<summary>4. Why does an image's history matter during recon?</summary>

`docker history --no-trunc` shows each build step, including `ENV` secrets, `curl | sh` downloads and copied keys. Files deleted in a later layer are still in the earlier layer, so a scanner or an attacker can extract them.
</details>

<details>
<summary>5. What does an unauthenticated Docker API on TCP 2375 give an attacker, and how do you fix it?</summary>

Full control of the daemon: list containers and read their env, create a container with the host file system mounted and any privilege, so it is remote root. Fix: use the Unix socket or `ssh://`; if TCP is needed use 2376 with `tlsverify` and client certificates on a private address, firewall it, and consider rootless.
</details>

<details>
<summary>6. Why is mounting `/var/run/docker.sock` into a container dangerous even read-only?</summary>

The socket is the daemon's API. Read-only mount flags apply to file operations, not to API calls made through the socket, so the container can still ask the root daemon to create a privileged container with host mounts. It is root-equivalent on the host.
</details>

<details>
<summary>7. List the dangerous capabilities and what each enables.</summary>

`SYS_ADMIN` (mounts, many namespace and cgroup operations: "the new root"), `SYS_PTRACE` (inspect and alter processes, dangerous with a shared PID namespace), `DAC_READ_SEARCH` (bypass file read checks), `SYS_MODULE` (load kernel modules), `NET_ADMIN` (change routes and firewall). Use `--cap-drop ALL` and add back the minimum.
</details>

<details>
<summary>8. What risk do SetUID binaries pose in a container image?</summary>

They run with their owner's rights (often root) so a flaw or risky feature can turn a low-privileged process into root inside the container, the first step of many other attacks. Mitigate with `no-new-privileges`, stripping the SetUID bits, and distroless images.
</details>

<details>
<summary>9. How do missing cgroup limits enable denial of service?</summary>

A container without `--memory`, `--cpus` or `--pids-limit` can consume all memory, CPU or process slots of the host. A fork bomb doubles processes each generation until the host's `pid_max`, breaking every container. A pids limit contains it inside the cgroup.
</details>

<details>
<summary>10. Why are kernel exploits a special problem for containers?</summary>

All containers share the host kernel, so one kernel flaw can break out of every container on the host regardless of its configuration. Defence: patch the kernel and runtimes quickly, keep seccomp, use user namespaces or rootless mode, and use sandboxed runtimes (gVisor, Kata) for untrusted code.
</details>

<details>
<summary>11. Why is membership of the `docker` group a privilege escalation path?</summary>

Group members can use the socket of the root daemon, so they can start containers with host mounts and privileges: it is root with another name. Remove users, use rootless Docker or Podman, or a narrow sudo wrapper.
</details>

<details>
<summary>12. Explain open registry attacks and how RBAC changes them.</summary>

With no authentication anyone can read the catalog, tags, manifests and layers (finding secrets), and, if pushes are allowed, overwrite a tag so the next deployment runs attacker code, or delete images. Authentication alone still lets any valid user do all of that; RBAC scopes who can pull, push and delete, and immutable tags stop overwrites even by a CI token.
</details>

<details>
<summary>13. Why are management tools such as Portainer high-value targets?</summary>

They hold the Docker socket or agents on many hosts, so anyone who logs in can do what the socket can do. Weak points: public exposure, first-run admin takeover, default credentials, no MFA, no roles. Harden with private access, SSO/MFA, RBAC, TLS, socket proxy, updates and audit.
</details>

<details>
<summary>14. How does SSRF in a containerized app reach cloud credentials and how do you stop it?</summary>

The app is tricked into fetching the metadata address 169.254.169.254, which can return the instance role's credentials. Stop it with URL validation after canonicalisation (a string blocklist is bypassable), IMDSv2 (token required) with hop limit 1, least-privilege roles, workload identity and network policy.
</details>

<details>
<summary>15. What is the Container Attack Matrix and how do you use it?</summary>

A table of attacker tactics (Initial Access to Impact) with techniques under each, such as Microsoft's Threat Matrix for Kubernetes and the MITRE ATT&CK Containers matrix. Use it as shared vocabulary in reports, to check which tactics you have no detection or control for, and to plan assessments. Verify current versions at source.
</details>

## References

- NIST SP 800-190; CIS Docker Benchmark; OWASP Docker Security Cheat Sheet; OWASP Top 10; OWASP SSRF Prevention Cheat Sheet.
- Microsoft Threat Matrix for Kubernetes; MITRE ATT&CK Containers matrix (attack.mitre.org): verify current versions.
- Docker docs: protect the daemon socket, rootless mode, userns-remap, seccomp. OCI Distribution Specification.
- Dive, Trivy, Grype, Syft, amicontained, deepce, CDK, docker-bench-security, Dockle, Hadolint, Harbor, Portainer: project pages (verify status and licences).
- Repo: csse [ch3](../../csse-course/ch3-attacking-container-supply-chain/README.md), [ch2 dynamic-analysis](../../csse-course/ch2-attacking-code-and-application-supply-chain/labs/dynamic-analysis/README.md), [06 Docker](../../06-ai-devsecops/docker/README.md), [05 sandboxing](../../05-agent-security/sandboxing/README.md), [cybersecurity-track 09 pentesting](../../cybersecurity-track/09-pentesting-fundamentals/README.md).
