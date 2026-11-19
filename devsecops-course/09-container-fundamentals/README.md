# Chapter 9: Container Fundamentals

This chapter covers **what containers are and how the Docker ecosystem fits together**: the kernel features, the Docker CLI, Engine and runtime, images and Dockerfiles, registries, running many containers (Compose, Swarm, Kubernetes) and the alternatives (Podman, CRI-O). It is the base for the attack chapter (CH10) and the defence chapter (CH11). Eight labs run **offline with fixtures and tests: Docker is not required**.

> **Source:** unified chapter for **[CCSE 1] Introduction to Containers**.
> **Safety.** Every lab is a simulation: fixtures that mirror real formats (`docker inspect`, compose files, Dockerfiles, registry concepts). Nothing is executed or sent over a network. Run real Docker only on a disposable lab VM.
> **Unofficial companion.** Your course videos and lab environment are the primary source. Tool status and numbers are hedged: **verify at the source**.

## Syllabus coverage

| Syllabus item | Where to study | Lab |
|---|---|---|
| [CCSE 1] What is a container? | [01 section 1](01-what-is-a-container.md#1-what-is-a-container); csse [lesson 01](../../csse-course/ch3-attacking-container-supply-chain/01-introduction-to-container-technology.md#2-what-is-a-container) | [docker-command](labs/docker-command/README.md) |
| [CCSE 1] Basics of a container and its challenges | [01 section 2](01-what-is-a-container.md#2-basics-of-a-container-and-its-challenges) | [docker-command](labs/docker-command/README.md) |
| [CCSE 1] Container vs. Virtualization | [01 section 3](01-what-is-a-container.md#3-container-vs-virtualization) (SVG); repo [IT fundamentals lesson 04](../../cybersecurity-track/01-it-fundamentals/04-virtualization-containers-cloud-basics.md) | n/a |
| [CCSE 1] Container Advantages | [01 section 4](01-what-is-a-container.md#4-container-advantages) | n/a |
| [CCSE 1] Container Disadvantages | [01 section 5](01-what-is-a-container.md#5-container-disadvantages) | n/a |
| [CCSE 1] Container fundamentals | [01 section 6](01-what-is-a-container.md#6-container-fundamentals-the-three-kernel-features); csse [kernel-features SVG](../../csse-course/ch3-attacking-container-supply-chain/02-attack-surface-and-analysis-of-containers.md#4-kernel-features-namespaces-cgroups-capabilities); repo [05 sandboxing](../../05-agent-security/sandboxing/README.md) | [docker-command](labs/docker-command/README.md) |
| [CCSE 1] Namespaces | [01 section 6.1](01-what-is-a-container.md#61-namespaces-what-the-process-can-see) | [docker-networking](labs/docker-networking/README.md) (net namespace) |
| [CCSE 1] Cgroup | [01 section 6.2](01-what-is-a-container.md#62-cgroups-what-the-process-can-use) | [docker-command](labs/docker-command/README.md) (limits flags) |
| [CCSE 1] Capabilities | [01 section 6.3](01-what-is-a-container.md#63-capabilities-what-root-can-do) | [CH10 container-escapes](../10-container-reconnaissance-and-attacks/labs/container-escapes/README.md) |
| [CCSE 1] Docker architecture and its components | [02 section 1](02-docker-architecture-and-runtime.md#1-the-big-picture) (SVG) | [docker-sdk](labs/docker-sdk/README.md) |
| [CCSE 1] Docker CLI | [02 section 2](02-docker-architecture-and-runtime.md#2-docker-cli); [csse COMMANDS.md](../../csse-course/ch3-attacking-container-supply-chain/labs/docker-commands/COMMANDS.md) | [docker-command](labs/docker-command/README.md) |
| [CCSE 1] Docker Engine (Daemon, API) | [02 section 3](02-docker-architecture-and-runtime.md#3-the-docker-engine-daemon-and-api) | [docker-sdk](labs/docker-sdk/README.md) |
| [CCSE 1] Docker Runtime (containerd, shim, runc) | [02 section 4](02-docker-architecture-and-runtime.md#4-docker-runtime-containerd-shim-runc) | n/a (concept; commands in [real-tools/docker.md](real-tools/docker.md)) |
| [CCSE 1] Interacting with the container ecosystem | [02 section 5](02-docker-architecture-and-runtime.md#5-interacting-with-the-container-ecosystem) | [docker-command](labs/docker-command/README.md), [docker-sdk](labs/docker-sdk/README.md) |
| [CCSE 1] Docker images and image layers | [03 section 2](03-images-dockerfile-and-registries.md#2-images-and-layers); repo [06 Docker](../../06-ai-devsecops/docker/README.md) | [dockerfile-build](labs/dockerfile-build/README.md), [manage-data](labs/manage-data/README.md) |
| [CCSE 1] Build Container images using Dockerfile | [03 sections 3 and 4](03-images-dockerfile-and-registries.md#3-building-images-with-a-dockerfile) | [dockerfile-build](labs/dockerfile-build/README.md), [writing-dockerfile](labs/writing-dockerfile/README.md) |
| [CCSE 1] Docker image repository | [03 section 5](03-images-dockerfile-and-registries.md#5-image-repositories-and-registries) | [container-registry](labs/container-registry/README.md) |
| [CCSE 1] Running a container | [03 section 7](03-images-dockerfile-and-registries.md#7-running-a-container) | [docker-command](labs/docker-command/README.md) |
| [CCSE 1] Managing / Orchestrating multiple containers | [04 section 1](04-orchestration-and-alternatives.md#1-why-orchestrate) | [docker-compose](labs/docker-compose/README.md) |
| [CCSE 1] Using CLI/API to manage multiple containers | [04 section 2](04-orchestration-and-alternatives.md#2-using-the-cli-and-api-to-manage-many-containers) | [docker-sdk](labs/docker-sdk/README.md) |
| [CCSE 1] Docker Compose | [04 section 3](04-orchestration-and-alternatives.md#3-docker-compose) | [docker-compose](labs/docker-compose/README.md) |
| [CCSE 1] Docker Swarm | [04 section 4](04-orchestration-and-alternatives.md#4-docker-swarm) (status hedged) | n/a (concept) |
| [CCSE 1] Kubernetes | [04 section 5](04-orchestration-and-alternatives.md#5-kubernetes); [csse ch4](../../csse-course/ch4-attacking-kubernetes-cluster-supply-chain/README.md) | n/a (see csse ch4 labs) |
| [CCSE 1] Docker alternatives | [04 section 6](04-orchestration-and-alternatives.md#6-docker-alternatives); [real-tools/podman-and-cri-o.md](real-tools/podman-and-cri-o.md) | n/a |
| [CCSE 1] Podman | [04 section 6.1](04-orchestration-and-alternatives.md#61-podman) | n/a ([guide](real-tools/podman-and-cri-o.md)) |
| [CCSE 1] CRI-O | [04 section 6.2](04-orchestration-and-alternatives.md#62-cri-o) | n/a ([guide](real-tools/podman-and-cri-o.md)) |
| [CCSE 1] Hands-On Exercises: | Labs below | [Lab index](#lab-index) |
| [CCSE 1] Working With Docker Command | [02 section 2](02-docker-architecture-and-runtime.md#2-docker-cli); [COMMANDS.md](../../csse-course/ch3-attacking-container-supply-chain/labs/docker-commands/COMMANDS.md) | [docker-command](labs/docker-command/README.md) |
| [CCSE 1] Docker Networking | [02 section 6](02-docker-architecture-and-runtime.md#6-docker-networking) | [docker-networking](labs/docker-networking/README.md) |
| [CCSE 1] Manage Data in Docker | [03 section 6](03-images-dockerfile-and-registries.md#6-data-volumes-bind-mounts-tmpfs) | [manage-data](labs/manage-data/README.md) |
| [CCSE 1] Create Docker Image using Dockerfile | [03 section 3](03-images-dockerfile-and-registries.md#3-building-images-with-a-dockerfile) | [dockerfile-build](labs/dockerfile-build/README.md) |
| [CCSE 1] Writing Dockerfile | [03 section 4](03-images-dockerfile-and-registries.md#4-writing-a-good-dockerfile) | [writing-dockerfile](labs/writing-dockerfile/README.md) |
| [CCSE 1] How To Use Container Registry | [03 section 5](03-images-dockerfile-and-registries.md#5-image-repositories-and-registries) | [container-registry](labs/container-registry/README.md) |
| [CCSE 1] Learn Docker Compose | [04 section 3](04-orchestration-and-alternatives.md#3-docker-compose) | [docker-compose](labs/docker-compose/README.md) |
| [CCSE 1] Working With Docker SDK | [02 section 3](02-docker-architecture-and-runtime.md#3-the-docker-engine-daemon-and-api) | [docker-sdk](labs/docker-sdk/README.md) |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| **Docker Swarm** taught as a main orchestrator | Swarm mode is still built into Docker Engine; Mirantis committed to support it through at least 2030, but Docker Inc. is not actively developing it. **Kubernetes is the default for new work.** Learn Swarm for older estates and exams. |
| "Docker Runtime" as the Kubernetes runtime | **dockershim was removed in Kubernetes 1.24.** Clusters use **containerd** or **CRI-O**. Docker Engine itself uses containerd + runc. |
| "Docker image repository" without trust | **Docker Content Trust (Notary v1) is retired** (announced 29 Jul 2025; notary.docker.io shuts down on 8 Dec 2026). Use **cosign** or **Notation**. Pin images by digest. |
| Compose as `docker-compose` | **Compose v2** is the `docker compose` plugin; the Python `docker-compose` v1 is legacy. |
| Daemon-centric view of Docker | **Podman** is daemonless and rootless-friendly; **rootless Docker** also exists. Treat the root daemon as a risk, not a given. |
| cgroups described generically | Modern hosts use **cgroup v2**. Older breakout write-ups assume v1: check the version. |
| Docker SDK shown without a version | The Python package is `docker`; method names and return types change between versions. Verify at the SDK docs. |

## How the three courses overlap here

This chapter is the **CCSE 1** material only. The CDE 7 "What is Docker / Docker vs Vagrant / basics and challenges" lines belong to **chapter 11** (defending containers), where they are merged with CCSE 4. The sibling **csse-course ch3** already teaches the same fundamentals from a supply chain angle, so this chapter **links** to its lessons and docker-commands lab and **adds** what the CCSE syllabus asks for and csse lacks: Docker architecture in depth, Dockerfile builds and cache, networking, data, registries, Compose, the SDK, Swarm, Kubernetes, Podman and CRI-O.

## Learning order

1. [Lesson 01](01-what-is-a-container.md), then the csse [docker-commands lab](../../csse-course/ch3-attacking-container-supply-chain/labs/docker-commands/README.md) and [docker-command](labs/docker-command/README.md). About 4 hours.
2. [Lesson 02](02-docker-architecture-and-runtime.md), then [docker-networking](labs/docker-networking/README.md) and [docker-sdk](labs/docker-sdk/README.md). About 4 hours.
3. [Lesson 03](03-images-dockerfile-and-registries.md), then [manage-data](labs/manage-data/README.md), [dockerfile-build](labs/dockerfile-build/README.md), [writing-dockerfile](labs/writing-dockerfile/README.md), [container-registry](labs/container-registry/README.md). About 6 hours.
4. [Lesson 04](04-orchestration-and-alternatives.md), then [docker-compose](labs/docker-compose/README.md) and the [Podman and CRI-O guide](real-tools/podman-and-cri-o.md). About 4 hours.
5. Then [Chapter 10: reconnaissance and attacks](../10-container-reconnaissance-and-attacks/README.md).

## Lab index

All labs run offline: `.venv/Scripts/python -m pytest devsecops-course/09-container-fundamentals`.

| Lab | Course exercise | Tests |
|---|---|---|
| [docker-command](labs/docker-command/README.md) | Working With Docker Command (links the csse lab) | 5 |
| [docker-networking](labs/docker-networking/README.md) | Docker Networking | 9 |
| [manage-data](labs/manage-data/README.md) | Manage Data in Docker | 7 |
| [dockerfile-build](labs/dockerfile-build/README.md) | Create Docker Image using Dockerfile | 8 |
| [writing-dockerfile](labs/writing-dockerfile/README.md) | Writing Dockerfile | 7 |
| [container-registry](labs/container-registry/README.md) | How To Use Container Registry | 9 |
| [docker-compose](labs/docker-compose/README.md) | Learn Docker Compose | 9 |
| [docker-sdk](labs/docker-sdk/README.md) | Working With Docker SDK | 9 |

Hedged guides for real tools: [Docker, Compose, registry and SDK](real-tools/docker.md), [Podman and CRI-O](real-tools/podman-and-cri-o.md).

## Exam tips

- **A container is a process.** Name the three features and what each limits: namespaces (see), cgroups (use), capabilities (do).
- **Container vs VM:** shared kernel versus own kernel. Say "weaker boundary, faster, lighter".
- **Docker stack order:** CLI, dockerd (Engine/API), containerd, shim, runc. Know that runc creates the container then exits and the shim stays.
- **Layers:** only `RUN`, `COPY`, `ADD` add layers; a change invalidates all later layers; deleted files stay in earlier layers.
- **Tag vs digest:** a tag moves, a digest does not. Deploy by digest.
- **Volumes vs bind mounts vs tmpfs:** know what survives `rm`.
- **Compose vs Swarm vs Kubernetes:** one host, a Docker-native cluster (maintenance mode), the industry standard.
- **Podman:** daemonless, rootless-friendly. **CRI-O:** a Kubernetes-only CRI runtime.
- **Publishing a port** with `-p 8080:80` binds all interfaces. Use `127.0.0.1:8080:80` to keep it local.
- **docker.sock is root.** So is the `docker` group.

## 15 exam-style questions

<details>
<summary>1. What is a container, in one sentence?</summary>

A normal Linux process (or group of processes) isolated by kernel features: namespaces limit what it sees, cgroups limit what it uses, and capabilities, seccomp and AppArmor/SELinux limit what it can do. It runs on the shared host kernel.
</details>

<details>
<summary>2. Give three differences between a container and a VM.</summary>

A VM has its own guest kernel on a hypervisor and a stronger boundary; a container shares the host kernel. Containers start in seconds and are MBs; VMs take longer and are GBs. A VM escape needs a hypervisor bug; a container escape is often just a bad run option such as `--privileged` or a mounted `docker.sock`.
</details>

<details>
<summary>3. Name the Linux namespaces and what each isolates.</summary>

pid (processes), net (network stack), mnt (mounts and root file system), uts (hostname), ipc (shared memory and queues), user (UID mapping), cgroup (cgroup view), time (clocks, newer kernels).
</details>

<details>
<summary>4. Why do cgroup limits matter for security?</summary>

They stop one container from exhausting host memory, CPU or process IDs (a leak, a miner or a fork bomb), which would be a denial of service for every other container. Flags: `--memory`, `--cpus`, `--pids-limit`.
</details>

<details>
<summary>5. Which capabilities are the most dangerous to add and why?</summary>

`SYS_ADMIN` (mounts, many namespace and cgroup operations: "the new root"), `SYS_PTRACE` (inspect and alter other processes), `DAC_READ_SEARCH` (bypass file read checks), `SYS_MODULE` (load kernel modules), `NET_ADMIN` (change network configuration). Prefer `--cap-drop ALL` and add back only what is needed.
</details>

<details>
<summary>6. Describe the path of `docker run nginx` through the Docker components.</summary>

The CLI sends an HTTP request to the Engine's API on the Unix socket. dockerd pulls the image (via containerd) and asks containerd to create the container. containerd starts a shim, the shim calls runc, runc sets up namespaces, cgroups, capabilities and seccomp, then starts the nginx process and exits. The shim keeps the process attached.
</details>

<details>
<summary>7. Why is access to the Docker daemon API dangerous?</summary>

The daemon runs as root and the API can create containers with any mount and privilege. Whoever can call it, through the socket, the `docker` group or an unauthenticated TCP port, is effectively root on the host.
</details>

<details>
<summary>8. What happens to layers when a later `RUN rm secret` is executed?</summary>

The file is hidden in the final view (a whiteout) but the earlier layer still contains it. Anyone who pulls the image can extract it. Use multi-stage builds and BuildKit secret mounts instead.
</details>

<details>
<summary>9. Why should you copy `requirements.txt` and install dependencies before copying the source?</summary>

The build cache reuses a layer only while it and all earlier layers are unchanged. Source changes often, dependencies rarely. Putting `COPY . .` first would rebuild the dependency layer on every code edit.
</details>

<details>
<summary>10. Tag versus digest: which should production use and why?</summary>

The digest. A tag is a movable pointer that anyone with push rights can repoint; a digest is the sha256 of the manifest and always names the same content. Combine with signature verification (cosign or Notation).
</details>

<details>
<summary>11. Compare volumes, bind mounts and tmpfs.</summary>

A volume is Docker-managed storage that survives `rm` (use for databases). A bind mount maps a host path into the container, survives `rm` and gives the container access to the host file system (risky for sensitive paths). tmpfs lives in RAM and disappears when the container stops (good for secrets in memory).
</details>

<details>
<summary>12. What does `depends_on` guarantee in Compose?</summary>

Only start order. With `condition: service_healthy` it waits for a passing healthcheck. It does not guarantee the dependency is ready or secure otherwise.
</details>

<details>
<summary>13. What is the status of Docker Swarm today?</summary>

Still built into Docker Engine and working. Mirantis has committed to support it through at least 2030 but Docker Inc. is not actively developing it, so Kubernetes is the default for new projects (verify at source).
</details>

<details>
<summary>14. How do Podman and rootless Docker improve security?</summary>

Podman has no always-on root daemon and runs rootless by default for normal users; rootless Docker runs the daemon as the user. A container escape then lands as an unprivileged user and the "docker group equals root" problem disappears.
</details>

<details>
<summary>15. What is CRI-O and why did dockershim removal matter?</summary>

CRI-O is a lightweight runtime that implements the Kubernetes Container Runtime Interface (CRI) and runs containers via an OCI runtime. Kubernetes 1.24 removed dockershim, so clusters now use containerd or CRI-O directly; the Docker daemon is usually not present on nodes.
</details>

## References

- NIST SP 800-190 Application Container Security Guide; CIS Docker Benchmark; OCI Image, Runtime and Distribution Specifications.
- Docker documentation (architecture, storage, networking, Compose, Swarm status, Content Trust retirement notice): verify at docs.docker.com.
- Podman, CRI-O, containerd and runc project documentation; Kubernetes docs on dockershim removal.
- Repo: [csse ch3](../../csse-course/ch3-attacking-container-supply-chain/README.md), [06 Docker](../../06-ai-devsecops/docker/README.md), [05 sandboxing](../../05-agent-security/sandboxing/README.md), [IT fundamentals lesson 04](../../cybersecurity-track/01-it-fundamentals/04-virtualization-containers-cloud-basics.md).
