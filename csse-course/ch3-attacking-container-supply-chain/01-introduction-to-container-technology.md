# Lesson 01: Introduction to Container Technology

> **Chapter:** 3 · Attacking the Container Supply Chain · **Time:** ~3 hours
> **You will:** explain what a container is (and is not), name the pieces of the container ecosystem, read an image manifest, and use the main ways to talk to a container runtime.

| | |
|---|---|
| **Prerequisites** | [IT fundamentals lesson 04: virtualization and containers](../../cybersecurity-track/01-it-fundamentals/04-virtualization-containers-cloud-basics.md); basic Linux |
| **Labs** | [docker-commands](labs/docker-commands/README.md) · [container-snapshots](labs/container-snapshots/README.md) |
| **Syllabus lines** | What is a container · Basics of container · Ways to interact with containers ecosystem |
| **Maps to** | NIST SP 800-190 (Application Container Security Guide) · CIS Docker Benchmark · OWASP Docker Security Cheat Sheet |

## 1. Why it matters

Almost every cloud workload you will assess is a container. Supply chain attackers like containers because an **image is a bundle of code that other people download and run as is**. One poisoned base image reaches thousands of builds. You cannot attack or defend what you cannot describe, so start with exact words.

## 2. What is a container

A container is **a normal Linux process (or group of processes) that the kernel isolates**. It is not a small virtual machine. There is no hypervisor and no separate kernel. Three kernel features create the isolation (see [lesson 02](02-attack-surface-and-analysis-of-containers.md#4-kernel-features-namespaces-cgroups-capabilities) and the SVG there):

- **Namespaces** limit what the process can *see* (processes, network, mounts, users).
- **Cgroups** limit what it can *use* (memory, CPU, process count).
- **Capabilities, seccomp and AppArmor/SELinux** limit what it can *do*.

| | Virtual machine | Container |
|---|---|---|
| Kernel | Own kernel per VM | **Shared host kernel** |
| Isolation boundary | Hypervisor (strong) | Kernel features (weaker) |
| Start time and size | Minutes, GBs | Seconds, MBs |
| Typical escape cause | Hypervisor bug (rare) | Kernel bug or **bad run configuration** (common) |

> **Windows note.** Windows containers use different mechanisms, and Docker Desktop on Windows or macOS runs Linux containers inside a small Linux VM. The security story in this chapter is about Linux containers.

## 3. Basics of container

### 3.1 Image, container, registry

- **Image:** a read-only template. A stack of **layers** (tar files of file changes) plus a **config JSON** (entrypoint, user, environment, exposed ports, history) plus a **manifest** (the list of layer digests). Defined by the OCI image specification.
- **Container:** a running instance: the image layers plus one thin **writable layer** on top.
- **Registry:** a server that stores images and serves them over the Registry HTTP API (Docker Hub, GHCR, ECR, Harbor, a private registry). See [attack-docker-registry](labs/attack-docker-registry/README.md).
- **Tag vs digest:** `nginx:1.27` is a movable label. `nginx@sha256:<64 hex>` is a content hash that cannot move. **Supply chain security leans on digests.**

An abridged manifest (real format, fake digests):

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {"digest": "sha256:aaaa...", "size": 1450},
  "layers": [
    {"digest": "sha256:bbbb...", "size": 29000000},
    {"digest": "sha256:cccc...", "size": 4100000}
  ]
}
```

### 3.2 The Dockerfile and layers

Each `FROM`, `RUN`, `COPY` and `ADD` can create a layer. **Layers never forget**: a later `RUN rm secret` hides the file but the earlier layer still holds it ([06 Docker lesson, section 2.1](../../06-ai-devsecops/docker/README.md)). The [container-snapshots lab](labs/container-snapshots/README.md) shows this with a layer diff.

### 3.3 The runtime stack

```text
docker CLI  ->  dockerd (daemon, root)  ->  containerd  ->  runc (creates the container with namespaces/cgroups)
                                              ^ Kubernetes talks to containerd or CRI-O directly through the CRI
```

Other names you will meet: **Podman** (daemonless, can run rootless), **CRI-O**, **BuildKit** (builder), **Buildah**, **Kaniko** (build in a cluster without a daemon), **gVisor** and **Kata Containers** (stronger isolation runtimes). The **Docker daemon runs as root and its API is root-equivalent**, which is the root of many attacks in this chapter.

## 4. Ways to interact with the containers ecosystem

| Way | What it is | Security note |
|---|---|---|
| **CLI** (`docker`, `podman`, `nerdctl`, `crictl`) | Talks to the daemon over `/var/run/docker.sock` | Anyone in the `docker` group is effectively root |
| **Docker Engine API** | REST over a Unix socket or TCP (2375 plain, 2376 TLS) | An exposed 2375 is full host takeover. See [unsecured-docker-daemon](labs/unsecured-docker-daemon/README.md) |
| **Registry API / OCI distribution** | `/v2/` paths for catalog, tags, manifests, blobs | Auth, TLS, scopes and immutable tags matter |
| **Docker Compose** | YAML for multi-container apps | Compose files can mount host paths and set `privileged` |
| **Kubernetes** | Orchestrator that schedules pods onto container runtimes | Chapter 4 |
| **Build systems and CI** | Build and push images automatically | Build credentials and pushes are a prime target |
| **Desktop tools and extensions** | Docker Desktop, Rancher Desktop, IDE plugins | Convenient and often over-privileged |
| **Image tools** | `skopeo`, `crane`, `oras`, `dive`, `syft`, `trivy`, `cosign` | Inspect and move images without running them |

Rule of thumb for later: **reading an image (inspect, scan, diff) is safe; running an unknown image is not**. Prefer tools that never execute the image.

## 5. Defend: foundations

1. Treat access to the daemon as root access.
2. Pull from known registries, by digest.
3. Run as non-root, with the fewest capabilities and a read-only filesystem.
4. Scan and sign images; keep the records.

## 6. Hands-on

1. Read [COMMANDS.md](labs/docker-commands/COMMANDS.md) and run the [docker-commands lab](labs/docker-commands/README.md) to see how run flags change risk.
2. In the [container-snapshots lab](labs/container-snapshots/README.md) commit a simulated container, save it, and diff the layers.
3. With real Docker (optional, see [real-tools/docker.md](real-tools/docker.md)): `docker image inspect alpine:3.20` and find the layer digests and config.

## 7. Scenario

A teammate says "containers are isolated, so we can run this third-party image with `--privileged` to get USB access". Explain why a privileged container shares the kernel and devices of the host and is therefore not isolated, and propose `--device` for the one device instead.

## 8. Interview Q&A

<details>
<summary>What is a container, in one sentence?</summary>

A process (or group of processes) on the host kernel, isolated by namespaces, limited by cgroups and restricted by capabilities, seccomp and LSM profiles.
</details>

<details>
<summary>Why is a container weaker isolation than a VM?</summary>

All containers share the host kernel, so a kernel vulnerability or a dangerous configuration (privileged, host mounts, docker.sock) can reach the host. A VM adds a hypervisor boundary with a separate kernel.
</details>

<details>
<summary>What is the difference between an image tag and a digest?</summary>

A tag is a mutable pointer that the registry owner (or an attacker with push access) can move. A digest is the SHA-256 of the manifest, so it identifies exact content.
</details>

## 9. References

- NIST SP 800-190, Application Container Security Guide.
- OCI Image Specification and Distribution Specification (opencontainers.org).
- Docker documentation: security overview (verify the current page at docs.docker.com).
- Repo: [06 Docker](../../06-ai-devsecops/docker/README.md), [05 sandboxing](../../05-agent-security/sandboxing/README.md).
