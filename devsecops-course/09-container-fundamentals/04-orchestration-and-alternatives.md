# Lesson 04: Managing Many Containers, and Docker Alternatives

> **Chapter:** 9 · Container Fundamentals · **Time:** ~3 hours
> **You will:** choose between the CLI/API, Compose, Swarm and Kubernetes for running many containers, read a Compose file for security problems, and explain Podman and CRI-O.

| | |
|---|---|
| **Prerequisites** | [Lessons 02](02-docker-architecture-and-runtime.md) and [03](03-images-dockerfile-and-registries.md) |
| **Labs** | [docker-compose](labs/docker-compose/README.md) · [docker-sdk](labs/docker-sdk/README.md) |
| **Syllabus lines** | Managing / Orchestrating multiple containers · Using CLI/API to manage multiple containers · Docker Compose · Docker Swarm · Kubernetes · Docker alternatives · Podman · CRI-O |
| **Reuse** | Kubernetes depth is in [csse ch4](../../csse-course/ch4-attacking-kubernetes-cluster-supply-chain/README.md) |

## 1. Why orchestrate?

One container is easy. A real system has tens: web, API, database, cache, workers. You need to **start them in order, connect them, restart the failed ones, scale them and update them without downtime**. DBA analogy: the difference between one instance on your laptop and a RAC cluster with Data Guard and a scheduler.

## 2. Using the CLI and API to manage many containers

The simplest way is a script: loops of `docker run`, or the SDK ([docker-sdk lab](labs/docker-sdk/README.md)). Filters help: `docker ps --filter label=app=shop`, `docker stop $(docker ps -q --filter name=shop-)`. It works but you carry all the logic: ordering, restarts, rollouts. Security note: every script or CI job that holds the socket is root-equivalent on that host.

## 3. Docker Compose

Compose describes a **multi-container app on one host** in a YAML file (`compose.yaml`) and runs it with `docker compose up`. It defines services, networks, volumes, ports, environment, `depends_on` and healthchecks.

```yaml
services:
  web:
    image: nginx:1.27@sha256:<digest>
    ports: ["127.0.0.1:8080:80"]
    depends_on:
      api: {condition: service_healthy}
  api:
    build: ./api
    healthcheck: {test: ["CMD", "true"]}
    networks: [frontend, backend]
  db:
    image: postgres:16
    volumes: [dbdata:/var/lib/postgresql/data]
    networks: [backend]
```

What to check in a Compose file (the [docker-compose lab](labs/docker-compose/README.md) automates it): `privileged: true`, a `docker.sock` volume, `network_mode: host`, `cap_add`, ports on all interfaces, secrets in `environment:`, `:latest` images, missing limits, and `depends_on` without a healthcheck. Use `secrets:` (file-based) instead of environment variables.

Compose v2 is the `docker compose` plugin; the old Python `docker-compose` v1 is legacy (verify at source). Compose is for development, tests and small single-host deployments, not for high availability.

## 4. Docker Swarm

Swarm is Docker's built-in clustering: `docker swarm init`, services, replicas, overlay networks, secrets and rolling updates, with a Raft-based manager quorum.

**Status (Nov 2026, verify at source):** Swarm mode is still built into Docker Engine and works. Mirantis has committed to supporting Swarm through at least 2030, but Docker Inc. is not actively developing it. For **new** work, Kubernetes is the default choice. You still meet Swarm in older estates and exams.

Security notes: protect the manager nodes (they hold the cluster state and secrets), keep the control-plane ports (2377, 7946, 4789) off untrusted networks, enable overlay encryption where needed, rotate join tokens.

## 5. Kubernetes

Kubernetes (K8s) is the industry standard orchestrator: a **control plane** (API server, etcd, scheduler, controllers) and **nodes** (kubelet, a container runtime such as containerd or CRI-O). You declare desired state (Deployments, Services, ConfigMaps, Secrets) and controllers make it true. It adds self-healing, autoscaling, RBAC, network policies and an ecosystem (Helm, operators).

It also adds attack surface: the API server, kubelet, etcd, RBAC mistakes, Secrets stored only base64-encoded, privileged pods, hostPath mounts. The full treatment is in [csse ch4](../../csse-course/ch4-attacking-kubernetes-cluster-supply-chain/README.md) and the Kubernetes lessons in the [06 AI DevSecOps module](../../06-ai-devsecops/kubernetes/README.md).

| | CLI/API scripts | Compose | Swarm | Kubernetes |
|---|---|---|---|---|
| Hosts | 1 (or scripted many) | 1 | many | many |
| Self-healing, scaling | DIY | restart policies | yes | yes |
| Learning curve | low | low | medium | high |
| Ecosystem | none | small | small, static | very large |
| Status | always | current | maintained, little new development | default for new work |

## 6. Docker alternatives

### 6.1 Podman

Podman (Red Hat) is a **daemonless** container engine with a Docker-compatible CLI (`alias docker=podman` mostly works). Each container is a child of the Podman process (via `conmon`), not of a root daemon. It is **rootless-friendly**: a normal user can run containers using user namespaces, so a container escape lands as that user, not root. It supports pods (groups of containers sharing namespaces like Kubernetes pods), `podman generate kube`, systemd integration and `podman compose` (hedged). Buildah and Skopeo are companion tools for building and copying images.

Security view: no always-on root daemon and no socket that equals root. Rootless has trade-offs (low ports, some networking and storage limits). Verify feature details at podman.io.

### 6.2 CRI-O

CRI-O is a lightweight runtime made **only for Kubernetes**. It implements the Kubernetes **Container Runtime Interface (CRI)**, pulls OCI images and uses an OCI runtime (runc or crun) to run them. It has no build or developer CLI. It is the default in some distributions (for example OpenShift). It is a CNCF project (verify the current level at cncf.io).

### 6.3 Others to recognise

containerd (used directly by Kubernetes and Docker), runc/crun (low-level runtimes), gVisor and Kata (sandboxed runtimes), LXC/LXD and Incus (system containers), Nerdctl (Docker-like CLI for containerd). Verify status of each at source.

## 7. Defend

- Prefer declarative, reviewed files (Compose or manifests in Git) over hand-typed commands.
- Run the Compose review in CI; fail on privileged mode and `docker.sock`.
- Use secrets features, not env vars; pin images by digest.
- If you have a choice: rootless Podman or rootless Docker for single hosts, Kubernetes with Pod Security standards for clusters.

## 8. Hands-on

[docker-compose](labs/docker-compose/README.md) and [docker-sdk](labs/docker-sdk/README.md). Real tools: [real-tools/podman-and-cri-o.md](real-tools/podman-and-cri-o.md).

## 9. Scenario

A team wants to move from Compose on one VM to production. Compare Swarm and Kubernetes for them in five bullets, hedging the Swarm status, and name two security controls you would require on day one.

## 10. References

- Docker docs: Compose file reference, Swarm mode (note the maintenance status); Kubernetes docs; Podman and CRI-O project sites.
- NIST SP 800-190 and the CIS Docker and Kubernetes Benchmarks.
- Repo: [csse ch4](../../csse-course/ch4-attacking-kubernetes-cluster-supply-chain/README.md), [06 Kubernetes](../../06-ai-devsecops/kubernetes/README.md).
