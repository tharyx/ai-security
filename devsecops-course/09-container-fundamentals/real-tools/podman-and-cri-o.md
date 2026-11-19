# Real tool guide: Podman and CRI-O (chapter 9, Docker alternatives)

> **Hedged guide.** Not run by the repo author for this guide. Verify at podman.io, cri-o.io and your distribution's documentation. Nothing in this repo's tests needs either tool.

## Podman: daemonless and rootless

| Idea | What to know |
|---|---|
| Daemonless | There is no long-running root daemon. The `podman` command forks the container itself (with a small monitor called `conmon`). No `docker.sock` equivalent that equals root (a rootless user socket exists only if you start it: `podman system service`). |
| Rootless | A normal user can run containers using user namespaces and `slirp4netns` or `pasta` networking. A container escape lands as that user. Needs `/etc/subuid` and `/etc/subgid` ranges. |
| Docker-compatible CLI | `podman run`, `ps`, `images`, `build`, `push` mostly mirror Docker. `alias docker=podman` works for many scripts. |
| Pods | `podman pod create` groups containers that share namespaces, like a Kubernetes pod. `podman generate kube` / `podman kube play` move to and from Kubernetes YAML (verify the current command names). |
| Compose | `podman compose` (wrapper) or `docker-compose` against the Podman socket: check compatibility per feature. |
| Systemd | Quadlet files let systemd run containers as services (hedged: newer versions). |

### Try it (lab VM)

```text
podman run --rm -it docker.io/library/alpine:3.20 id
podman ps -a
podman unshare cat /proc/self/uid_map       # see the rootless UID mapping
podman info --format '{{.Host.Security.Rootless}}'
```

### Trade-offs to remember

Rootless limits: binding ports below 1024 needs a sysctl, some storage drivers and network features differ, and `--privileged` in rootless gives only the user's own privileges (a good thing). Compare each security claim with the [privilege-escalation lab](../../10-container-reconnaissance-and-attacks/labs/privilege-escalation-and-misconfig/README.md): a rootless engine turns "docker group = root" into LOW.

## CRI-O: the Kubernetes-only runtime

- Implements the Kubernetes **CRI**. The kubelet talks to CRI-O, which pulls OCI images and runs them with an OCI runtime (runc or crun). No build tool, no developer CLI.
- Inspect on a node with `crictl` (generic CRI client): `crictl ps`, `crictl pods`, `crictl images`, `crictl inspect <id>`. It works for containerd too.
- Why you care: after dockershim was removed (Kubernetes 1.24) clusters use containerd or CRI-O, so the Docker daemon is usually not on the node. Do not assume `docker ps` works on a Kubernetes node.

## Which to pick (short)

| Situation | Choice |
|---|---|
| Developer laptop | Docker Desktop, or Podman Desktop |
| Single Linux server, security-minded | Rootless Podman or rootless Docker |
| Kubernetes cluster | containerd (most common) or CRI-O (OpenShift and some distributions) |
| Strong isolation needed | Add gVisor or Kata as a runtime class (chapter 11) |

## Related

[Lesson 04](../04-orchestration-and-alternatives.md#6-docker-alternatives) and [csse ch4](../../../csse-course/ch4-attacking-kubernetes-cluster-supply-chain/README.md).
