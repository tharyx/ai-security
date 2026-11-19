# Real tool guide: Docker (and friends) for the chapter 3 labs

> **Hedged guide.** Not run by the repo author for this guide. Commands and flags change between versions: check `docker --help` and docs.docker.com. Tests in this repo never need Docker.

## Safe setup

- Use a **disposable VM** (course lab VM, or a Linux VM on your laptop). Do not run suspicious images on your daily machine.
- Docker Desktop (Windows or macOS) runs Linux containers in a small VM. On Linux, prefer **rootless Docker** or Podman for experiments.
- No internet-exposed daemon. Keep the API on the Unix socket.

## Commands that map to the labs

| Lab | Real commands |
|---|---|
| docker-commands | `docker run`, `docker ps`, `docker inspect`, `docker logs`, `docker exec` |
| container-snapshots | `docker commit c snap:1`; `docker save -o snap.tar snap:1`; `tar tf snap.tar`; `docker diff c`; `docker history --no-trunc snap:1` |
| malicious-image | `docker image inspect img`; `docker save img \| tar -xO manifest.json`; `skopeo inspect docker://img`; scan with Trivy ([trivy.md](trivy.md)) before running anything |
| backdoor-docker-image | `docker pull img@sha256:<digest>`; `crane digest img:tag`; `docker image ls --digests` |
| attack-docker-registry | `docker run -d -p 127.0.0.1:5000:5000 registry:2` (a local, empty registry for practice); `curl http://127.0.0.1:5000/v2/_catalog`. Add basic auth or token auth and TLS to see 401 and TLS errors. Use **Harbor** for immutable tags, robot accounts and scanning |
| exploit-containerized-app | Only in the course lab: start a container with a risky flag and observe it with `docker inspect`. Do not mount the socket of a machine you care about |
| unsecured-docker-daemon | `docker info`; read `/etc/docker/daemon.json`; `ss -ltnp \| grep 2375`; run **docker-bench-security** (CIS checks) |
| minimize-misconfigurations | `hadolint Dockerfile`; `docker run --read-only --cap-drop ALL ...`; `--security-opt seccomp=profile.json`; `--security-opt apparmor=web-app` |
| secure-mini-image | `docker build`, `docker images`, `dive image`, `syft image`, `trivy image` |
| typosquatting-image | Docker Hub badges; `docker pull` from your internal mirror only |

## Debugging a distroless container

`docker run --rm -it --pid container:<id> --net container:<id> busybox sh` attaches a throwaway shell that shares namespaces (Docker CLI feature; verify flags). In Kubernetes use `kubectl debug`.

## Useful related tools

Podman, Buildah, BuildKit, Kaniko, skopeo, crane, oras, Dive, docker-bench-security, gVisor (`runsc`), Kata Containers.

## Do not

- Do not run `docker run --privileged` on your laptop to "see what happens".
- Do not paste real secrets into `-e` flags during practice.
- Do not scan or connect to registries and daemons you do not own.
