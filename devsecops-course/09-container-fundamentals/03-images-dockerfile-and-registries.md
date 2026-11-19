# Lesson 03: Images, Layers, Dockerfiles and Registries

> **Chapter:** 9 · Container Fundamentals · **Time:** ~4 hours
> **You will:** explain image layers, build an image from a Dockerfile (and why the order of lines matters), write a safer Dockerfile, use a registry with tags and digests, and run a container.

| | |
|---|---|
| **Prerequisites** | [Lesson 02](02-docker-architecture-and-runtime.md) |
| **Labs** | [manage-data](labs/manage-data/README.md) · [dockerfile-build](labs/dockerfile-build/README.md) · [writing-dockerfile](labs/writing-dockerfile/README.md) · [container-registry](labs/container-registry/README.md) |
| **Syllabus lines** | Docker images and image layers · Build Container images using Dockerfile · Docker image repository · Running a container |
| **Reuse** | Repo [06 Docker lesson](../../06-ai-devsecops/docker/README.md) (layers, Dockerfile linter); csse [lesson 04](../../csse-course/ch3-attacking-container-supply-chain/04-securing-container-applications.md) (distroless, multi-stage) |

## 1. Why it matters

The image is the part of the container you did not write yourself. It is the **supply chain**. How it is built, where it is stored and how you name it decide whether you run what you think you run.

## 2. Images and layers

An image is three things (OCI image spec):

- **Layers:** tar files of file changes, stacked. Each is identified by a sha256 digest.
- **Config JSON:** default user, environment, entrypoint, exposed ports, history.
- **Manifest:** a list of the config and layer digests. The digest of the manifest identifies the image.

A running container adds one thin **writable layer** on top. When the container is removed, that layer is gone. Data you care about belongs in a **volume** ([manage-data lab](labs/manage-data/README.md)).

```text
  container (writable layer)        <- lost on `docker rm`
  layer 4: COPY app.py
  layer 3: RUN pip install ...
  layer 2: RUN apt-get install ...
  layer 1: base image (debian-slim)  <- shared by many images, stored once
```

Storage is done by a **union file system** (`overlay2` on most hosts): lower layers are read-only, a change in a file copies it up into the writable layer (copy-on-write).

**Layers never forget.** If layer 2 contains a secret and layer 3 runs `rm secret`, layer 2 still holds it. Anyone who pulls the image can extract it. DBA analogy: deleting a row in a later transaction does not erase an earlier backup.

## 3. Building images with a Dockerfile

A **Dockerfile** is a text recipe. Main instructions:

| Instruction | Does | Layer? |
|---|---|---|
| `FROM` | Start from a base image (or `scratch`) | base |
| `RUN` | Run a command at build time | **yes** |
| `COPY` / `ADD` | Copy files in (`ADD` also fetches URLs and unpacks tarballs: prefer `COPY`) | **yes** |
| `ENV`, `ARG` | Set environment, build arguments | metadata |
| `WORKDIR`, `USER` | Working directory, user | metadata |
| `EXPOSE` | Documents a port; does not publish it | metadata |
| `CMD`, `ENTRYPOINT` | What runs at start (use exec form `["a","b"]`) | metadata |
| `HEALTHCHECK` | How to test health | metadata |

**The build cache.** Docker reuses a layer if the instruction, its parent and any copied files are unchanged. As soon as one layer changes, **every layer after it is rebuilt**. So put things that change rarely (dependency install) before things that change often (your source).

```dockerfile
# good order
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY app.py /app/app.py
```

**Multi-stage builds.** Build with a fat image, ship a thin one. Compilers, source and build secrets stay in the discarded stages:

```dockerfile
FROM golang:1.23 AS build
RUN go build -o /out/app ./...
FROM gcr.io/distroless/static
COPY --from=build /out/app /app
USER 65532
ENTRYPOINT ["/app"]
```

Do the [dockerfile-build lab](labs/dockerfile-build/README.md): a parser, a layer model, a cache explainer and a multi-stage comparison. BuildKit (the default builder in current Docker) adds parallel stages, cache mounts and **secret mounts** (`RUN --mount=type=secret`) so secrets never land in a layer.

## 4. Writing a good Dockerfile

| Rule | Why |
|---|---|
| Pin the base by **digest** (`FROM python:3.12-slim@sha256:...`), not `latest` | Tags move; digests do not |
| Use a **small base** (slim, alpine, distroless) | Fewer packages, fewer CVEs |
| **Non-root `USER`** with a numeric UID | Limits damage; works with Kubernetes policies |
| No secrets in `ENV`, `ARG` or `COPY` | They end up in history and layers |
| No `curl \| sh`, no `ADD` from URLs | Unverified code at build time |
| `apt-get update && apt-get install --no-install-recommends` in **one** `RUN`, clean up in the same layer | Smaller layers, no stale cache |
| Exec-form `CMD`/`ENTRYPOINT` | Signals reach the app |
| `HEALTHCHECK` | Orchestrators can detect hangs |
| `.dockerignore` | Keeps `.git`, `.env`, keys out of the build context |

Run the [writing-dockerfile lab](labs/writing-dockerfile/README.md) to lint a bad file and fix it. The repo's [Dockerfile linter](../../06-ai-devsecops/docker/README.md) goes further; the real tool is **Hadolint** (and **Dockle** for built images). Static analysis and distroless are deepened in chapter 11.

## 5. Image repositories and registries

A **registry** stores images and serves them over the OCI Distribution (Registry v2) HTTP API. A **repository** is a named collection of an image's versions: `team/api`. A **reference** looks like:

```text
registry.example.com:5000 / team/api : 1.4 @sha256:ab12...
 registry (host:port)       repository  tag   digest
```

Docker fills in defaults: `nginx` means `docker.io/library/nginx:latest`.

- A **tag** is a movable label. Whoever can push can move it.
- A **digest** is the sha256 of the manifest. It cannot move. **Deploy by digest.**
- **Public vs private:** Docker Hub, GHCR, Quay are public services (with private repos). Private registries: Harbor, GitLab Registry, cloud registries (ECR, ACR, GAR), or the simple `registry:2` image.
- Operations: `docker login`, `docker tag`, `docker push`, `docker pull`.

> **Content trust: outdated to current.** Docker Content Trust (Notary v1) is **retired**. It was announced on 29 Jul 2025 and the notary.docker.io service shuts down on **8 Dec 2026** (verify at source). Use **cosign** or **Notation** to sign images. The details are in the [csse image-signing lesson](../../csse-course/ch3-attacking-container-supply-chain/05-technologies-for-securing-containerized-applications.md#4-image-signing-and-content-trust) and chapter 11.

Do the [container-registry lab](labs/container-registry/README.md): a local in-process registry showing the tag moving and the digest staying put. The attack side is in [CH10 registry attacks](../10-container-reconnaissance-and-attacks/02-container-attack-matrix-image-and-registry-attacks.md#5-registry-based-attacks).

## 6. Data: volumes, bind mounts, tmpfs

| Type | Where | Survives `rm`? | Risk |
|---|---|---|---|
| Writable layer | Inside the container | No | Lost data |
| **Volume** | Managed by Docker | Yes | Low; the right choice for databases |
| **Bind mount** | A host path | Yes | Container touches the host file system |
| **tmpfs** | RAM | No (gone at stop) | Good for secrets in memory; uses RAM |

Never bind-mount `/`, `/etc` or `docker.sock` into an app container. Use `:ro` when you must mount host files. See [manage-data](labs/manage-data/README.md).

## 7. Running a container

`docker run` = pull if needed, **create**, **start**. A defensive default:

```text
docker run -d --name web \
  --user 10001:10001 --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges \
  --memory 256m --pids-limit 200 --cpus 0.5 \
  -p 127.0.0.1:8080:8080 \
  registry.example.com/team/web@sha256:<digest>
```

Each flag matches a fact from lesson 01: non-root, read-only file system, fewer capabilities, no privilege gain, resource limits, narrow port, pinned image. Review a command with the [csse run-flag parser](../../csse-course/ch3-attacking-container-supply-chain/labs/docker-commands/README.md).

## 8. Hands-on

[manage-data](labs/manage-data/README.md), [dockerfile-build](labs/dockerfile-build/README.md), [writing-dockerfile](labs/writing-dockerfile/README.md), [container-registry](labs/container-registry/README.md). Real commands are in [real-tools/docker.md](real-tools/docker.md).

## 9. Scenario

Your pipeline pushes `shop/web:latest` and production pulls `latest`. Someone with a stolen CI token pushes a new `latest`. Describe what production runs next and give three fixes (digest pins, signing with verification at admission, immutable tags).

## 10. References

- OCI Image and Distribution Specifications; Docker docs on storage drivers, BuildKit, Dockerfile reference.
- Hadolint and Dockle project docs; Docker's notice on retiring Content Trust (verify at docs.docker.com).
- Repo: [06 Docker](../../06-ai-devsecops/docker/README.md), csse [lesson 03](../../csse-course/ch3-attacking-container-supply-chain/03-attacking-the-container-supply-chain.md).
