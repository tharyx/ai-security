# Lab: How to use a container registry

**Course exercise:** "How To Use Container Registry". Lessons: [03 repositories and registries](../../03-images-dockerfile-and-registries.md#5-image-repositories-and-registries).

**Time:** 45 minutes. **Safety:** An in-process registry object. No sockets.

## What it models

A local **registry simulator**: push blobs and manifests, tags as movable pointers, digests as content hashes, `pull` by tag or by digest, `tag` (retag without copying), delete by digest, catalog and tag listing, plus Docker's **reference normalisation** (`nginx` becomes `docker.io/library/nginx:latest`).

## Steps

```text
.venv/Scripts/python devsecops-course/09-container-fundamentals/labs/container-registry/demo.py
.venv/Scripts/python -m pytest devsecops-course/09-container-fundamentals/labs/container-registry -v
```

1. Run the demo and watch the tag move while the digest stays fixed.
2. Pull by digest after somebody re-pushes the tag. Which image do you get?
3. Tamper with a blob in the simulator and see `verified` become False.
4. Compare with the attack side: [registry-attacks](../../../10-container-reconnaissance-and-attacks/labs/registry-attacks/README.md) and the [csse registry lab](../../../../csse-course/ch3-attacking-container-supply-chain/labs/attack-docker-registry/README.md).

## Expected output (real run)

```text
nginx                                         -> docker.io/library/nginx:latest
myuser/app:2.1                                -> docker.io/myuser/app:2.1
localhost:5000/team/api:dev                   -> localhost:5000/team/api:dev
ghcr.io/org/tool@sha256:abababababababababababababababababababababababababababababababab -> ghcr.io/org/tool@sha256:abab

push shop/web:1.0 and tag latest -> sha256:f699a23338b1 | tags: ['1.0', 'latest']
someone re-pushes tag 1.0 with an extra layer -> sha256:56eb5e1fb413
pull by TAG    resolves to: sha256:56eb5e1fb413 (moved!)
pull by DIGEST resolves to: sha256:f699a23338b1 (the original, immutable)
untagged but still pullable by digest: []

registry log:
  push shop/web:1.0 -> sha256:f699a23338b1
  tag shop/web:latest -> same digest as 1.0
  push shop/web:1.0 -> sha256:56eb5e1fb413
  pull registry.example/shop/web:1.0 -> sha256:56eb5e1fb413
  pull shop/web@sha256:f699a23338b145387b34720aacb867a872fc219855404690ebf3432030a65e52 -> sha256:f699a23338b1
```

## Think about it

DBA analogy: a tag is a synonym, a digest is the ROWID of the exact content. Deployments should name the ROWID.

## Run the real tool

`docker run -d -p 127.0.0.1:5000:5000 registry:2`, `docker tag app localhost:5000/app:1`, `docker push`, `curl http://127.0.0.1:5000/v2/_catalog`, `crane digest`, `skopeo inspect`. See [real-tools/docker.md](../../real-tools/docker.md).

> Hedged: real tools and flags change between versions. Verify at the source. Tests in this repo never need Docker.

## Tests

`9` tests in `test_dso_ch09_*.py`: `.venv/Scripts/python -m pytest devsecops-course/09-container-fundamentals/labs/container-registry`.
