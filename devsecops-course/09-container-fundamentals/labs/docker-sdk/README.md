# Lab: Working with Docker SDK

**Course exercise:** "Working With Docker SDK". Lessons: [02 Docker CLI, Engine API and SDKs](../../02-docker-architecture-and-runtime.md#3-the-docker-engine-daemon-and-api).

**Time:** 45 minutes. **Safety:** An offline mock client. The real `docker` package is NOT imported or needed.

## What it models

A **mock client** with the same method names as the real Docker SDK for Python: `client.ping()`, `client.version()`, `client.info()`, `client.containers.list/run/get`, `container.stop/remove/logs`, `client.images.pull/list/get`. It is driven by [fixtures/daemon-state.json](fixtures/daemon-state.json). One function, `audit(client)`, works on both the mock and the real client.

## Steps

```text
.venv/Scripts/python devsecops-course/09-container-fundamentals/labs/docker-sdk/demo.py
.venv/Scripts/python -m pytest devsecops-course/09-container-fundamentals/labs/docker-sdk -v
```

1. Run the demo and read the audit findings.
2. Pull an image that is not in the fixture registry and handle `ImageNotFound`.
3. Write your own `audit` rule (for example: container without a memory limit).
4. On a lab machine with Docker, point the same `audit()` at the real client (see below).

## Expected output (real run)

```text
ping: True | server: 27.3.1-fixture
running: ['web', 'agent']
all    : [('web', 'running'), ('agent', 'running'), ('old-job', 'exited')]
pulled : ['nginx:1.27'] sha256:bbbb00000000
pull failed (as expected): pull access denied / not found: evil/miner:1
run    : demo running | logs: started echo hi
after remove: ['web', 'agent', 'old-job']

audit(client):
  - agent: privileged container
  - agent: mounts docker.sock (/var/run/docker.sock:/var/run/docker.sock:rw)
  - agent: runs as image default user (probably root)
  - agent: unpinned image tools/agent:latest
```

## Think about it

The SDK talks to the same API as the CLI, over the same socket. So a script with SDK access has the same power as `docker` with root. How would you protect a CI job that uses it? (Rootless daemon, a scoped socket proxy, or a remote builder.)

## Run the real tool

Hedged: `pip install docker`, then `import docker; client = docker.from_env(); client.ping(); [c.name for c in client.containers.list()]`. `audit(client)` in [fake_docker.py](fake_docker.py) only uses `containers.list(all=True)`, `c.attrs`, `c.name` and `c.image`; in the real SDK `c.image` is an Image object, so use `c.image.tags` or `c.attrs['Config']['Image']` (verify against the SDK docs for your version).

> Hedged: real tools and flags change between versions. Verify at the source. Tests in this repo never need Docker.

## Tests

`9` tests in `test_dso_ch09_*.py`: `.venv/Scripts/python -m pytest devsecops-course/09-container-fundamentals/labs/docker-sdk`.
