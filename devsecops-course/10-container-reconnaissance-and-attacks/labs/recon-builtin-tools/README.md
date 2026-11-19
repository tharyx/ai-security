# Lab: Using built-in Docker tools for reconnaissance

**Course exercise:** "Using Built-in Docker Tools for Reconnaissance". Lessons: [01 recon, native tools](../../01-container-reconnaissance.md#8-attack-surface-analysis-with-native-tools).

**Time:** 60 minutes. **Safety:** Fixtures that mirror `docker ps/inspect/info/network ls/volume ls` JSON. No Docker is queried.

## What it models

Turns five JSON documents ([docker_ps](fixtures/docker_ps.json), [inspect](fixtures/inspect.json), [info](fixtures/info.json), [network_ls](fixtures/network_ls.json), [volume_ls](fixtures/volume_ls.json)) into an **inventory** (image, user, ports, networks, mounts, secret env names) and a per-container **risk score** with reasons, plus host-level findings (rootful daemon, insecure registry, flat networks, unused volumes). Also see [csse docker-commands](../../../../csse-course/ch3-attacking-container-supply-chain/labs/docker-commands/README.md).

## Steps

```text
.venv/Scripts/python devsecops-course/10-container-reconnaissance-and-attacks/labs/recon-builtin-tools/demo.py
.venv/Scripts/python -m pytest devsecops-course/10-container-reconnaissance-and-attacks/labs/recon-builtin-tools -v
```

1. Run the demo and read the ranking. Why does `ops-agent` come first?
2. Remove `docker.sock` from `shop-api` and watch its score drop.
3. Add a new container to `inspect.json` and see it appear.
4. On a lab machine run `docker inspect $(docker ps -q)` and feed the JSON in.

## Expected output (real run)

```text
container  image            user           score  level
ops-agent  ops/agent:2.0    root             120  CRITICAL
shop-api   shop/api:latest  root(default)     87  CRITICAL
shop-web   nginx:1.27       101                5  LOW
old-batch  alpine:3.20      1000               5  LOW
shop-db    postgres:16.4    999                0  LOW

Why ops-agent scores 120: privileged; sensitive bind mount /; host network; host PID namespace; runs as root; no memory limit; no pids limit

Host-level findings:
 - daemon runs rootful without user namespace remapping
 - live-restore disabled: daemon restart stops all containers
 - insecure registry configured: registry.internal:5000
 - network 'backend': inter-container communication on with 2 containers
 - 2 unused volumes may hold old data: 9f8e7d6c5b4a, cache-old
```

## Think about it

Recon is a questionnaire answered by `inspect`: who (User), what rights (Privileged, CapAdd), what it can touch (Binds, Mounts), who can touch it (Ports, Networks), what it knows (Env). Which three fields find 80 percent of problems? (Privileged/CapAdd, Binds, Env.)

## Run the real tool

`docker ps -a --format '{{json .}}'`, `docker inspect`, `docker info --format '{{json .}}'`, `docker network ls`, `docker volume ls`, `docker system df`.

> Hedged: real tools and flags change between versions. Verify at the source. Tests in this repo never need Docker.

## Tests

`7` tests in `test_dso_ch10_*.py`: `.venv/Scripts/python -m pytest devsecops-course/10-container-reconnaissance-and-attacks/labs/recon-builtin-tools`.
