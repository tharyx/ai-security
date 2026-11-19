# Lab: Learn Docker Compose

**Course exercise:** "Learn Docker Compose". Lessons: [04 managing many containers: Compose](../../04-orchestration-and-alternatives.md#3-docker-compose).

**Time:** 45 minutes. **Safety:** Parses YAML text with PyYAML. Nothing is started.

## What it models

A **Compose file parser**, the **dependency graph** from `depends_on` (list form and condition form), a **start order** by topological sort with **cycle detection**, and a **security review** (privileged, docker.sock, host network, `cap_add`, wide-open ports, secrets in the file, unpinned images, missing limits and healthchecks). Fixture: [compose.yml](fixtures/compose.yml).

## Steps

```text
.venv/Scripts/python devsecops-course/09-container-fundamentals/labs/docker-compose/demo.py
.venv/Scripts/python -m pytest devsecops-course/09-container-fundamentals/labs/docker-compose -v
```

1. Run the demo and draw the dependency graph.
2. Add `db` to `depends_on` of `cache` and `cache` to `db` to create a cycle: read the error.
3. Remove the healthcheck from `api` and see the "will never start" warning on `web`.
4. Fix every CRITICAL and HIGH finding in the fixture.

## Expected output (real run)

```text
Dependency graph:
  web    depends on ['api']
  api    depends on ['cache', 'db']
  db     depends on []
  cache  depends on []
  debug  depends on []
Start order: cache -> db -> api -> debug -> web

Security review:
  [CRITICAL] cache  privileged: true gives the container almost all host capabilities and devices
  [CRITICAL] cache  mounts docker.sock: control of the Docker daemon equals root on the host
  [HIGH    ] api    secret 'DB_PASSWORD' written in the compose file: use secrets: or an env file kept out o
  [HIGH    ] cache  network_mode: host removes network isolation
  [HIGH    ] debug  cap_add SYS_ADMIN
  [HIGH    ] web    image 'nginx:latest' is not pinned
  [MEDIUM  ] web    port 80:80 is published on all interfaces: bind 127.0.0.1 or put a proxy in front
  ... plus 10 LOW items
```

## Think about it

`depends_on` only orders start-up; it does not make a service ready unless you use `condition: service_healthy`. Why is that also a security topic? (A service that starts before its auth or policy sidecar may run unprotected.)

## Run the real tool

`docker compose config`, `docker compose up -d`, `docker compose ps`. Compose v2 is the `docker compose` plugin; `docker-compose` v1 is legacy (verify at source).

> Hedged: real tools and flags change between versions. Verify at the source. Tests in this repo never need Docker.

## Tests

`9` tests in `test_dso_ch09_*.py`: `.venv/Scripts/python -m pytest devsecops-course/09-container-fundamentals/labs/docker-compose`.
