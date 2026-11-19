# Lab: Docker networking

**Course exercise:** "Docker Networking". Lessons: [02 Docker architecture, networking](../../02-docker-architecture-and-runtime.md#6-docker-networking), [CH10 recon](../../../10-container-reconnaissance-and-attacks/01-container-reconnaissance.md).

**Time:** 45 minutes. **Safety:** A topology fixture ([fixtures/topology.json](fixtures/topology.json)) and a calculator. No packets are sent.

## What it models

`bridge` (default and user-defined), `host`, `none` and `overlay` networks; whether container A can reach container B (and by name or by IP); whether a host-network container can reach host localhost services; and which published ports (`-p`) are exposed on every interface or only on loopback.

## Steps

```text
.venv/Scripts/python devsecops-course/09-container-fundamentals/labs/docker-networking/demo.py
.venv/Scripts/python -m pytest devsecops-course/09-container-fundamentals/labs/docker-networking -v
```

1. Run the demo and read each reachability line. Note why `web` cannot reach `db` (different networks) but `api` can reach both.
2. Change `db` in the fixture to also join `frontend`. What changed in the findings?
3. Change `-p 0.0.0.0:8080:80` to `127.0.0.1:8080:80`. Does the exposure finding disappear?
4. Add a third container on the default `bridge` and watch the flat-network finding grow.

## Expected output (real run)

```text
      web -> api      :3000  YES same user-defined bridge 'frontend' (reach by name 'api')
      web -> db       :5432  NO  no common network (['frontend'] vs ['backend']): isolated
      api -> db       :5432  YES same user-defined bridge 'backend' (reach by name 'db')
  legacy1 -> legacy2  :9000  YES same default bridge (reach by IP only; no name resolution)
 worker-a -> worker-b :7001  YES same overlay 'mesh' (even across nodes)
    batch -> web      :80    NO  batch is on network 'none': loopback only
host-network monitor can reach host localhost ports: [5432, 2375]

Exposure:
  web      0.0.0.0:8080->80       ALL INTERFACES
  api      127.0.0.1:3000->3000   loopback only
  monitor  host:9100              ALL INTERFACES (host network)

Findings:
 - web listens on 0.0.0.0:8080->80 on every interface: bind to 127.0.0.1 or firewall it
 - monitor listens on host:9100 on every interface: bind to 127.0.0.1 or firewall it
 - legacy1, legacy2 share the default bridge (flat network, no DNS isolation): use user-defined networks
```

## Think about it

DBA analogy: a user-defined network is a separate listener/subnet with its own service names; the default bridge is a shared flat LAN. Which one would you put a database on? (A user-defined backend network with no published port.)

## Run the real tool

`docker network ls`, `docker network inspect backend`, `docker run --network none alpine ip addr`, `ss -ltnp` on the host to see published ports. Overlay needs Swarm mode or Kubernetes networking.

> Hedged: real tools and flags change between versions. Verify at the source. Tests in this repo never need Docker.

## Tests

`9` tests in `test_dso_ch09_*.py`: `.venv/Scripts/python -m pytest devsecops-course/09-container-fundamentals/labs/docker-networking`.
