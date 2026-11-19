# Lab: Unsecured docker daemon

**Course exercise:** "Unsecured docker daemon". Lessons: [03 section 4](../../03-attacking-the-container-supply-chain.md#4-attacking-through-container-misconfigurations), [04 section 5](../../04-securing-container-applications.md#5-securing-the-docker-daemon).

**Time:** 45 minutes. **Safety:** no network. `FakeDaemon` answers `GET /version` from configuration only. Do not scan or connect to Docker APIs you do not own.

## What it audits

[daemon_audit.py](daemon_audit.py) checks `daemon.json` against a subset of CIS Docker Benchmark ideas (IDs are this lab's `DD-xxx`; look up the matching CIS numbers in your benchmark version):

| ID | Idea |
|---|---|
| DD-001 | TCP API without TLS client verification (critical) |
| DD-002, DD-003 | plaintext port 2375, bound to all interfaces |
| DD-004 | `icc` allowed on the default bridge |
| DD-005 | no user-namespace remap or rootless |
| DD-006 to DD-012 | no-new-privileges, live-restore, insecure registries, logging, userland proxy, experimental, seccomp disabled |
| DD-013, DD-014 | `docker.sock` mode and group |
| DD-020 | Docker API listening in `ss -ltnp` output |

## Steps

```text
.venv/Scripts/python csse-course/ch3-attacking-container-supply-chain/labs/unsecured-docker-daemon/demo.py
.venv/Scripts/python -m pytest csse-course/ch3-attacking-container-supply-chain/labs/unsecured-docker-daemon -v
```

1. Audit [daemon_insecure.json](fixtures/daemon_insecure.json): 11 findings. Fix them one at a time until it matches [daemon_secure.json](fixtures/daemon_secure.json).
2. Compare the two `FakeDaemon` answers: open API versus a handshake that needs a client certificate.
3. Read [listeners.txt](fixtures/listeners.txt): which line is the real emergency?
4. Why is `0.0.0.0:2376` with TLS still a risk? (A leaked client certificate is a root credential; prefer private binding, short-lived certs, or SSH.)

## Expected output (real run, abridged)

```text
== daemon_insecure.json: 11 finding(s) ==
  [CRITICAL] DD-001 daemon API on ['tcp://0.0.0.0:2375'] without TLS client verification: anyone who can reach the port controls the host
  [HIGH    ] DD-002 ...
  anonymous GET /version -> (200, 'Docker version 27.x (SIMULATED): API answers anyone, including POST /containers/create')
== daemon_secure.json: 0 finding(s) ==
  anonymous GET /version -> (0, 'TLS handshake failed: client certificate required')
== listening sockets ==
  [CRITICAL] DD-020 Docker API listening on 0.0.0.0:2375
```

## Real-tool twin

`docker info`, `docker-bench-security`, `ss -ltnp`, CIS-CAT. See [real-tools/docker.md](../../real-tools/docker.md).
