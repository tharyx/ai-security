# Lab: Docker host (daemon) and kernel attacks

**Course exercise:** "Docker host (Daemon) / kernel attacks: unauthenticated API, insecure endpoint, network segregation, DoS, kernel exploits". Lessons: [03 daemon and kernel attacks](../../03-container-host-daemon-and-kernel-attacks.md#2-unauthenticated-docker-api-and-insecure-endpoint).

**Time:** 60 minutes. **Safety:** Config analysis and arithmetic. The fork-bomb part is a **number model** and forks nothing. Kernel vulnerability data is FIXTURE data. See also [csse unsecured-docker-daemon](../../../../csse-course/ch3-attacking-container-supply-chain/labs/unsecured-docker-daemon/README.md) and [remote-docker-api-scan](../remote-docker-api-scan/README.md).

## What it models

(1) `daemon.json` audit: **TCP endpoint without TLS**, no user remapping, `icc` on. (2) **Flat network** exposure: reachable pairs on the default bridge. (3) **DoS**: containers without memory, pids or cpu limits, and a fork-bomb *concept* (population doubling until the container pids limit or the host `pid_max`). (4) **Kernel risk**: the host kernel version is matched against a fixture CVE list, because every container shares that kernel.

## Steps

```text
.venv/Scripts/python devsecops-course/10-container-reconnaissance-and-attacks/labs/daemon-and-kernel-attacks/demo.py
.venv/Scripts/python -m pytest devsecops-course/10-container-reconnaissance-and-attacks/labs/daemon-and-kernel-attacks -v
```

1. Run the demo and compare `daemon-bad.json` with `daemon-good.json`.
2. Set `--pids-limit 200` in the model: what happens to the host impact line?
3. Try three kernel versions with `kernel_risk()`. Which fixture flaw needs user namespaces?
4. Write the `daemon.json` fix for the bad one.

## Expected output (real run)

```text
== daemon-bad.json ==
  [CRITICAL] tcp://0.0.0.0:2375: TCP endpoint with NO TLS client verification = unauthenticated root API reachable fro
  [MEDIUM  ] no userns-remap: root in a container is root (UID 0) on the host
  [MEDIUM  ] icc enabled on the default bridge: every container can talk to every other
  [LOW     ] no-new-privileges not set by default
  [LOW     ] live-restore off: a daemon restart kills all containers
  [LOW     ] userland-proxy on (default): extra attack surface and slower; consider disabling
== daemon-good.json ==
  [OK      ] no findings

Flat network:
  - network 'bridge' is flat: 3 containers (web, api, db) = 3 reachable pairs; one compromised container can scan 

DoS exposure (missing limits):
  - api: no memory/pids/cpus limit -> can exhaust the host's memory, pids, cpus
  - db: no pids limit -> can exhaust the host's pids

Fork-bomb concept (arithmetic only):
  pids-limit=None  ->  32768 processes after 15 generations, stopped by HOST pid_max (host-wide outage); severe: new processes fail everywhere
  pids-limit=200   ->    200 processes after 8 generations, stopped by container pids limit; none: other containers unaffected

Kernel risk by host kernel version (fixture CVE list):
  5.4.0-150        ['FIXTURE-K-001', 'FIXTURE-K-003']
  5.15.0-fixture   ['FIXTURE-K-001', 'FIXTURE-K-002', 'FIXTURE-K-003']
  6.8.12           none in the fixture list
```

## Think about it

A VM has its own kernel, so a kernel bug stops at the VM. A container shares the host kernel, so the same bug can cross every container on the host. That is why patching the host kernel is a container-security task.

## Run the real tool

`docker info`, `uname -r`, `cat /etc/docker/daemon.json`, `docker run --memory 256m --pids-limit 200 --cpus 0.5`, distro security trackers for kernel CVEs (verify at source).

> Hedged: real tools and flags change between versions. Verify at the source. Tests in this repo never need Docker.

## Tests

`9` tests in `test_dso_ch10_*.py`: `.venv/Scripts/python -m pytest devsecops-course/10-container-reconnaissance-and-attacks/labs/daemon-and-kernel-attacks`.
