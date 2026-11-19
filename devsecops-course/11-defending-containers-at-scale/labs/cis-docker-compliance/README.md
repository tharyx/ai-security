# Lab: Minimize Docker misconfigurations with CIS compliance

**Course exercise:** "Minimize Docker Security Misconfigurations With CIS Compliance" [CCSE 4]. Lesson: [03 section 6](../../03-daemon-host-and-kernel-hardening.md#6-dynamic-analysis-docker-bench-and-the-cis-benchmark).

**Time:** 50 minutes. **Safety:** the "host" is a JSON bundle. Nothing is read from a real system.

**Link, do not repeat:** daemon.json-only checks are in [csse ch3 unsecured-docker-daemon](../../../../csse-course/ch3-attacking-container-supply-chain/labs/unsecured-docker-daemon/README.md) and misconfiguration fixes in [minimize-misconfigurations](../../../../csse-course/ch3-attacking-container-supply-chain/labs/minimize-misconfigurations/README.md). This lab is the **whole-benchmark** view with a score.

## What it does

[cis_audit.py](cis_audit.py) is a docker-bench-security-like auditor. Input: host facts, file owner/mode, `daemon.json`, and `docker inspect`-shaped containers. Output: PASS/FAIL per check, a score, a severity-weighted score, a per-section tally and a pipeline exit code.

Check ids are CIS Docker Benchmark-**style** section numbers: 1 host, 2 daemon, 3 files, 4 images, 5 containers. Numbers and wording change between benchmark versions (and the benchmark is licensed content): verify against the version you are audited on.

## Steps

```text
.venv/Scripts/python devsecops-course/11-defending-containers-at-scale/labs/cis-docker-compliance/demo.py
.venv/Scripts/python -m pytest devsecops-course/11-defending-containers-at-scale/labs/cis-docker-compliance -v
```

1. Audit [bundle_bad.json](fixtures/bundle_bad.json). Which three failures would you fix first? (Use severity: docker.sock mode, unauthenticated TCP, privileged container.)
2. Fix the bundle until it matches [bundle_good.json](fixtures/bundle_good.json) (100%).
3. Compare plain and weighted score. Why is the weighted one lower for the bad bundle?
4. The same engine is reused by [audit-docker-daemon-host](../audit-docker-daemon-host/README.md) with different fixtures.

## Expected output (real run)

```text
== bundle_bad.json: score 8.6% (weighted 8.0%), gate(high) exit code 1
   by section: {'1': '1/5', '2': '0/8', '3': '2/6', '4': '0/2', '5': '0/14'}
[FAIL] 1.1.1 (low   ) Separate partition for /var/lib/docker (containers)
        - /var/lib/docker shares the root filesystem
[FAIL] 1.1.5 (medium) Audit rule for /var/lib/docker
        - no auditd watch
[FAIL] 1.1.6 (medium) Audit rule for /etc/docker
        - no auditd watch
[FAIL] 1.2.2 (high  ) Only trusted users in the docker group
        - unapproved user in docker group: bob
        - unapproved user in docker group: contractor1
[FAIL] 2.2   (medium) Restrict network traffic between containers on the default bridge (icc=false)
        - icc not set to false
[FAIL] 2.5   (high  ) No insecure registries
        - insecure registry registry.example.invalid:5000
[FAIL] 2.6   (high  ) TLS authentication for the Docker daemon if it listens on TCP
        - tcp://0.0.0.0:2375 without full tlsverify config
[FAIL] 2.8   (medium) User namespace support (userns-remap) enabled
        - userns-remap not set
[FAIL] 2.12  (low   ) Centralized and remote logging configured
        - log driver keeps logs only on the host
[FAIL] 2.14  (low   ) Live restore enabled
        - live-restore off
[FAIL] 2.15  (low   ) Userland proxy disabled
        - userland-proxy on
[FAIL] 2.18  (medium) Containers restricted from acquiring new privileges (daemon default)
        - no-new-privileges not default
[FAIL] 3.2   (medium) docker.service permissions 644 or stricter
        - too open
[FAIL] 3.15  (high  ) docker.sock owned by root:docker
        - wrong owner
[FAIL] 3.16  (high  ) docker.sock permissions 660 or stricter
        - mode 0666 lets others use the daemon
[FAIL] 3.17  (medium) daemon.json owned by root:root
        - wrong owner
[FAIL] 4.1   (high  ) Containers run as a non-root user
        - web: runs as root
        - ci-agent: runs as root
[FAIL] 4.6   (low   ) HEALTHCHECK present
        - web: no healthcheck
        - ci-agent: no healthcheck
[FAIL] 5.2   (medium) AppArmor or SELinux profile applied
        - web: no LSM profile
        - ci-agent: no LSM profile
[FAIL] 5.3   (high  ) No dangerous added Linux capabilities
        - ci-agent: dangerous CapAdd
[FAIL] 5.4   (high  ) No privileged containers
        - ci-agent: privileged
... (abridged)
```

## Run the real tool (hedged)

```text
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security && sudo sh docker-bench-security.sh
```

docker-bench-security is a shell script that reads the real host and daemon; run it only on machines you own. Its check numbering follows the CIS benchmark version it was written for. Commercial tools (CIS-CAT, cloud posture products) cover the same ground with reports. See [real-tools](../../real-tools/README.md).
