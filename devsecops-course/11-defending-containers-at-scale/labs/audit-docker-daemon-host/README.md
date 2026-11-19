# Lab: Auditing the Docker daemon and host for security issues

**Course exercise:** "Auditing Docker daemon and host for security issues" [CDE 7]. Lesson: [03 section 6](../../03-daemon-host-and-kernel-hardening.md#6-dynamic-analysis-docker-bench-and-the-cis-benchmark).

**Time:** 40 minutes. **Safety:** fixtures only.

## What it does

This is the CDE 7 lab and it **shares the auditor** from [cis-docker-compliance](../cis-docker-compliance/README.md) (loaded by path, not copied). What is different:

- the fixtures: a **build server** (Jenkins agent with `--privileged`, docker.sock mounted, TCP 2375) before and after hardening;
- [audit_host.py](audit_host.py) adds a **`docker info` text parser** and a **cross-check**: the daemon you configured is not always the daemon that is running (restart pending, `userns-remap` typo);
- a **remediation list** for failed checks, and a pipeline gate.

DBA analogy: comparing `spfile` to `v$parameter`: the file says one thing, the running instance another.

## Steps

```text
.venv/Scripts/python devsecops-course/11-defending-containers-at-scale/labs/audit-docker-daemon-host/demo.py
.venv/Scripts/python -m pytest devsecops-course/11-defending-containers-at-scale/labs/audit-docker-daemon-host -v
```

1. Read the "before" failures. Which single misconfiguration (docker.sock mounted into a privileged container) is equivalent to giving the CI job root on the host?
2. Apply the remediation lines to the "before" bundle until the gate passes.
3. In [docker_info.txt](fixtures/docker_info.txt) turn `Live Restore Enabled` to false and watch the cross-check report drift.

## Expected output (real run)

```text
== buildserver_before.json: score 31.4% weighted 34.7% gate exit=1
   failed: 1.1.3, 1.1.5, 1.1.6, 1.2.2, 2.2, 2.6, 2.8, 2.12, 2.14, 2.15, 2.18, 3.16, 4.1, 4.6, 5.2, 5.3, 5.4, 5.10, 5.11, 5.12, 5.14, 5.25, 5.28, 5.31
   fix -> 1.2.2: Remove unapproved users from the docker group (it is root-equivalent).
   fix -> 2.6: Use fd:// or a unix socket; if TCP is required set tlsverify + CA + server cert/key.
   fix -> 2.8: Set "userns-remap": "default" in /etc/docker/daemon.json (plan for volume ownership).
   fix -> 3.16: chmod 660 /var/run/docker.sock; owner root:docker.
   fix -> 5.4: Drop --privileged; add only the specific capability needed.
   fix -> 5.31: Never mount docker.sock; use a rootless builder (BuildKit/kaniko) in CI.
== buildserver_after.json: score 100.0% weighted 100.0% gate exit=0
   failed: none
== docker info parsed: {'storage-driver': 'overlay2', 'log-driver': 'syslog', 'live-restore': True, 'security-options': ['apparmor', 'seccomp', 'userns']}
== cross-check: consistent
```

## Run the real tool (hedged)

`docker info`, `docker inspect $(docker ps -q)`, `ss -ltnp | grep -E '2375|2376'`, `stat /var/run/docker.sock`, `auditctl -l`, and docker-bench-security. Run them only on hosts you own. See [real-tools](../../real-tools/README.md).
