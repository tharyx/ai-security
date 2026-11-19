# Lab: Auditing Docker with auditd

**Course exercise:** "Auditing Docker using AuditD" [CCSE 5]. Lesson: [02 section 4](../../02-runtime-prevention-policy-and-tools.md#4-auditd-for-docker-files-and-binaries).

**Time:** 40 minutes. **Safety:** rules are text and the audit log is a fixture. Do not load rules on a shared host without asking its owner.

**Link, do not repeat:** the Linux audit basics are in [cybersecurity-track 01 IT fundamentals](../../../../cybersecurity-track/01-it-fundamentals/README.md); how detections feed a SIEM is [06 SIEM](../../../../cybersecurity-track/06-siem-sentinel-splunk/README.md).

## What it does

- [docker.rules](docker.rules): watches on `/usr/bin/docker*`, `/usr/bin/dockerd`, `/usr/bin/containerd`, `/usr/bin/runc`, `/var/lib/docker`, `/etc/docker` (incl. `daemon.json`), the docker unit files, and `docker.sock` (both `/run` and `/var/run`), each with a **key** (`-k`) so you can search later; plus one syscall rule logging every `execve` of the docker CLI.
- [auditd_tool.py](auditd_tool.py): `lint` (missing watches, no key, writes not logged), `parse_log` (group SYSCALL and PATH records by event serial) and `detect`:
  - `DOCKER_SOCK_ACCESS`: a process other than docker/dockerd/containerd opened the socket (a web app with the socket is a container-escape path);
  - `DOCKER_CONFIG_CHANGE`: `daemon.json` or a unit file touched (an editor "save" shows as two events: open and rename/create);
  - `DOCKER_CLI_UNAPPROVED_USER`: docker CLI used by an unapproved login user (`auid` survives `sudo`; `4294967295` = no login session).

Paths differ by distro (usr-merge, snap, rootless Docker puts the socket under `$XDG_RUNTIME_DIR`): verify with `which docker`, `systemctl cat docker`.

## Steps

```text
.venv/Scripts/python devsecops-course/12-container-security-monitoring/labs/auditd-docker/demo.py
.venv/Scripts/python -m pytest devsecops-course/12-container-security-monitoring/labs/auditd-docker -v
```

1. Lint the full ruleset (clean), then the weak ruleset in the demo (4 problems shown).
2. Read [audit.log](audit.log) and predict the alerts. Which event is the scariest? (The python process with no login session on the socket.)
3. Add a rule for `/etc/subuid` and `/etc/subgid` and a test that proves the linter's coverage list changes.

## Expected output (real run)

```text
13 rules parsed; lint: OK
lint of a weak ruleset: ['watch /usr/bin/docker has no -k key: you will not be able to search for it', 'watch /etc/docker does not log writes (-p wa)', 'missing watch:...
7 audit events
[high] DOCKER_SOCK_ACCESS (event 502): /usr/bin/python3.12 (uid=33, auid=unset) opened /var/run/docker.sock
[high] DOCKER_CONFIG_CHANGE (event 503): /usr/bin/vim.basic touched /etc/docker/daemon.json (auid=1001, syscall=257)
[high] DOCKER_CONFIG_CHANGE (event 504): /usr/bin/vim.basic touched /etc/docker/daemon.json (auid=1001, syscall=82)
[medium] DOCKER_CLI_UNAPPROVED_USER (event 506): docker CLI used by auid=1002
```

## Run the real tool (hedged)

```text
sudo cp docker.rules /etc/audit/rules.d/docker.rules && sudo augenrules --load
sudo auditctl -l | grep docker
sudo ausearch -k docker-sock -i
sudo aureport -f -i
```

Ship `/var/log/audit/audit.log` to your SIEM (or let a Wazuh agent read it: see [wazuh-docker-monitoring](../wazuh-docker-monitoring/README.md)). Rules cost CPU on busy hosts: watch the audit backlog. See [real-tools](../../real-tools/README.md).
