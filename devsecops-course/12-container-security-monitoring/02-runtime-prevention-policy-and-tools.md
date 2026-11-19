# Lesson 02: Runtime Prevention, Policy, Wazuh, auditd, Falco and Tracee

> **Chapter:** 12 · Container Security Monitoring · **Time:** ~5 hours
> **You will:** separate prevention from detection, manage runtime policy as code, and use Wazuh, auditd, Falco and Tracee (eBPF) for container monitoring.

| | |
|---|---|
| **Prerequisites** | [Lesson 01](01-monitoring-logs-and-incident-response.md); [Chapter 11 lesson 03](../11-defending-containers-at-scale/03-daemon-host-and-kernel-hardening.md) |
| **Labs** | [wazuh-docker-monitoring](labs/wazuh-docker-monitoring/README.md) · [auditd-docker](labs/auditd-docker/README.md) · [falco-runtime-rules](labs/falco-runtime-rules/README.md) · [tracee-runtime](labs/tracee-runtime/README.md) |
| **Syllabus lines** | [CCSE 5] Docker runtime prevention · Policy creation, enforcement, and management · Docker security monitoring using Wazuh |

## 1. Runtime prevention

**Detection** tells you; **prevention** stops it. Prevention at runtime is the set of controls that make the attack **fail while it happens**:

| Layer | Control |
|---|---|
| process | non-root user, `no-new-privileges`, `--cap-drop ALL` |
| syscalls | seccomp allowlist |
| files / MAC | AppArmor, SELinux; read-only root filesystem |
| resources | memory, CPU, pids limits |
| network | default-deny egress, network segregation |
| sandbox | gVisor, Kata |
| image | only signed, scanned images may start (admission policy) |
| active response | kill or freeze a container on a high-confidence rule (Falco-driven response, Wazuh active response) |

Active response is powerful and risky: start with alerts, move to automatic action only for high-confidence rules, and always keep a way to undo. Details of the first rows: [Chapter 11 lesson 03](../11-defending-containers-at-scale/03-daemon-host-and-kernel-hardening.md).

## 2. Policy creation, enforcement and management

A **policy** is a written, testable rule: "no container runs as root", "no `docker.sock` mounts", "images come only from our registry and must be signed", "shells in production containers raise an alert".

- **Create:** start from a standard (CIS Docker, NIST 800-190, your own risk list), express each rule as code: a Falco rule, an admission policy, a CI check, a Wazuh rule.
- **Enforce:** at **three points**: build (CI), deploy (admission/registry) and run (Falco/seccomp/AppArmor).
- **Manage:** keep policies in Git; review and test every change (replay recorded events: see the labs); roll out in **audit mode** first, then enforce; track exceptions with an owner and an expiry; measure alerts per rule and false-positive rate ([Chapter 14](../14-vulnerability-management/02-false-positives-and-false-negatives.md)); retire rules nobody acts on.

DBA analogy: profiles and resource limits in the database, kept as scripts under version control, with a change process.

## 3. Wazuh Docker monitoring

**Wazuh** is an open-source SIEM/XDR platform (agent, manager, indexer, dashboard). Its **docker-listener** module (a wodle in the agent's `ossec.conf`) subscribes to the Docker event stream and emits JSON that the manager decodes into fields (`docker.Action`, `docker.Actor.Attributes...`). Rules match fields with regexes, chain with `if_sid`, and correlate repeats with `frequency` and `timeframe`. Levels 0 to 15 drive alerting. Wazuh also provides **file integrity monitoring** (watch `/etc/docker`), **SCA** (CIS-style policy checks), log collection (auditd, Docker logs) and vulnerability detection for host packages. Module names and options differ by version: verify at the Wazuh docs.

Lab: [wazuh-docker-monitoring](labs/wazuh-docker-monitoring/README.md). SIEM background: [cybersecurity-track 06](../../cybersecurity-track/06-siem-sentinel-splunk/README.md), [07 EDR](../../cybersecurity-track/07-edr-xdr-mdr/README.md).

## 4. auditd for Docker files and binaries

The Linux audit framework records syscalls and file access in the kernel. Docker rules (CIS style) watch:

| Path | Why |
|---|---|
| `/usr/bin/docker*`, `/usr/bin/dockerd`, `containerd`, `runc` | binary replaced or run |
| `/var/lib/docker` | images, containers, volumes |
| `/etc/docker` (incl. `daemon.json`, TLS keys) | daemon config changes |
| `docker.service`, `docker.socket`, `/etc/default/docker` | service definition changes |
| `/run/docker.sock` (and `/var/run/docker.sock`) | **who talks to the daemon** |

Syntax: `-w <path> -p <perms: r w x a> -k <key>`. Add a **key** to every rule so `ausearch -k` finds it. `auid` is the **login uid** and survives `sudo` (value `4294967295` means no login session). Alert on: a non-Docker process opening the socket, edits to `daemon.json`, Docker CLI use by an unapproved user. Rules cost CPU: test on a busy host and watch the backlog. Lab: [auditd-docker](labs/auditd-docker/README.md).

## 5. Falco and Tracee

**Falco** (CNCF graduated; created by Sysdig) watches kernel events through an eBPF probe (older: kernel module) and evaluates YAML **rules**:

```text
- rule: Terminal shell in container
  condition: spawned_process and container and proc.name in (shell_binaries) and proc.tty != 0
  output: "Shell in container (user=%user.name container=%container.name cmd=%proc.cmdline)"
  priority: NOTICE
```

Building blocks: **lists** (named sets), **macros** (named conditions), **rules** (condition + output + priority + tags), **fields** (`proc.name`, `container.id`, `fd.name`, `evt.type`, `fd.sport` ...). Outputs go to stdout, files or, through **Falcosidekick**, to Slack, a SIEM or a function. Default rules ship with Falco; you tune them with exceptions and your own lists. Lab: [falco-runtime-rules](labs/falco-runtime-rules/README.md), an interpreter for a subset so you learn the condition language offline.

**Tracee** (Aqua Security, open source) also uses **eBPF**: it traces kernel events and runs **signatures** (container escape, anti-debugging, dropped executables, ...). Its strength is rich event data and forensics-style context; Falco's strength is the rule language and ecosystem. Many teams run one of them, not both. Lab: [tracee-runtime](labs/tracee-runtime/README.md).

| | Falco | Tracee | auditd | Wazuh |
|---|---|---|---|---|
| Source | eBPF/syscalls | eBPF | kernel audit | agent logs, FIM, events |
| Strength | container-aware rules | rich events, signatures | built into Linux, files and sockets | SIEM, correlation, compliance |
| Output | alerts | alerts/events | audit.log | alerts in a dashboard |

eBPF in one line: small kernel-verified programs run at hook points and report what happens, without kernel modules or app changes. Both tools need privilege and a recent kernel; verify requirements at source.

## 6. Hands-on

1. Run all four labs and write one sentence per lab on what it caught that the others did not.
2. Make one rule fire in two tools (for example a shell in a container: Falco and Wazuh `exec_create`).

## 7. Quick check

1. Detection or prevention: seccomp? Falco?
2. Why do audit rules need keys?
3. Where does Falco read events from?

## 8. References

- Falco: https://falco.org/docs/ · Tracee: https://aquasecurity.github.io/tracee/
- Wazuh docs: Docker monitoring (verify the current module name) · `man auditctl`, `man audit.rules`.
- CIS Docker Benchmark section 1.1 (audit rules).
