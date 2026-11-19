# Lesson 03: Container-based, Docker Host (Daemon) and Kernel Attacks

> **Chapter:** 10 · Container Reconnaissance and Attacks · **Time:** ~6 hours
> **You will:** explain how a misconfigured container reaches the host (privileged mode, mounts, SetUID, shared namespaces, capabilities), how the Docker daemon and kernel are attacked, why `docker` group means root, and how enumeration tools such as deepce work, then fix each.

| | |
|---|---|
| **Prerequisites** | [Lesson 01](01-container-reconnaissance.md), [chapter 9 lesson 01](../09-container-fundamentals/01-what-is-a-container.md) |
| **Labs** | [container-escapes](labs/container-escapes/README.md) · [daemon-and-kernel-attacks](labs/daemon-and-kernel-attacks/README.md) · [remote-docker-api-scan](labs/remote-docker-api-scan/README.md) · [privilege-escalation-and-misconfig](labs/privilege-escalation-and-misconfig/README.md) · [deepce-exploitation](labs/deepce-exploitation/README.md) · csse: [exploit-containerized-app](../../csse-course/ch3-attacking-container-supply-chain/labs/exploit-containerized-app/README.md), [unsecured-docker-daemon](../../csse-course/ch3-attacking-container-supply-chain/labs/unsecured-docker-daemon/README.md) |
| **Syllabus lines** | Container-based attacks · Manipulating the privileged mode containers · Attacking mounted Docker volumes · Abusing SetUID/SetGID binaries · Exploiting shared namespaces · Attacking Linux capabilities · Docker host (Daemon) / kernel attacks · Exploiting unauthenticated Docker API · Insecure Docker endpoint · Lack of network segregation · Denial of service attacks · Kernel exploits · Privilege escalation methods in Docker · Security misconfigurations |
| **Reuse** | csse [lesson 03 section 4](../../csse-course/ch3-attacking-container-supply-chain/03-attacking-the-container-supply-chain.md#4-attacking-through-container-misconfigurations) and [lesson 04 section 5](../../csse-course/ch3-attacking-container-supply-chain/04-securing-container-applications.md#5-securing-the-docker-daemon) |

> **Safety: analysis, not exploitation.** This lesson explains **why** each configuration is dangerous and **how to detect and fix it**. It deliberately gives no breakout recipes. The labs analyse configurations and fixtures; the escape analyzer and deepce-lite contain no exploit code (a test checks that). Practise real breakouts only on a disposable VM you own.

## 1. Container-based attacks

**Rule:** an attacker who controls code inside a container tries to cross a boundary. Each risky run option removes one boundary. The [container-escapes lab](labs/container-escapes/README.md) reads a container configuration and lists the escape paths with a *why* and a *fix*.

| Boundary | Removed by | Section |
|---|---|---|
| Capability and device boundary | `--privileged` | 1.1 |
| File-system boundary | Host mounts, the Docker socket | 1.2 |
| Privilege boundary inside the container | SetUID/SetGID binaries | 1.3 |
| Visibility boundary | Shared PID, NET, IPC namespaces | 1.4 |
| Kernel-surface boundary | Dangerous capabilities, no seccomp/AppArmor | 1.5 |

### 1.1 Manipulating privileged-mode containers

`--privileged` gives the container **all capabilities**, access to **all host devices** and **turns off the default seccomp and AppArmor** confinement. What is left is mostly namespaces, which do not stop a process that can mount devices and manage the kernel. In practice, root in a privileged container can usually reach the host disk. It is sometimes used "to make it work" (Docker-in-Docker, CI runners, hardware access).

Detect: `HostConfig.Privileged: true` in inspect; a full `CapEff` mask (`000001ffffffffff` on current kernels). Fix: remove it; add only the one capability or `--device` needed; use rootless builders or Kubernetes with Pod Security "restricted".

### 1.2 Attacking mounted Docker volumes (and the Docker socket)

A bind mount makes a host path part of the container's file system. The risks, in order of severity:

1. **`/var/run/docker.sock`:** this is the daemon's API. A process that can write to it can ask the root daemon to create a new container with any mount and privilege. So **mounting the socket is root on the host**, even with `:ro` (read-only does not stop API calls).
2. **`/` or large host paths** (`/etc`, `/root`, `/var/lib/docker`, `/home`): read-write means the container can change host configuration, add users or plant files; read-only still leaks `shadow`, keys and every other container's data.
3. **`/proc` and `/sys`:** kernel and device interfaces; exposing them widens the attack surface.
4. **A writable app directory** shared with the host: a root container can create root-owned or SetUID files the host later trusts.

Also check **volumes** shared between containers: a weak container can poison data a strong one reads. Detect: `Binds` and `Mounts` in inspect. Fix: mount the narrowest path, read-only, as a non-root user; use named volumes; use a **socket proxy** with an allow-list if a tool really needs the API. See [manage-data](../09-container-fundamentals/labs/manage-data/README.md).

### 1.3 Abusing SetUID/SetGID binaries

A SetUID binary runs with its **owner's** privileges (often root), whoever starts it. Images contain a handful (`su`, `passwd`, `mount`, sometimes `sudo`). If one has a flaw or a risky feature, a low-privileged process can become root **inside the container**. That is rarely a host escape by itself, but it is the usual first step to every other path in this section (root inside makes mounts, socket access and capability abuse possible). Detect with `find / -perm /6000 -type f` in the image (or a scanner). Fix: `--security-opt no-new-privileges` (a process cannot gain privileges through exec), strip the bits in the Dockerfile (`chmod u-s,g-s`), use distroless images that contain none.

### 1.4 Exploiting shared namespaces

Sharing a namespace with the host removes the matching isolation:

- `--pid=host`: the container sees and can signal host processes; with `SYS_PTRACE` or root it can read their memory, environment variables and secrets.
- `--network=host`: the container is on the host's network stack. It reaches services bound to `127.0.0.1` (a local database, a localhost-only Docker API, the cloud metadata address) and can sniff traffic with `NET_RAW`.
- `--ipc=host`: shared memory segments of host processes are visible.
- No `user` namespace: UID 0 in the container is UID 0 on the host, so file ownership and some kernel checks treat it as host root.

Also `--pid=container:<id>` and `--network=container:<id>` share with **another container**, which is useful for debugging and also a lateral movement path. Fix: keep namespaces private; use user-namespace remapping or rootless mode.

### 1.5 Attacking Linux capabilities

Capabilities beyond Docker's default 14 widen what root inside the container may do. The three the syllabus names:

- **`SYS_ADMIN`:** a broad "do many admin things" capability (mounts, many namespace and cgroup operations). It is called "the new root". With a weak seccomp/AppArmor profile it is the classic enabler of breakouts.
- **`SYS_PTRACE`:** inspect and modify other processes; dangerous with `--pid=host` or when sharing a PID namespace with a sensitive container.
- **`DAC_READ_SEARCH`:** bypass file read permission checks and open files by handle; historically used to read files outside the container's intended view when combined with a host-visible mount.

Others to know: `SYS_MODULE` (load kernel modules), `NET_ADMIN` (change routes and firewall), `DAC_OVERRIDE`. Fix: `--cap-drop ALL`, add back the minimum, keep seccomp and AppArmor enabled. The lab's analyzer explains each in plain English.

## 2. Unauthenticated Docker API and insecure endpoint

The Docker daemon can listen on TCP (`-H tcp://0.0.0.0:2375`). **Port 2375 is plain HTTP with no authentication.** Anyone who can reach it can call the whole API: list containers (and read their env), create a privileged container with the host root mounted, and so on. That makes it **remote root**, and exposed 2375 ports are scanned for at internet scale (cryptominers are the classic payload).

An **insecure endpoint** is any of: TCP without TLS; TLS without **client certificate verification** (anyone can connect, encrypted); binding to `0.0.0.0` when a private interface was meant; a firewall rule that "temporarily" allows the port; the API reachable from other containers (host network, or a bridge gateway). Recon: `ss -ltnp | grep -E '2375|2376'`, `docker info`, `/etc/docker/daemon.json` `"hosts"`, systemd unit overrides. See [remote-docker-api-scan](labs/remote-docker-api-scan/README.md) (localhost mock only) and the audits in [daemon-and-kernel-attacks](labs/daemon-and-kernel-attacks/README.md).

Fix: keep the API on the Unix socket. If remote use is needed, prefer `ssh://` access. If TCP is required: port **2376**, `tlsverify` with CA, server and **client** certificates, a private bind address, firewall rules, and rootless mode. See the [csse unsecured-docker-daemon lab](../../csse-course/ch3-attacking-container-supply-chain/labs/unsecured-docker-daemon/README.md).

## 3. Lack of network segregation

By default every container on the `bridge` network can reach every other one. If an internet-facing web container is compromised, the attacker scans the bridge and attacks the database, cache and internal APIs ("lateral movement"). Also with `icc` enabled, with `host` networking, or when many apps share one overlay.

Fix: one **user-defined network per tier** (frontend, backend, data), `--internal` networks for things that must not reach the internet, publish only needed ports on specific addresses, `icc=false` on the default bridge, and network policies on Kubernetes. The [docker-networking lab](../09-container-fundamentals/labs/docker-networking/README.md) calculates reachability; [daemon-and-kernel-attacks](labs/daemon-and-kernel-attacks/README.md) counts the exposed pairs on a flat network.

## 4. Denial of service attacks

Without cgroup limits a container can use all the memory, CPU or process slots of the **host**. Classic forms: a memory leak or allocation loop (the kernel's OOM killer may kill the wrong process, including the daemon); a CPU burner; a **fork bomb** (processes create processes until the host cannot create more); filling the disk with logs or a volume; network flooding.

The fork-bomb idea in one line: the number of processes doubles each generation, so a few seconds are enough to hit the system-wide limit. A **pids limit** (`--pids-limit`) caps it inside the container's cgroup; without one the limit hit is the host's `pid_max` and everything on the host suffers. The lab models this as **arithmetic only** (nothing is forked) to make the point. Also set `--memory`, `--cpus`, log rotation (`--log-opt max-size`), disk quotas and ulimits, and monitor OOM events ([inspect-daemon-activity](labs/inspect-daemon-activity/README.md)).

## 5. Kernel exploits

All containers on a host share **one kernel**. A bug that lets code in a container corrupt or take over the kernel is a container escape for **every** container on that host, however careful the container configuration. Typical sources: kernel components reachable from unprivileged code (user namespaces, networking, file systems such as overlayfs, io_uring, cgroups). Some need a capability (so dropping it blocks the path), some need only unprivileged code.

Defence: **patch the host kernel** and runtime (runc, containerd) promptly and keep a patch SLA; use a current distribution kernel; keep seccomp on (the default profile blocks many risky system calls); consider **user-namespace remapping or rootless** mode; disable unprivileged user namespaces if you do not need them (hedged: some tools do); and use **sandboxed runtimes** (gVisor, Kata) for untrusted code (chapter 11). The lab maps a host kernel version to a **fixture CVE list** so you see how exposure depends on the version; real data comes from your distribution's security tracker (verify at source).

## 6. Privilege escalation methods in Docker

Collecting the paths:

| Method | Why it works | Fix |
|---|---|---|
| **`docker` group membership** | The group can use the root daemon's socket; "can run docker" equals "is root" | Do not add users; use rootless Docker/Podman or audited sudo |
| Mounted `docker.sock` in a container | Same as above, from inside | Do not mount; socket proxy |
| Privileged container / dangerous capabilities | Boundary removed (section 1) | Remove; drop caps |
| Writable host mounts + root container | Container creates files the host trusts | Non-root user, `:ro`, userns |
| SetUID binaries | Root inside the container | `no-new-privileges`, strip bits |
| Kernel or runtime vulnerabilities | Shared kernel (section 5) | Patch; sandboxed runtimes |
| Weak sudo rules around docker | `sudo docker` with wildcards equals root | Fixed, narrow commands |

### Security misconfigurations (the common root cause)

Most real incidents are not zero-days: they are **settings**. Typical list: rootful daemon with no user namespaces; API on TCP without TLS; `--privileged`; socket and host mounts; root user; no limits; default bridge; secrets in env; `latest` images; no seccomp/AppArmor profile; no logging; outdated runtime. Benchmarks give the checklist: **CIS Docker Benchmark** (run with `docker-bench-security`) and NIST SP 800-190. The [privilege-escalation-and-misconfig lab](labs/privilege-escalation-and-misconfig/README.md) turns a host profile into escalation chains and shows how rootless mode and userns-remap change severity.

## 7. deepce and similar tools

**deepce** ("Docker Enumeration, Escalation of Privileges and Container Escapes") is a shell script (verify the project's current maintenance status). Run **inside** a container, it enumerates: am I in a container; which runtime; my user; capabilities; whether the Docker socket or other interesting mounts are present; whether the container is privileged; network and cloud-metadata reachability; secrets in environment and files; and it points to or automates follow-up checks. Similar tools: **amicontained** (reports runtime, namespaces, capabilities, seccomp), **CDK** (container penetration toolkit), **linpeas** (general Linux enumeration). Defenders run them on their own containers to see what an attacker sees.

The [deepce-exploitation lab](labs/deepce-exploitation/README.md) implements **deepce-lite**: the enumeration and reporting half only, over a **fake container** (a fixture of `/proc/self/status`, `/proc/mounts` and files). It decodes the capability bitmask, spots the socket, host block devices, shared host PID and metadata reachability, and reports **escape vectors**. It performs no exploitation and a test enforces that.

## 8. Defend (summary)

1. `--cap-drop ALL`, non-root `USER`, `no-new-privileges`, read-only root file system.
2. No `--privileged`, no socket, no broad host mounts, no shared host namespaces.
3. Daemon API on the Unix socket; TLS client certs if remote; rootless or userns-remap.
4. Cgroup limits (memory, pids, cpu) on every container.
5. Segmented networks; published ports bound narrowly.
6. Patch kernel and runtimes; CIS benchmark checks in CI and on hosts; admission policy (Kubernetes Pod Security, OPA/Kyverno) to block risky configs.
7. Runtime detection (Falco, Tracee, auditd, Wazuh) for chapter 12.

## 9. Hands-on

[container-escapes](labs/container-escapes/README.md), [daemon-and-kernel-attacks](labs/daemon-and-kernel-attacks/README.md), [remote-docker-api-scan](labs/remote-docker-api-scan/README.md), [privilege-escalation-and-misconfig](labs/privilege-escalation-and-misconfig/README.md), [deepce-exploitation](labs/deepce-exploitation/README.md), and the csse [exploit-containerized-app](../../csse-course/ch3-attacking-container-supply-chain/labs/exploit-containerized-app/README.md) and [unsecured-docker-daemon](../../csse-course/ch3-attacking-container-supply-chain/labs/unsecured-docker-daemon/README.md).

## 10. Scenario

A developer says: "I mounted `docker.sock` read-only, so it is safe." Explain in five lines why it is not, what the worst case is, and what you would use instead.

## 11. References

- CIS Docker Benchmark; NIST SP 800-190; OWASP Docker Security Cheat Sheet; Docker docs: protect the daemon socket, rootless mode, userns-remap.
- Linux man pages `capabilities(7)`, `namespaces(7)`; deepce, amicontained, CDK, docker-bench-security project pages (verify status).
- Repo: [05 sandboxing](../../05-agent-security/sandboxing/README.md), csse [lesson 03](../../csse-course/ch3-attacking-container-supply-chain/03-attacking-the-container-supply-chain.md) and [lesson 05](../../csse-course/ch3-attacking-container-supply-chain/05-technologies-for-securing-containerized-applications.md).
