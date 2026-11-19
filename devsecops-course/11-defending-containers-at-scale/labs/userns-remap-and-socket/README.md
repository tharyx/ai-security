# Lab: user namespace remapping and the Docker socket

**Course topic:** "Docker user remapping", "Docker socket configuration", "fd", "TCP socket", "TLS authentication" [CCSE 4]. Lesson: [03 sections 2 and 3](../../03-daemon-host-and-kernel-hardening.md#2-user-namespace-remapping-and-sandboxed-runtimes).

**Time:** 40 minutes. **Safety:** configuration fixtures only; no daemon is started.

**Link, do not repeat:** the broader daemon audit is [csse ch3 unsecured-docker-daemon](../../../../csse-course/ch3-attacking-container-supply-chain/labs/unsecured-docker-daemon/README.md).

## What it does

[daemon_checks.py](daemon_checks.py):

| Function | What it checks |
|---|---|
| `check_userns` | `userns-remap` set; `/etc/subuid` and `/etc/subgid` have a range (>= 65536) for `dockremap` |
| `check_tcp` | `tcp://` listener: no TLS = critical; TLS without client verification = high; mutual TLS on all interfaces = medium |
| `check_fd` | `fd://` means systemd socket activation: `docker.socket` should be `SocketMode=0660`, `SocketGroup=docker` |
| `check_client_cert` | mutual TLS: client CN allow-list, expiry, issuer, `clientAuth` usage |

Three ways to reach the daemon: the **unix socket** (local, permission-controlled, but access = root), **fd://** (same socket, opened by systemd), **TCP** (remote: only with mutual TLS, ideally not at all; SSH `docker -H ssh://` is a simpler remote option).

## Steps

```text
.venv/Scripts/python devsecops-course/11-defending-containers-at-scale/labs/userns-remap-and-socket/demo.py
.venv/Scripts/python -m pytest devsecops-course/11-defending-containers-at-scale/labs/userns-remap-and-socket -v
```

1. Compare [daemon_bad.json](fixtures/daemon_bad.json) with [daemon_good.json](fixtures/daemon_good.json).
2. Remove the `dockremap` line from the subuid fixture: what happens to the daemon? (It will not start.)
3. Expire the client certificate (change the date in the demo): which check fires?

## Expected output (real run)

```text
== BAD daemon.json
userns: ['userns-remap not configured: container root is host root (UID 0)']
tcp   : [critical] tcp://0.0.0.0:2375: Docker API on TCP without TLS: anyone reaching it is root on the host
tcp   : [critical] port 2375 is the conventional plaintext Docker port
fd    : ['docker.socket SocketMode=0666: use 0660 (or 0600)']
== GOOD daemon.json
userns: OK
tcp   : OK
fd    : OK
== userns with missing subuid range: ['/etc/subuid has no range for dockremap: daemon will fail to start']
== client cert today: OK
== client cert in 2028: ['client certificate expired 2027-06-30']
```

## Run the real tool (hedged)

```text
# /etc/docker/daemon.json
{ "userns-remap": "default" }
# then: sudo systemctl restart docker ; ls /var/lib/docker (a new <uid>.<gid> directory appears)
```

`userns-remap` changes where images and volumes live and can break bind mounts that need host root ownership: test first. Rootless Docker/Podman are alternatives. TLS setup uses `dockerd --tlsverify --tlscacert ... --tlscert ... --tlskey ...`. Verify at source.
