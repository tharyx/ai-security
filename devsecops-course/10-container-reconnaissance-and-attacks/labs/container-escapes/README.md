# Lab: Container escapes (analysis)

**Course exercise:** "Container-based attacks: privileged mode, mounted volumes, SetUID/SetGID, shared namespaces, Linux capabilities". Lessons: [03 container-based attacks](../../03-container-host-daemon-and-kernel-attacks.md#1-container-based-attacks).

**Time:** 75 minutes. **Safety:** **Purely analytical.** The analyzer reads a config and explains escape paths. It contains no exploit code, runs nothing and a test checks that. Related: [csse exploit-containerized-app](../../../../csse-course/ch3-attacking-container-supply-chain/labs/exploit-containerized-app/README.md).

## What it models

[escape_analyzer.py](escape_analyzer.py) takes a `docker inspect`-style configuration plus a list of SetUID files and returns **escape paths** with id, severity, a plain-English *why* and a *fix*: privileged mode, mounted `docker.sock` or host paths, SetUID/SetGID binaries, shared host PID, NET and IPC namespaces, dangerous capabilities (SYS_ADMIN, SYS_PTRACE, DAC_READ_SEARCH, SYS_MODULE, NET_ADMIN) and disabled seccomp/AppArmor. Fixtures: [risky](fixtures/risky.json), [moderate](fixtures/moderate.json), [hardened](fixtures/hardened.json).

## Steps

```text
.venv/Scripts/python devsecops-course/10-container-reconnaissance-and-attacks/labs/container-escapes/demo.py
.venv/Scripts/python -m pytest devsecops-course/10-container-reconnaissance-and-attacks/labs/container-escapes -v
```

1. Run the demo: verdicts DENY, REVIEW, OK.
2. Take `risky.json` and remove flags one at a time. Does one removal fix it? (No: one flag is rarely the only path.)
3. Mount `docker.sock` read-only: does the finding go away? (No: `:ro` does not stop API calls.)
4. Write a hardened config for a web app that must read one host directory.

## Expected output (real run)

```text
== /ci-runner (risky): verdict DENY, 11 escape paths ==
  [CRITICAL] ESC-CAP-SYS_ADMIN  Dangerous capability SYS_ADMIN
  [CRITICAL] ESC-HOSTMOUNT      Sensitive host path mounted (/)
  [CRITICAL] ESC-PRIV           Privileged mode
  [CRITICAL] ESC-SOCK           Container runtime socket mounted (/var/run/docker.sock)
  [HIGH    ] ESC-CAP-DAC_READ_SEARCH Dangerous capability DAC_READ_SEARCH
  [HIGH    ] ESC-CAP-SYS_PTRACE Dangerous capability SYS_PTRACE
  [HIGH    ] ESC-HOSTMOUNT      Sensitive host path mounted (/etc read-only)
  [HIGH    ] ESC-HOSTNET        Shared host network namespace
  [HIGH    ] ESC-HOSTPID        Shared host PID namespace
  [MEDIUM  ] ESC-HOSTIPC        Shared host IPC namespace
  [LOW     ] ESC-SETUID         SetUID/SetGID binaries in the image (/usr/bin/su, /usr/bin/passwd)

  Explanation of the first one:
    why: CAP_SYS_ADMIN is 'the new root': it allows mounting file systems, using many namespace and cgroup operations and more. Combined with a weak seccomp/Ap...
    fix: --cap-drop ALL, then add back only what the app needs (not SYS_ADMIN).

== /metrics (moderate): verdict REVIEW, 4 escape paths ==
  [HIGH    ] ESC-HOSTMOUNT      Sensitive host path mounted (/proc read-only)
  [HIGH    ] ESC-HOSTPID        Shared host PID namespace
  [HIGH    ] ESC-SETUID         SetUID/SetGID binaries in the image (/usr/bin/sudo)
  [MEDIUM  ] ESC-CAP-NET_ADMIN  Dangerous capability NET_ADMIN
== /web (hardened): verdict OK, 0 escape paths ==
```

## Think about it

Each path is a different *kind* of boundary removed: privileged removes the capability and device boundary, sockets and mounts remove the file boundary, shared namespaces remove the visibility boundary, capabilities widen the kernel boundary.

## Run the real tool

Use `docker inspect`, `docker-bench-security`, deepce and CDK (hedged) only in your own lab. See [real-tools/recon-tools.md](../../real-tools/recon-tools.md).

> Hedged: real tools and flags change between versions. Verify at the source. Tests in this repo never need Docker.

## Tests

`8` tests in `test_dso_ch10_*.py`: `.venv/Scripts/python -m pytest devsecops-course/10-container-reconnaissance-and-attacks/labs/container-escapes`.
