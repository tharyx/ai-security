# Lab: Custom seccomp and AppArmor policy

**Course topic:** "Kernel Hardening using Seccomp and AppArmor" and "Custom policy creation using Seccomp and AppArmor" [CCSE 4]; "Kernel Hardening using SecComp and AppArmor" [CDE 7]. Lesson: [03 section 5](../../03-daemon-host-and-kernel-hardening.md#5-kernel-hardening-seccomp-and-apparmor).

**Time:** 50 minutes. **Safety:** text processing only; no kernel, no Docker.

**Link, do not repeat:** the fixed-profile demos are in [csse ch3 labs](../../../../csse-course/ch3-attacking-container-supply-chain/labs/minimize-misconfigurations/README.md) and lesson [04 section 6](../../../../csse-course/ch3-attacking-container-supply-chain/04-securing-container-applications.md). This lab builds profiles **from observation**.

## What it does

[policy_gen.py](policy_gen.py):

1. `parse_strace` extracts the unique syscalls from an `strace` capture.
2. `gen_seccomp` builds an **allowlist** profile (`defaultAction: SCMP_ACT_ERRNO`) from them plus a small runtime baseline. Dangerous syscalls (`ptrace`, `mount`, `unshare`, `bpf`, `kexec_load`, ...) are **never auto-allowed**; they are reported for a human to decide.
3. `validate_seccomp` rejects denylist-style profiles (`defaultAction: ALLOW`) and allowed dangerous calls.
4. `gen_apparmor` builds a profile from file-access observations, with explicit denies for `/proc/sys`, `/sys`, the docker socket, `mount`, `ptrace`, `capability sys_admin`.
5. `validate_apparmor` flags blanket `file,`, `/** rw`, complain mode, dangerous capabilities.

Important caveat: a profile learned from one test run is **incomplete**. Run it in audit/complain mode against your whole test suite first, then enforce. Docker's default seccomp profile is a good general-purpose allowlist; write custom ones for high-risk workloads.

## Steps

```text
.venv/Scripts/python devsecops-course/11-defending-containers-at-scale/labs/seccomp-apparmor-custom-policy/demo.py
.venv/Scripts/python -m pytest devsecops-course/11-defending-containers-at-scale/labs/seccomp-apparmor-custom-policy -v
```

1. Run the demo. How many syscalls did the web app really need?
2. Feed [strace_with_ptrace.txt](fixtures/strace_with_ptrace.txt): why are `ptrace` and `mount` refused?
3. Validate [bad_seccomp.json](fixtures/bad_seccomp.json) and [bad_apparmor.profile](fixtures/bad_apparmor.profile) and fix them.

## Expected output (real run)

```text
observed syscalls: ['execve', 'brk', 'mmap', 'openat', 'read', 'socket', 'bind', 'listen', 'accept4', 'futex', 'write', 'epoll_wait']
generated seccomp: default = SCMP_ACT_ERRNO | allowed = 28 | refused = []
validate generated: OK
second capture refuses: ['mount', 'ptrace']
validate bad_seccomp.json: ['defaultAction allows everything: this is a denylist, not an allowlist', 'dangerous syscall allowed: mount', 'dangerous syscall allowed: pt...
---- generated AppArmor profile ----
#include <tunables/global>

profile dso-web-app flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  network inet tcp,

  /app/** r,
  /usr/bin/python3.12 ix,
  /usr/lib/python3/** r,
  /etc/ssl/certs/** r,
  /tmp/** rw,
  /var/log/app/*.log w,

  # explicit denies: belt and braces for what the container must never touch
  deny /proc/sys/** wklx,
  deny /sys/** wklx,
  deny /var/run/docker.sock rwklx,
  deny mount,
  deny ptrace,
  deny capability sys_admin,
}

validate generated: OK
validate bad_apparmor.profile:
  - profile is in complain mode: it logs but does not enforce
  - blanket 'file' rule allows all file access
  - root-wide write rule: /** rw
  - dangerous capability allowed: capability sys_admin
  - allows ptrace
  - allows access to docker.sock
  - missing deny for /proc/sys
```

## Run the real tool (hedged)

```text
docker run --security-opt seccomp=profile.json --security-opt apparmor=dso-web-app myimage
sudo apparmor_parser -r -W dso-web-app.profile
```

For learning mode use `aa-genprof`/`aa-logprof` (AppArmor) and an audit-style seccomp action or tools such as `strace`, `oci-seccomp-bpf-hook` or Inspektor Gadget (check which are maintained). AppArmor needs a host that supports it (Ubuntu, Debian, SUSE); RHEL-family uses SELinux. Verify at source.
