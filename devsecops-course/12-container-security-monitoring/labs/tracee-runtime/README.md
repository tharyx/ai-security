# Lab: Tracee-style runtime security

**Course exercise:** "Tracee - Runtime Security" [CCSE 5]. Lesson: [02 section 5](../../02-runtime-prevention-policy-and-tools.md#5-falco-and-tracee).

**Time:** 45 minutes. **Safety:** JSON events and Python signatures. No eBPF.

## What it does

Tracee (Aqua Security, open source) uses **eBPF** to collect kernel events (process exec, file open, mounts, ptrace...) and runs **signatures** over the stream. [tracee_lite.py](tracee_lite.py) keeps that design: events are shaped like Tracee's JSON output (`eventName`, `processName`, `containerId`, `args[]`), and three stateful signatures run over them. Event and signature names are simplified; the real project ships many signatures (container escape, anti-debugging, dropped executables, ...): verify names at the Tracee docs. IDs here are this lab's own `DSO-TRC-xxx`.

| Signature | Idea | Why stateful |
|---|---|---|
| DSO-TRC-001 dropped executable | file written in `/tmp`, `/dev/shm`, then executed | needs memory of earlier writes |
| DSO-TRC-002 anti-debugging | `ptrace(PTRACE_TRACEME)` | malware refusing to be debugged |
| DSO-TRC-003 container escape attempt | write to cgroup `release_agent`; mount of host block device; `nsenter --target 1` | only meaningful inside a container |

eBPF in one line: small verified programs run **inside the kernel** at hook points, so you see every process without a kernel module and without changing the app. DBA analogy: a trace on the instance (like 10046) instead of sprinkling logging into every application.

## Steps

```text
.venv/Scripts/python devsecops-course/12-container-security-monitoring/labs/tracee-runtime/demo.py
.venv/Scripts/python -m pytest devsecops-course/12-container-security-monitoring/labs/tracee-runtime -v
```

1. Why does the host-side `/tmp/notes.sh` (events 1007-1008) also alert for "dropped executable"? Is it a false positive? How would you tune it (exclude known build users, require network origin)?
2. Remove the container id from the release_agent event: the escape signature stays quiet. Is that right? (It is a container-focused signature; a host process writing there is a different story.)
3. Add a signature: "container reads `/proc/*/environ` of another process".

## Expected output (real run)

```text
t=1002 sev=3 DSO-TRC-001 Dropped executable [container c1]: bash executed /tmp/.cache/kworker which was written earlier in a temp dir
t=1003 sev=2 DSO-TRC-002 Anti-debugging [container c1]: kworker called PTRACE_TRACEME
t=1004 sev=3 DSO-TRC-003 Container escape attempt [container c1]: write to cgroup release_agent (classic privileged-container escape)
t=1005 sev=3 DSO-TRC-003 Container escape attempt [container c1]: container mounted host block device /dev/sda1
t=1006 sev=3 DSO-TRC-003 Container escape attempt [container c1]: nsenter targeting PID 1 (host namespaces)
t=1008 sev=3 DSO-TRC-001 Dropped executable [container host]: bash executed /tmp/notes.sh which was written earlier in a temp dir
```

## Run the real tool (hedged)

```text
sudo docker run --name tracee --rm --pid=host --cgroupns=host --privileged -v /etc/os-release:/etc/os-release-host:ro aquasec/tracee:latest
```

Flags and image names change between releases: copy the current command from the Tracee docs. It needs a kernel with BTF/CO-RE support (most current distros). Tracee runs privileged and sees everything: treat its output as sensitive. See [real-tools](../../real-tools/README.md).
