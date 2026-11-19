# Lab 05: Sandboxing Tool Execution Using Docker (policy generator plus subprocess twin)

> **Chapter 3 exercise:** Sandboxing Tool Execution Using Docker
> **Study first:** [Lesson 04, section 2.1](../../04-defending-memory-context-and-tool-use.md#21-tool-execution-sandboxing-and-output-validation)
> **Generic material in this repo:** [05-agent-security/sandboxing](../../../../05-agent-security/sandboxing/README.md) · [06-ai-devsecops/runtime-security](../../../../06-ai-devsecops/README.md)

Offline, harmless and tested. No network, no API key, no GPU, no Docker needed by the tests. Secrets are canaries or clearly fake values; domains end in `.example`. The model is a `MockLLM` subclass: deterministic and deliberately gullible. The lab is **self-contained** (it does not import code from another lab).

## What it simulates

Part 1 builds a hardened `docker run` command from a policy object and **refuses unsafe policies** (privileged, network, root user, docker.sock mount, secret-looking env, unpinned image, missing limits). Part 2 is a subprocess twin that shows the policy ideas without Docker: scrubbed environment, private working directory, timeout, output cap. **Docker is never started by the tests.**

## Files

`sandbox.py` (`SandboxPolicy`, `validate_policy`, `build_docker_args`, `SubprocessSandbox`) · `Dockerfile` · `tool.py` · `demo.py` · `test_caase_ch3_sandbox.py`

## Vulnerable vs defended

| | |
|---|---|
| **Vulnerable** | Run the tool as the agent's own user with its environment, network and home directory. |
| **Defended** | No network, read-only root filesystem, non-root user, `--cap-drop ALL`, `no-new-privileges`, memory/CPU/PID limits, a small `noexec` tmpfs, read-only mounts from allowed roots only. The builder fails closed. The twin proves env scrubbing, timeout and output cap, and a test states honestly that a subprocess is not isolation. |

## Run it

```powershell
.venv/Scripts/python caase-course/ch3-agent-memory-context-and-tool-use/labs/05-docker-tool-sandbox/demo.py
.venv/Scripts/python -m pytest caase-course/ch3-agent-memory-context-and-tool-use/labs/05-docker-tool-sandbox -v
```

## Real demo output

(Canary suffixes are random on every run.)

```text
Generated command (never executed here):
  docker run --rm --network none --read-only --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges --memory 256m --cpus 0.5 --pids-limit 64 --tmpfs /tmp:rw,noexec,nosuid,size=16m -v /srv/work/in:/data:ro agent-tool-sandbox:1.0 python /app/tool.py

Unsafe policy problems:
  - privileged containers are forbidden
  - network must be 'none'
  - must run as a non-root user

Subprocess twin, scrubbed env : secret visible: None
Subprocess twin, env passed   : secret visible: FAKE-TOKEN-123
Runaway loop                  : SandboxResult(returncode=None, stdout='', timed_out=True, truncated=False)
```

24 tests pass.

## Try it yourself

Run the generated command for real (guide below). Try to write to `/`, reach the network, or read an environment variable from inside. Add `--security-opt seccomp=` and AppArmor/SELinux profiles and compare. Look at gVisor or a microVM runtime as a stronger boundary.

## Limits

The generated command is hedged: verify flags against your Docker version. A shared-kernel container is not as strong as a microVM. On Windows, Docker Desktop runs Linux containers in a VM; the paths in mounts differ.

## Real-tool guide: run it in Docker (hedged)

> Not run by the repo author. Needs Docker Desktop (Linux containers). Check disk space first. Verify every flag against `docker run --help` for your version.

```powershell
cd caase-course/ch3-agent-memory-context-and-tool-use/labs/05-docker-tool-sandbox
docker build -t agent-tool-sandbox:1.0 .
# print the hardened command line from the policy generator:
..\..\..\..\.venv\Scripts\python demo.py
# then run it, adjusting the mount path to a folder you control that holds input.txt:
docker run --rm --network none --read-only --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges `
  --memory 256m --cpus 0.5 --pids-limit 64 --tmpfs /tmp:rw,noexec,nosuid,size=16m `
  -v D:\work\in:/data:ro agent-tool-sandbox:1.0 /data/input.txt
```

Then try, from inside a debug shell (`--entrypoint sh`), to: write to `/app`, open a network connection, list `/proc` of the host, read your environment. Each should fail. For production, pin the base image by digest, add a seccomp profile, and consider gVisor or a microVM runtime.
