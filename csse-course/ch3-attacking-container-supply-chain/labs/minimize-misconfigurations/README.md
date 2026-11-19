# Lab: Minimize docker security misconfigurations

**Course exercise:** "Minimize docker security misconfigurations". Lessons: [04](../../04-securing-container-applications.md), [05 section 3](../../05-technologies-for-securing-containerized-applications.md#3-seccomp-and-apparmor).

**Time:** 60 minutes. **Safety:** text analysis only; no Docker.

## Reuse

This lab **links** two existing tools instead of copying them:

- the 12-rule Dockerfile linter in [06-ai-devsecops/docker/lab/dockerfile_lint.py](../../../../06-ai-devsecops/docker/lab/dockerfile_lint.py) (module [README](../../../../06-ai-devsecops/docker/README.md));
- the `docker run` assessor from [docker-commands](../docker-commands/run_assess.py).

## What is new

- [hardener.py](hardener.py): `lint_with_fixes` (each rule gets a fix hint), `harden_run` (builds a safe `docker run` command from a small profile), `harden_compose` (same for Compose), and a re-assessment loop that proves the generated command is clean.
- [profiles/seccomp-web-app.json](profiles/seccomp-web-app.json) and [profiles/apparmor-web-app](profiles/apparmor-web-app): example profiles, and [profiles.py](profiles.py) to validate them (default-deny, no dangerous syscalls, deny rules for mount, ptrace, `/proc/sys`, docker.sock).

## Steps

```text
.venv/Scripts/python csse-course/ch3-attacking-container-supply-chain/labs/minimize-misconfigurations/demo.py
.venv/Scripts/python -m pytest csse-course/ch3-attacking-container-supply-chain/labs/minimize-misconfigurations -v
```

1. Read the lint results for 06's vulnerable Dockerfile with fix hints.
2. Change `RunProfile` (add a capability, remove `writable_dirs`) and re-assess.
3. Add `"mount"` to the seccomp allow list and watch the validator fail.
4. The example profiles are **teaching samples**. Build a real profile by recording your app's syscalls and testing under load.

## Expected output (real run)

```text
== generated run command ==
  docker run -d --read-only --user 10001:10001 --cap-drop ALL --cap-add NET_BIND_SERVICE --security-opt no-new-privileges --memory 256m --pids-limit 100 --tmpfs /tmp -p 127.0.0.1:8080:8080 shop-api@sha256:ddd...
  re-assessed: OK
== profiles ==
  seccomp problems : []
  apparmor problems: []
```

## Real-tool twin

hadolint, Trivy config, docker-bench-security, `docker run --security-opt seccomp=... apparmor=...`.
