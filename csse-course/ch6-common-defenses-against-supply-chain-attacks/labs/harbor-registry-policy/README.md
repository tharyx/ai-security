# Lab: Container Registry using Harbor

**Course exercise:** "Container Registry using Harbor". Lesson: [03-change-control-and-licensed-code.md](../../03-change-control-and-licensed-code.md#11-protected-branches). Chapter guide: [README](../../README.md). Real-tool guides: [real-tools](../../real-tools/README.md).

**Time:** 50 minutes. **Tests:** 10, all offline. **Safety:** fixtures only; secrets are FAKE, domains are `.example`, advisory ids are fictional, nothing is downloaded or executed, and tests never need Docker, Kubernetes, a network or an account.

> **Outdated to current.** Named tool: **Harbor**. Harbor is a CNCF graduated project and actively maintained (verify the current release).

## What the offline twin does

`registry.py` simulates a registry: **projects** (public or private), **robot accounts** (scoped permissions and expiry), **immutable tag rules**, **prevent vulnerable images from running** (severity threshold, time-boxed CVE allowlist), and a **signature required** policy.

## Steps

```text
.venv/Scripts/python csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/harbor-registry-policy/demo.py
.venv/Scripts/python -m pytest csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/harbor-registry-policy -v
```

1. Run the demo and read each ALLOW/DENY line.
2. Try pushing `v1.0` twice, then `latest` twice. Why does one fail? (Immutable tag patterns.)
3. Set the threshold to MEDIUM and re-pull. Which images are now blocked?

## Expected output (real run)

```text
OK    push prod/api:v1.0
DENY  push again (immutable tag): tag 'v1.0' is immutable and already exists
DENY  pull with push-only robot: robot 'ci-push' lacks 'pull' on project 'prod'
DENY  anonymous pull: anonymous pull denied: project is private
OK    pull signed LOW-only image
DENY  pull image with a CRITICAL vuln: pull blocked: EXAMPLE-2026-0003 (CRITICAL) at or above HIGH
OK    pull after time-boxed CVE allowlist
```

## Real-tool guide (hedged: verify commands against the current docs)

```text
# Harbor is deployed with Helm or docker compose; plan resources (it needs a database, Redis, storage)
helm repo add harbor https://helm.goharbor.io        # verify in the Harbor docs
helm install harbor harbor/harbor --set expose.type=...   # configure TLS and storage per the docs
# In the UI or API: create a project, add a robot account scoped to push or pull on that project,
# enable "Prevent vulnerable images from running" with a severity, add an immutability rule,
# enable the vulnerability scanner (Trivy is the default scanner adapter), set tag retention.
docker login harbor.example -u 'robot$ci-push'       # use the robot name and secret from Harbor
```
Use a small local test install only if you have the disk space; the tests do not need it. Harbor also supports signature policy with cosign or Notation (verify in the docs).
