# Lab: Image-based attacks

**Course exercise:** "Image-based attacks: Extracting passwords, tokens, TLS certs; Exploiting vulnerable components". Lessons: [02 image-based attacks](../../02-container-attack-matrix-image-and-registry-attacks.md#3-image-based-attacks).

**Time:** 60 minutes. **Safety:** No exploit code: the lab produces an analysis (entry, flaw, privilege, impact). Vulnerability IDs are FIXTURE IDs. Token is a runtime-built canary.

## What it models

(1) **Extracting secrets** from an image without running it (history and file contents). (2) **Exploit-path analysis** for vulnerable components: which flaws are reachable from the network or from user input, which are only second-step, how root and a mounted `docker.sock` turn a container bug into a host compromise, and a FIX NOW / FIX SOON / BACKLOG priority. For malicious and backdoored images see [csse malicious-image](../../../../csse-course/ch3-attacking-container-supply-chain/labs/malicious-image/README.md) and [csse backdoor-docker-image](../../../../csse-course/ch3-attacking-container-supply-chain/labs/backdoor-docker-image/README.md).

## Steps

```text
.venv/Scripts/python devsecops-course/10-container-reconnaissance-and-attacks/labs/image-based-attacks/demo.py
.venv/Scripts/python -m pytest devsecops-course/10-container-reconnaissance-and-attacks/labs/image-based-attacks -v
```

1. Run the demo and read the first path.
2. Set `docker_sock` to False and the user to a non-root UID: how does the impact line change?
3. Close the exposed port: which path stops being reachable?
4. Why is the local-only flaw BACKLOG and not ignored?

## Expected output (real run)

```text
Secrets an attacker gets without running the image:
  image history      SERVICE_TOKEN          via: docker history --no-trunc IMAGE (no need to run it)
  /app/.git/config   credentials in a URL   via: docker save + tar, or docker cp from a stopped container

Exploit paths (vulnerable components):

[FIX NOW] FIXTURE-A1 in flask: reachable=True (component serves the exposed port)
    - entry: internet to port 8080
    - flaw: FIXTURE-A1 RCE in flask 1.0
    - privilege: code runs as root inside the container
    - pivot: mounted docker.sock lets that root start a host-level container
    - impact: host compromise

[FIX NOW] FIXTURE-A2 in pillow: reachable=True (component processes user input (image processing of user uploads))
    - entry: internet to port 8080
    - flaw: FIXTURE-A2 memory corruption in pillow 8.0
    - privilege: code runs as root inside the container
    - pivot: mounted docker.sock lets that root start a host-level container
    - impact: host compromise

[BACKLOG (not directly reachable)] FIXTURE-A4 in internal-metrics: reachable=False (needs a foothold inside the container first: a second step, not an entry point)
    - entry: existing foothold
    - flaw: FIXTURE-A4 RCE in internal-metrics 0.3
    - privilege: code runs as root inside the container
    - pivot: mounted docker.sock lets that root start a host-level container
    - impact: host compromise
```

## Think about it

CVSS alone is not priority. Reachability and blast radius decide order. A 9.8 in a library nobody can reach is below a 7.8 in the file parser that takes uploads.

## Run the real tool

`trivy image`, `grype`, `docker scout cves` (hedged), plus KEV and EPSS data for prioritisation. See [real-tools/recon-tools.md](../../real-tools/recon-tools.md).

> Hedged: real tools and flags change between versions. Verify at the source. Tests in this repo never need Docker.

## Tests

`8` tests in `test_dso_ch10_*.py`: `.venv/Scripts/python -m pytest devsecops-course/10-container-reconnaissance-and-attacks/labs/image-based-attacks`.
