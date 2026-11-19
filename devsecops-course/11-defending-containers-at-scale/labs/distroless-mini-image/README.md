# Lab: A secure, miniature image with distroless

**Course exercise:** "Build a Secure, Miniature Image With Distroless To Minimize Attack Footprint" [CCSE 4]. Lesson: [02 section 2](../../02-secure-images-linting-and-scanning.md#2-base-images-distroless-and-scratch).

**Time:** 25 minutes. **Safety:** fixture catalogue only.

**Link, do not repeat:** the multi-stage build itself (Dockerfile comparison, size and package numbers) is in [csse ch3 secure-mini-image](../../../../csse-course/ch3-attacking-container-supply-chain/labs/secure-mini-image/README.md). Do that lab first.

## What this adds

The csse lab shows *how* to build small. This one shows *why it matters* as a number: [surface.py](surface.py) scores each base image by what an attacker finds after getting code execution (packages, shell, package manager, curl/wget, known CVEs) and picks the smallest sufficient image.

## Steps

```text
.venv/Scripts/python devsecops-course/11-defending-containers-at-scale/labs/distroless-mini-image/demo.py
.venv/Scripts/python -m pytest devsecops-course/11-defending-containers-at-scale/labs/distroless-mini-image -v
```

1. Run it. Which image wins when you do not need a shell? Which when you do?
2. Add your own base image to [catalog.json](fixtures/catalog.json) with realistic numbers from `docker history` / `syft`.
3. The catch: no shell means no `docker exec -it ... sh`. How will you debug? (Ephemeral debug containers, `kubectl debug`, a debug variant tag.)

## Expected output (real run)

```text
   0  scratch + static binary        6 MB  pkgs=0   shell=False tools=[]
   3  distroless/static (example)    2 MB  pkgs=3   shell=False tools=[]
  51  alpine (example)               8 MB  pkgs=15  shell=True  tools=['apk', 'sh']
 171  debian:12-slim (example)      75 MB  pkgs=90  shell=True  tools=['apt', 'bash', 'sh']
 235  ubuntu:latest (example)       78 MB  pkgs=100 shell=True  tools=['apt', 'bash', 'curl', 'perl', 'sh']
pick (no shell needed): scratch + static binary
pick (shell needed)   : alpine (example)
```

## Run the real tool (hedged)

Distroless images (Google) and Chainguard-style minimal images exist for several languages; `scratch` works for static binaries (Go, Rust with musl). Check each project's current tags and support policy: verify at source.
