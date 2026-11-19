# Lab: Build a secure, miniature image to minimize attack footprint

**Course exercise:** "Build a secure, miniature image to minimize attack footprint". Lessons: [04 sections 3 and 4](../../04-securing-container-applications.md#3-distroless-and-scratch-images).

**Time:** 60 minutes. **Safety:** offline. The comparison uses **illustrative fixture numbers** in [fixtures/images.json](fixtures/images.json). They are teaching data, not measurements. Measure real images with Trivy or Grype.

## Files

- [compare.py](compare.py): ranks full, slim, alpine, distroless and scratch images with a simple attack-surface score (packages, CVEs by severity, shell, package manager, compiler, root, size).
- [examples/Dockerfile.bloated](examples/Dockerfile.bloated): the "before".
- [examples/Dockerfile.go-scratch](examples/Dockerfile.go-scratch) and [examples/Dockerfile.python-distroless](examples/Dockerfile.python-distroless): multi-stage "after" examples with pinned (fake) digests, numeric non-root `USER` and hash-checked pip.
- The linter is the [06 Dockerfile linter](../../../../06-ai-devsecops/docker/README.md), loaded by path.

## Steps

```text
.venv/Scripts/python csse-course/ch3-attacking-container-supply-chain/labs/secure-mini-image/demo.py
.venv/Scripts/python -m pytest csse-course/ch3-attacking-container-supply-chain/labs/secure-mini-image -v
```

1. Compare the table. Which factor drives the score most for the full image? (Packages and CVEs.) For slim? (The shell and package manager.)
2. Lint the three Dockerfiles. `Dockerfile.bloated` has six findings, the multi-stage ones none.
3. Write your own multi-stage Dockerfile for a small app and make the linter pass.
4. With real Docker and a real app (optional), build both and compare `docker images`, `trivy image` and `syft` package counts.

## Expected output (real run)

```text
image                             MB  pkgs  C+H shell  size   score
python:3.12 (full)              1020   410   44   yes  100%   770.0
python:3.12-slim                 140    95    6   yes   14%   193.5
alpine + python                   60    40    2   yes    6%   111.8
distroless python3                55    22    1    no    5%    28.8
scratch + static Go binary         9     0    0    no    1%     1.4

Dockerfile.bloated: 6 finding(s) ['DF-001', 'DF-002', 'DF-003', 'DF-008', 'DF-009', 'DF-012']
Dockerfile.go-scratch: 0 finding(s) []
Dockerfile.python-distroless: 0 finding(s) []
```

## Trade-offs to remember

No shell means debugging changes (ephemeral containers). Scratch needs a static binary plus CA certificates. Alpine uses musl. Pin by digest and rebuild often.
