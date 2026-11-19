# Lab: Use third-party tools for image inspection

**Course exercise:** "Use Third-party Tools for Image Inspection". Lessons: [01 recon, third-party tools](../../01-container-reconnaissance.md#9-attack-surface-analysis-with-third-party-tools).

**Time:** 60 minutes. **Safety:** Layer fixtures. Secret-like values are canaries built at runtime from pieces.

## What it models

A **Dive-like** layer inspector (final file view with whiteouts, **efficiency score**, wasted bytes per layer), a **secret finder** that scans every layer including files deleted later, and a **Trivy/Grype-like** package check against a fixture vulnerability list (fake IDs).

## Steps

```text
.venv/Scripts/python devsecops-course/10-container-reconnaissance-and-attacks/labs/recon-third-party-image-inspection/demo.py
.venv/Scripts/python -m pytest devsecops-course/10-container-reconnaissance-and-attacks/labs/recon-third-party-image-inspection -v
```

1. Run the demo: which layer wastes the most space?
2. Where is the key that `RUN rm` deleted? (Still in layer 2.)
3. Fix the Dockerfile story: how would you avoid both problems? (Multi-stage plus BuildKit secret mounts.)
4. On a lab machine compare with `dive IMAGE` and `trivy image IMAGE`.

## Expected output (real run)

```text
Image shop/api:1.4: total 71,874,280 B, visible 38,874,080 B, wasted 33,000,200 B, efficiency 54.1%
  layer 0:  30,120,000 B  wasted           0 B  FROM debian:12-slim
  layer 1:  25,250,000 B  wasted  25,000,000 B  RUN apt-get update && apt-get install -y curl
  layer 2:         280 B  wasted         200 B  COPY secrets/ /app/secrets/
  layer 3:   8,004,000 B  wasted   8,000,000 B  COPY . /app
  layer 4:           0 B  wasted           0 B  RUN rm -rf /var/lib/apt/lists/* /app/secrets
  layer 5:   8,500,000 B  wasted           0 B  COPY data-v2.bin /app/data.bin

Secrets (found in layers, even the ones deleted later):
  layer 2 /app/secrets/id_key    private key block    DELETED later but still in layer
  layer 2 /app/.env              fake token           still in final fs

Vulnerable packages (fixture DB):
  CRITICAL  libwebp 1.2.0 < 1.3.2  (FIXTURE-0002)
  HIGH      openssl 3.0.9 < 3.0.13  (FIXTURE-0001)
```

## Think about it

Why is an efficiency score a security metric? (Wasted layers are where deleted secrets and old packages hide.)

## Run the real tool

See [real-tools/recon-tools.md](../../real-tools/recon-tools.md): `dive`, `trivy image`, `grype`, `syft`.

> Hedged: real tools and flags change between versions. Verify at the source. Tests in this repo never need Docker.

## Tests

`7` tests in `test_dso_ch10_*.py`: `.venv/Scripts/python -m pytest devsecops-course/10-container-reconnaissance-and-attacks/labs/recon-third-party-image-inspection`.
