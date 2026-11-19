# Lab: Dive and Dockle forensics

**Course topic:** "Docker Tools, Techniques, and Tactics: Dive (Forensic), Dockle" [CCSE 4]. Lesson: [04 section 5](../../04-trust-registries-and-cicd.md#5-tools-techniques-and-tactics-dive-and-dockle).

**Time:** 45 minutes. **Safety:** a JSON image fixture; the "secret" is a canary.

**Link, do not repeat:** extraction of secrets from real images is in [csse ch3 backdoor-docker-image](../../../../csse-course/ch3-attacking-container-supply-chain/labs/backdoor-docker-image/README.md) and [malicious-image](../../../../csse-course/ch3-attacking-container-supply-chain/labs/malicious-image/README.md); layer-based SBOM in [tern-layer-sbom](../../../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/tern-layer-sbom/README.md).

## The key idea

An image is a stack of layers. `RUN rm /app/.env` does **not** remove the file: a whiteout marker hides it in the final filesystem, but the earlier layer still contains it. Anyone who pulls the image can extract it. [layer_forensics.py](layer_forensics.py) finds that, scores wasted bytes like Dive's "efficiency", and runs a Dockle-like checklist (non-root user, HEALTHCHECK, setuid files, `ADD`, secrets in `ENV`, sudo, apt cache). Dockle ids shown are the commonly cited ones: verify at source.

DBA analogy: `DELETE` without `VACUUM`/redaction: the row is gone from queries, not from the datafile.

## Steps

```text
.venv/Scripts/python devsecops-course/11-defending-containers-at-scale/labs/dive-dockle-forensics/demo.py
.venv/Scripts/python -m pytest devsecops-course/11-defending-containers-at-scale/labs/dive-dockle-forensics -v
```

1. Run on [image_leaky.json](fixtures/image_leaky.json). Which layer added the secret, which "removed" it?
2. Compare with [image_clean.json](fixtures/image_clean.json): no leak, 100% efficiency, no Dockle findings.
3. Fix the real problem: never COPY the secret (BuildKit `--mount=type=secret`), then rotate it. Deleting is not fixing.

## Expected output (real run)

```text
== image_leaky.json
  deleted-but-present: app/.env added in L2, removed in L3, content='DB_PASSWORD=canary-hunter2-not-real'
  secret in L2 (ADD secrets.env /app/.env): app/.env in_final_image=False
  dive-style efficiency: 99.7% (4060 wasted bytes)
  dockle WARN  CIS-DI-0001: Last user should not be root
  dockle INFO  CIS-DI-0005: Enable Content trust (retired DCT: prefer cosign/Notation verification)
  dockle WARN  CIS-DI-0006: Not found HEALTHCHECK statement
  dockle WARN  CIS-DI-0008: setuid/setgid files: usr/bin/sudo
  dockle WARN  CIS-DI-0009: Use COPY instead of ADD
  dockle FATAL CIS-DI-0010: Secrets in ENV: API_TOKEN
  dockle WARN  DKL-DI-0001: Avoid sudo command
  dockle INFO  DKL-DI-0005: Clear apt-get caches
== image_clean.json
  dive-style efficiency: 100.0% (0 wasted bytes)
```

## Run the real tool (hedged)

```text
dive registry.example.invalid/shop/web:2.0
dockle registry.example.invalid/shop/web:2.0
docker history --no-trunc registry.example.invalid/shop/web:2.0
docker save registry.example.invalid/shop/web:2.0 -o web.tar   # then inspect layer tarballs
```

CI mode: `CI=true dive IMAGE` fails below an efficiency threshold; `dockle --exit-code 1 --exit-level warn IMAGE`. Verify flags at source. Use only on images you are allowed to inspect.
