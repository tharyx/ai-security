# Lab: Create an SBOM with Tern

**Course exercise:** "Create an SBOM with Tern". Lesson: [04-asset-inventory-and-sboms.md](../../04-asset-inventory-and-sboms.md#23-container-sbom). Chapter guide: [README](../../README.md). Real-tool guides: [real-tools](../../real-tools/README.md).

**Time:** 40 minutes. **Tests:** 7, all offline. **Safety:** fixtures only; secrets are FAKE, domains are `.example`, advisory ids are fictional, nothing is downloaded or executed, and tests never need Docker, Kubernetes, a network or an account.

> **Outdated to current.** Named tool: **Tern**. **Check the Tern repository's maintenance status before relying on it.** Maintained alternatives: Syft and cdxgen (which also report which layer a package came from).

## What the offline twin does

`layer_sbom.py` models an image as layers, each with a package snapshot. It computes **per-layer added, removed and changed packages**, attributes each final package to the layer (and Dockerfile instruction) that introduced its current version, separates base-image packages from yours, and finds packages **removed in a later layer but still present in history**.

## Steps

```text
.venv/Scripts/python csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/tern-layer-sbom/demo.py
.venv/Scripts/python -m pytest csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/tern-layer-sbom -v
```

1. Run the demo and read the layer report.
2. Which layer upgraded `openssl`? Which command caused it? Who owns fixing a vulnerable base package? (The base image: rebuild on a newer base.)
3. Add a layer that installs `wget` and confirm it is attributed to your layer.

## Expected output (real run)

```text
sha256:l1 [base] FROM debian:12-slim (base)
   + {'libc6': '2.36-9+deb12u7', 'bash': '5.2.15-2+b7'} -  {} ~ {}
sha256:l2 [yours] RUN apt-get update && apt-get install -y curl openssl
   + {'curl': '7.88.1-10+deb12u5', 'openssl': '3.0.13-1~deb12u1'} -  {} ~ {}
sha256:l3 [yours] RUN apt-get install -y --only-upgrade openssl && apt-get purge -y curl
   + {} -  {'curl': '7.88.1-10+deb12u5'} ~ {'openssl': ('3.0.13-1~deb12u1', '3.0.14-1~deb12u1')}
sha256:l4 [yours] COPY . /app (no package manager)
   + {} -  {} ~ {}
attribution: {'libc6': 'sha256:l1', 'bash': 'sha256:l1', 'openssl': 'sha256:l3'}
base vs added: {'from_base_image': ['bash', 'libc6'], 'added_by_you': ['openssl']}
layers with no package change: ['sha256:l4']
removed later but still in history: ['curl']
```

## Real-tool guide (hedged: verify commands against the current docs)

```text
# Tern (if the project is still maintained for your use; verify first)
pip install tern                       # check the project's current install instructions
tern report -i <image>:<tag> -f json -o tern-report.json
tern report -f cyclonedx -i <image>:<tag> -o tern.cdx.json     # check supported formats in your version
```
Alternative with layer information: `syft <image> -o json` includes the layer id of each package (`locations[].layerID`). Verify the field names in your Syft version.
