# Lab: Generate the SBOM for Docker Image using Syft

**Course exercise:** "Generate the SBOM for Docker Image using Syft". Lesson: [04-asset-inventory-and-sboms.md](../../04-asset-inventory-and-sboms.md#23-container-sbom). Chapter guide: [README](../../README.md). Real-tool guides: [real-tools](../../real-tools/README.md).

**Time:** 45 minutes. **Tests:** 8, all offline. **Safety:** fixtures only; secrets are FAKE, domains are `.example`, advisory ids are fictional, nothing is downloaded or executed, and tests never need Docker, Kubernetes, a network or an account.

> **Outdated to current.** Named tool: **Syft**. Syft is actively maintained. Verify the current release.

## What the offline twin does

`container_sbom.py` takes an **image filesystem listing fixture** (a dict of path to text), reads `/etc/os-release`, parses the **dpkg status** file (Debian-like) or the **apk installed** database (Alpine-like), also finds Python `dist-info` and npm `package.json` files, and emits CycloneDX with distro-aware purls.

## Steps

```text
.venv/Scripts/python csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/syft-container-sbom/demo.py
.venv/Scripts/python -m pytest csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/syft-container-sbom -v
```

1. Run the demo and compare the Debian-like and Alpine-like outputs.
2. In `IMAGE_FS`, mark `openssl` as `deinstall ok config-files` and confirm it disappears.
3. Why does the purl carry `distro=debian-12`? (Advisories are matched per distro release.)

## Expected output (real run)

```text
== debian-app: debian 12 -> 4 components
   pkg:deb/debian/libc6@2.36-9+deb12u7?arch=amd64&distro=debian-12
   pkg:deb/debian/openssl@3.0.13-1~deb12u1?arch=amd64&distro=debian-12
   pkg:npm/left-pad@1.3.0
   pkg:pypi/flask@3.0.3
== alpine-base: alpine 3.20.1 -> 2 components
   pkg:apk/alpine/busybox@1.36.1-r29?arch=x86_64&distro=alpine-3.20.1
   pkg:apk/alpine/musl@1.2.5-r0?arch=x86_64&distro=alpine-3.20.1
```

## Real-tool guide (hedged: verify commands against the current docs)

```text
docker pull <image>@sha256:<digest>            # pin by digest
syft <image>@sha256:<digest> -o cyclonedx-json=image.cdx.json
syft docker-archive:image.tar                  # or scan a saved image: docker save -o image.tar <image>
syft oci-dir:./layout -o table                 # an OCI layout directory
```
The learner laptop has little disk space: scan small images and delete them afterwards (`docker image rm`). Not needed for the tests.
