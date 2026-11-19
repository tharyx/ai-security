# Lab: Signing container images for trust

**Course exercise:** "Signing Container Images for Trust" [CCSE 4]. Lesson: [04 section 1](../../04-trust-registries-and-cicd.md#1-content-trust-and-integrity-checks-dct-is-retired).

**Time:** 30 minutes. **Safety:** HMAC simulation with a test key. It is **not** real cosign or Notation.

**Link, do not repeat:** real signing walk-through is [csse ch6 cosign-container-signing](../../../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/cosign-container-signing/README.md) and the guide [real-tools/cosign-notation.md](../../../../csse-course/ch3-attacking-container-supply-chain/real-tools/cosign-notation.md).

> **Outdated:** Docker Content Trust (Notary v1) is retired (announced July 2025, service shutdown planned December 2026: verify at source). Use cosign or Notation.

## What it models

[sign_verify.py](sign_verify.py): sign the **digest** (not the tag), keep the signature with the image, and at deploy time (1) resolve the tag to a digest, (2) recompute the digest from the manifest, (3) require a valid signature from an **allowed signer**. The demo shows four failures: tag re-pointed to a backdoored image, tampered manifest, wrong key, signer not allowed.

## Steps

```text
.venv/Scripts/python devsecops-course/11-defending-containers-at-scale/labs/sign-container-images/demo.py
.venv/Scripts/python -m pytest devsecops-course/11-defending-containers-at-scale/labs/sign-container-images -v
```

1. Run the four cases. Why does re-pointing the tag fail even though the old signature is still in the registry?
2. Why sign digests? (Tags are mutable pointers; a digest is a content hash.)
3. Real cosign keyless signing replaces the long-lived key with a short-lived certificate tied to an identity and logs to a transparency log: what problem of this HMAC demo does that remove? (Key custody.)

## Expected output (real run)

```text
1 signed image      : (True, 'verified sha256:2dde90901709... signed by ci@example.invalid')
2 tag re-pointed    : (False, 'no valid signature from an allowed signer')
3 manifest tampered : (False, 'manifest does not match its digest (tampered content)')
4 untrusted signer  : (False, 'no valid signature from an allowed signer')
```

## Run the real tool (hedged)

```text
cosign sign --key cosign.key registry.example.invalid/shop/api@sha256:<digest>
cosign verify --key cosign.pub registry.example.invalid/shop/api@sha256:<digest>
notation sign registry.example.invalid/shop/api@sha256:<digest>
```

Then enforce at admission (Kubernetes policy controllers) or in the registry. Flags and keyless defaults change: verify at source.
