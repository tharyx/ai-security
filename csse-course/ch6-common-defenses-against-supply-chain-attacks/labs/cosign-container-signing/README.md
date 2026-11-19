# Lab: Signing Container Images for Trust

**Course exercise:** "Signing Container Images for Trust". Lesson: [01-proving-integrity-with-cryptography.md](../../01-proving-integrity-with-cryptography.md#4-artifact-signing). Chapter guide: [README](../../README.md). Real-tool guides: [real-tools](../../real-tools/README.md).

**Time:** 60 minutes. **Tests:** 11, all offline. **Safety:** fixtures only; secrets are FAKE, domains are `.example`, advisory ids are fictional, nothing is downloaded or executed, and tests never need Docker, Kubernetes, a network or an account.

> **Outdated to current.** Named tool: **cosign (Sigstore) / Notation**. **Docker Content Trust (Notary v1) is retired**: shutdown of the Notary v1 service announced for 8 Dec 2026. Use cosign or Notation. Sigstore and Notation are actively maintained (verify versions).

## What the offline twin does

`image_signing.py` signs and verifies with an **HMAC and a FAKE key** (real tools use asymmetric keys or keyless certificates). It teaches: sign the **digest**, verify what the tag points to **now**, bind the repository identity, require **claims**, reject replay on another digest or repository, sign **attestations** (in-toto style statements) and pin **identity + issuer** for keyless certificates.

## Steps

```text
.venv/Scripts/python csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/cosign-container-signing/demo.py
.venv/Scripts/python -m pytest csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/cosign-container-signing -v
```

1. Run the demo, especially the 'tag repointed' line.
2. Run the tests; find the one that proves a signature cannot be copied to another image.
3. Explain why verifying only at build time is not enough.

## Expected output (real run)

```text
verify: (True, 'verified sha256:6bbd8b3a2e71...')
verify with wrong key: (False, 'no valid signature for sha256:6bbd8b3a2e71...')
required claim ok: True | wrong claim: False
after tag repoint: (False, 'no valid signature for sha256:a19b6159b9bc...')
attestation: {'builder': 'ci.example', 'source': 'repo.example@abc123'}
identity pinned: True
```

## Real-tool guide (hedged: verify commands against the current docs)

```text
# cosign with a key pair (verify current CLI syntax in the Sigstore docs)
cosign generate-key-pair                                     # creates cosign.key and cosign.pub; protect the private key
cosign sign --key cosign.key <registry>/<repo>@sha256:<digest>
cosign verify --key cosign.pub <registry>/<repo>@sha256:<digest>
# keyless (CI with an OIDC identity)
cosign sign <registry>/<repo>@sha256:<digest>
cosign verify <registry>/<repo>@sha256:<digest> \
  --certificate-identity "https://<ci-host>/<org>/<repo>/.workflows/release.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://<oidc-issuer>"
# attestations
cosign attest --predicate sbom.cdx.json --type cyclonedx <image>@sha256:<digest>
# Notation (Notary Project)
notation sign <registry>/<repo>@sha256:<digest>
notation verify <registry>/<repo>@sha256:<digest>
```
Needs a registry you control. For admission-time enforcement see Kyverno or Sigstore policy-controller (verify). Never paste private keys or tokens into chat or repositories.
