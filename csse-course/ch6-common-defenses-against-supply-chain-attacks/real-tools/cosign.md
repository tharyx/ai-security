# cosign (Sigstore) and Notation (hedged)

> **Docker Content Trust (Notary v1) is retired**: Docker announced on 29 Jul 2025 that the Notary v1 service shuts down on **8 Dec 2026**. Migrate to cosign or Notation. Both are actively maintained; verify the current CLI syntax in their docs.

## cosign: key-based

```text
cosign generate-key-pair                              # keep cosign.key private (KMS/HSM or a secret manager in real use)
cosign sign --key cosign.key <registry>/<repo>@sha256:<digest>
cosign verify --key cosign.pub <registry>/<repo>@sha256:<digest>
```

## cosign: keyless (OIDC identity from CI)

```text
cosign sign <registry>/<repo>@sha256:<digest>          # obtains a short-lived certificate; entry goes to a transparency log
cosign verify <registry>/<repo>@sha256:<digest> \
  --certificate-identity "<exact signer identity URL>" \
  --certificate-oidc-issuer "<issuer URL>"
```

Public transparency means signing identities and image names may be visible publicly: check privacy needs (a private Sigstore deployment exists for that).

## Attestations (SBOM, provenance)

```text
cosign attest --predicate sbom.cdx.json --type cyclonedx <image>@sha256:<digest>
cosign verify-attestation --type cyclonedx <image>@sha256:<digest> --certificate-identity ... --certificate-oidc-issuer ...
```

## Notation (Notary Project)

```text
notation cert add --type ca --store <name> ca.crt     # trust store (check current subcommands)
notation sign <registry>/<repo>@sha256:<digest>
notation verify <registry>/<repo>@sha256:<digest>      # needs a trust policy file
```

## Enforcing at deploy time

Verification must happen where the image is used: Kubernetes admission (Kyverno `verifyImages`, Sigstore policy-controller, Ratify with Gatekeeper) or the deploy job. Check each project's docs.

## Rules

1. Sign and verify **digests**, not tags.
2. Pin the expected **signer identity and issuer**.
3. Only the release pipeline on protected branches may sign.
4. Rotate and protect keys; prefer keyless or KMS-backed keys.

Lab: [cosign-container-signing](../labs/cosign-container-signing/README.md). Concepts: [lesson 01](../01-proving-integrity-with-cryptography.md).
