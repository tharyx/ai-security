# Real tool guide: cosign (Sigstore) and Notation (Notary Project)

> **Hedged guide.** Not run by the repo author for this guide. Flags and defaults change; follow docs.sigstore.dev and notaryproject.dev. Keyless signing needs internet access to Fulcio and Rekor and an OIDC identity. Use a **throwaway test registry and image**.

> **Status.** Docker Content Trust (Notary v1) is retired, with the notary.docker.io service scheduled to shut down on 8 Dec 2026 (verify at docs.docker.com). Do not start new work on it.

## cosign: key-based quick start (offline-friendly concepts)

```text
cosign generate-key-pair                      # makes cosign.key (encrypted) and cosign.pub
cosign sign --key cosign.key registry.example/team/app@sha256:<digest>
cosign verify --key cosign.pub registry.example/team/app@sha256:<digest>
```

Always sign and verify the **digest**, not a tag.

## cosign: keyless in CI (concept)

In GitHub Actions with OIDC (`id-token: write`), `cosign sign <image>@<digest>` obtains a short-lived certificate from Fulcio and logs to Rekor. Verify with identity and issuer:

```text
cosign verify \
  --certificate-identity-regexp "^https://github.com/ORG/REPO/.github/workflows/release.yml@refs/heads/main$" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  registry.example/team/app@sha256:<digest>
```

Pin Actions to commit SHAs in the same workflow (brief fact: mutable tags were abused in tj-actions/changed-files, CVE-2025-30066).

## Attestations (SBOM, provenance)

```text
cosign attest --key cosign.key --predicate sbom.cdx.json --type cyclonedx <image>@<digest>
cosign verify-attestation --key cosign.pub --type cyclonedx <image>@<digest>
```

See [CMCPSE provenance-attestations](../../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/labs/provenance-attestations/README.md) for the offline twin.

## Notation

```text
notation cert generate-test --default "test.example"        # test certificate only
notation sign registry.example/team/app@sha256:<digest>
notation verify registry.example/team/app@sha256:<digest>
```

Notation needs a **trust store** (CA certificates) and a **trust policy** file saying which registry scopes trust which identities. Plugins connect it to cloud key services (verify current plugin names).

## Enforce at admission

Kyverno `verifyImages`, Sigstore policy-controller, Ratify + Gatekeeper, or cloud-native policy: reject pods whose image has no valid signature from the expected identity. See [chapter 4 lesson 03](../../ch4-attacking-kubernetes-cluster-supply-chain/03-abusing-the-kubernetes-request-pipeline.md).

## Pitfalls

- A signature that is not checked at deploy time protects nothing.
- Verify the **signer identity**, not just that a signature exists.
- Protect signing keys (KMS or HSM) or prefer keyless.
- Signing does not mean "no vulnerabilities"; keep scanning.
- Plan key and certificate rotation and revocation.
