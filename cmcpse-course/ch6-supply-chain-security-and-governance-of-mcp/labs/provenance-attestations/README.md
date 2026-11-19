# Lab: Provenance Attestations for an MCP Server CI/CD Pipeline

**Course exercise:** "Create provenance attestations for an MCP server CI/CD pipeline". Lessons: [03 transparency (provenance)](../../03-transparency-and-integrity.md#3-provenance-and-attestations-for-mcp-server-builds), [04 SLSA](../../04-supply-chain-frameworks.md#1-slsa-for-mcp-builds). Related: [ch5 mcp-cicd-pipeline](../../../ch5-devsecops-for-mcp-security/labs/mcp-cicd-pipeline/README.md) (where this step would run) and the [signing lab](../sign-verify-mcp-build/README.md).

**Time:** 45 minutes. Offline. The key, builder id and repository are fictional (`ci.example.internal`).

## What it builds

1. **`make_statement`**: an **in-toto Statement v1** whose predicate is **SLSA provenance v1**: `subject` (artifact name + sha256), `buildDefinition` (build type, repository, ref, workflow, `resolvedDependencies` with the source commit and pinned materials) and `runDetails` (builder id, invocation id).
2. **`sign_statement`**: a **DSSE envelope** (`payloadType`, base64 `payload`, `signatures`). The HMAC covers the **PAE** (Pre-Authentication Encoding) of the type and payload, so changing the type invalidates the signature.
3. **`deploy_gate`**: verifies and then enforces policy.

| Gate check | Stops |
|---|---|
| Signature valid for a trusted key | Forged statements |
| Artifact digest equals a `subject` digest; every deployed artifact is covered | Artifact swapped after the build; replayed old attestations |
| **Builder id** is on the allowlist | A build on a laptop or an unknown runner |
| **Repository** equals the expected repo | A build from a fork or a look-alike repo |
| **Ref** is allowed (for example `refs/heads/main`) | Release builds from feature branches |
| **Workflow** path is allowed | A modified pipeline file producing "official" artifacts |
| Every material has a digest | Unpinned inputs |

## Steps

```text
.venv/Scripts/python cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/labs/provenance-attestations/demo.py
.venv/Scripts/python -m pytest cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/labs/provenance-attestations -v
```

1. Run the demo. Read the statement fields and map them to SLSA's "who built what, from where".
2. Add a check that the **commit** is on a protected branch (hint: in real life ask the git host; here pass a set of allowed commits).
3. Chain the labs: build artifact → [SBOM](../sbom-mcp-server/README.md) → statement that lists the SBOM digest as a material → [signed bundle](../sign-verify-mcp-build/README.md) → this gate. Draw the data flow.
4. Which SLSA build level does this pipeline reach? (Hint: the HMAC key sits where? Can a build step read it? That is the L2 versus L3 question.)

## Expected output (real run)

```text
{
 "_type": "https://in-toto.io/Statement/v1",
 "predicateType": "https://slsa.dev/provenance/v1"
}
subject: [{'name': 'notes-mcp-1.2.0.tar', 'digest': {'sha256': 'e442736bd952a9c3fba7e699f4f1b3ae7b1c01c8c960337caed7107baf82b666'}}]
builder: https://ci.example.internal/builders/mcp-release@v1
envelope keys: ['payloadType', 'payload', 'signatures'] | payloadType: application/vnd.in-toto+json

-- gate: good build: GateResult(ok=True, reasons=[])
-- gate: artifact swapped after the build: ['artifact notes-mcp-1.2.0.tar does not match the attested digest']
-- gate: built from a fork: ['built from https://git.example.internal/mallory/notes-mcp, expected https://git.example.internal/acme/notes-mcp']
-- gate: built on an unknown builder: ['builder https://laptop.example/builder is not trusted']
-- gate: forged statement (attacker key): ['no valid signature from a trusted key']
```

## Optional: real tooling (hedged, NOT executed by the repo author)

Options change quickly; check each project's documentation.

- **GitHub:** the `actions/attest-build-provenance` action creates a Sigstore-signed provenance attestation in a workflow; `gh attestation verify <file> --repo <owner/repo>` verifies it.
- **SLSA GitHub generator** (slsa-framework/slsa-github-generator) produces SLSA provenance for builds, and `slsa-verifier` verifies it.
- **cosign:** `cosign attest-blob --predicate provenance.json --type slsaprovenance1 --bundle out.json <file>` and `cosign verify-blob-attestation ...` (flags and type names vary by version; verify).

## Limits

An attestation is only as trustworthy as the platform that produced it. A statement signed by a compromised builder is a well-signed lie. HMAC is a stand-in for asymmetric or keyless signing. The lab's policy has no transparency log and no key rotation.
