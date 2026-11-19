# 03. Transparency and Integrity: SBOM, Provenance, Signing, Cards and Verification

> **Syllabus:** Transparency and Integrity in the MCP Supply Chain: generating SBOMs for MCP servers, provenance and attestations for MCP server builds, MCP server signing (concepts and implementation), Model Cards and MLBOMs in agentic contexts, verifying integrity of third-party MCP servers before deployment.
> **Time:** 3 hours. **Labs:** [`sbom-mcp-server`](labs/sbom-mcp-server/README.md), [`provenance-attestations`](labs/provenance-attestations/README.md), [`sign-verify-mcp-build`](labs/sign-verify-mcp-build/README.md). **General background:** [CAISP ch6 lesson 04](../../caisp-course/ch6-supply-chain-attacks-in-ai/04-transparency-and-integrity-sbom-mlbom-signing.md) with its [sbom-and-mlbom](../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/sbom-and-mlbom/) and [model-signing](../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/model-signing/) labs.

## 1. Four documents, four questions

| Document | Question it answers | Lab |
|---|---|---|
| **SBOM** | *What is in this server?* (components, versions, licenses) | `sbom-mcp-server` |
| **Provenance / attestation** | *Where, how and by whom was it built?* | `provenance-attestations` |
| **Signature** | *Is this exactly what the publisher released, and who is the publisher?* | `sign-verify-mcp-build` |
| **Model card / BOM / server card** | *What does it do, with what data and limits?* | discussion in section 5 |

They fit together: the signature protects the artifact **and** the attestation; the attestation points at the artifact digest and lists the source and builder; the SBOM lists the content.

## 2. Generating SBOMs for MCP servers

A **Software Bill of Materials** is a machine-readable inventory of components. Common formats: **CycloneDX** (OWASP) and **SPDX** (Linux Foundation, ISO/IEC 5962). Generate from the **lock file or the built image**, not from memory.

| Ecosystem | Example tools (verify current) |
|---|---|
| Python | `cyclonedx-py`, `pip-audit` (can output CycloneDX), Syft |
| Node | `@cyclonedx/cyclonedx-npm`, `npm sbom`, Syft |
| Containers | Syft, Trivy, Docker Scout |
| Many | cdxgen |

MCP-specific content worth adding (lab conventions, not standards): the **transport**, the **list of tools** and the **hash of the tool manifest**, the **launch command**, the **required credentials and scopes**. This lets a reviewer see "what is this server and what can it do" next to "what is in it".

What to do with an SBOM: store it with the release, sign it, compare it between versions (a **new dependency** or **new maintainer** is a review trigger), feed it to the vulnerability scanner, and answer "which of our servers use `h11` version X?" in minutes when an advisory lands.

Lab: [`sbom-mcp-server`](labs/sbom-mcp-server/README.md) generates a CycloneDX 1.5 shaped SBOM from a lock file and **analyzes** it: known vulnerabilities from a local advisory file, license policy, unpinned and unhashed components, registry allowlist, transitive depth, and a risk score.

## 3. Provenance and attestations for MCP server builds

**Provenance** is a signed statement about a build: *this artifact (digest) was built by this builder from this source (repo, commit) with these inputs.* An **attestation** is any signed statement about an artifact (provenance, a vulnerability scan result, an SBOM, a review).

Standard shapes (verify versions at the sources):

- **in-toto Statement** (v1): `_type`, `subject` (artifact names and digests), `predicateType`, `predicate`.
- **SLSA provenance** predicate (v1): `buildDefinition` (build type, external parameters such as repository and ref, resolved dependencies with digests) and `runDetails` (builder id, metadata).
- **DSSE envelope:** `payloadType`, base64 `payload`, `signatures`. The signature covers a Pre-Authentication Encoding of the type and payload, so the type cannot be swapped.

A trimmed example, as the lab produces it:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{"name": "notes-mcp-1.2.0.tar", "digest": {"sha256": "e442..."}}],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://ci.example.internal/mcp-build/v1",
      "externalParameters": {"repository": "https://git.example.internal/acme/notes-mcp", "ref": "refs/heads/main", "workflow": ".ci/release.yml"},
      "resolvedDependencies": [{"uri": "git+https://...@refs/heads/main", "digest": {"gitCommit": "9f2c..."}}]
    },
    "runDetails": {"builder": {"id": "https://ci.example.internal/builders/mcp-release@v1"}, "metadata": {"invocationId": "run-4711"}}
  }
}
```

**What the consumer checks (the "deploy gate"):** signature valid and from a trusted key or identity; the artifact digest matches a `subject`; the **builder id** is on the trust list; the **source repository** is the expected one (so a build from a fork fails); the **ref** is allowed (release branch or tag); the build **workflow** is the expected file; all materials are pinned by digest. The lab's `deploy_gate` does exactly these checks and has a test for each.

Real tooling (examples; verify): GitHub Artifact Attestations and `actions/attest-build-provenance`, the SLSA GitHub generator, `cosign attest`/`cosign verify-attestation`, `gh attestation verify`, in-toto tooling, Tekton Chains, GUAC for aggregating metadata. An attestation is only as strong as the **build platform that created it**: a self-hosted laptop builder produces a signed statement with little value.

Lab: [`provenance-attestations`](labs/provenance-attestations/README.md).

## 4. MCP server signing: concepts and implementation

**Concept.** A digital signature binds a publisher identity to a digest. Verifying it proves integrity (not changed) and authenticity (made by the key holder). It does **not** prove the code is benign: a signed backdoor is still a backdoor. Signing answers "is this what the publisher released?"; vetting answers "should we run it?".

**Key models.**

| Model | How | Trade-off |
|---|---|---|
| Long-lived keys (GPG, minisign, cosign key pair, KMS key) | You hold and rotate a private key | You must protect and rotate it |
| **Keyless (Sigstore)** | Short-lived certificate from Fulcio tied to an OIDC identity (for example a CI workflow); signing event recorded in the Rekor transparency log | No long-lived key to steal; verification checks *identity and issuer* and the log |
| Platform attestations | The CI platform signs for you | Trust in the platform |

**Practical commands.** *(Not executed by the repo author; flags and defaults change between releases, so check `cosign --help` and the Sigstore docs for your version.)*

```text
# Sign a build artifact (keyless, interactive or CI OIDC); writes a bundle with signature + certificate + log entry
cosign sign-blob --yes --bundle notes-mcp-1.2.0.tar.sigstore.json notes-mcp-1.2.0.tar

# Verify: require the EXPECTED identity and issuer, not just "some valid signature"
cosign verify-blob \
  --bundle notes-mcp-1.2.0.tar.sigstore.json \
  --certificate-identity "https://github.com/acme/notes-mcp/.github/workflows/release.yml@refs/tags/v1.2.0" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  notes-mcp-1.2.0.tar

# Containers: sign and verify an image by digest
cosign sign ghcr.io/acme/notes-mcp@sha256:<digest>
cosign verify ghcr.io/acme/notes-mcp@sha256:<digest> --certificate-identity ... --certificate-oidc-issuer ...
```

**Models:** the **OpenSSF Model Signing (OMS)** project defines a way to sign ML model files (v1.0 released in 2025), supporting keys, certificates or Sigstore keyless signing, and uses the Sigstore bundle format. If your MCP deployment ships model files (for example a local embedding model or classifier used by the server), sign them the same way. See [CAISP ch6 lesson 04](../../caisp-course/ch6-supply-chain-attacks-in-ai/04-transparency-and-integrity-sbom-mlbom-signing.md#5-model-signing). *(Check the project's current CLI: `model_signing` Python package, verify.)*

**Where signing helps in MCP today (honest view).** Most MCP servers in the wild are **not signed**. Signing helps when *you* build or mirror the server and sign it in your pipeline, then verify at deploy. For third-party servers, ask: does the publisher provide signatures or provenance (npm provenance, PyPI attestations, signed container images)? If not, **you** become the builder: build from a reviewed, pinned source in your pipeline and sign that. Do not assume the host verifies signatures for you; check what your host does.

**The offline twin.** [`sign-verify-mcp-build`](labs/sign-verify-mcp-build/README.md) signs a build manifest (file digests) with an **HMAC** key and verifies it at deploy: signature, every file re-hashed, no extra files, expected name, no rollback. It detects changed, added and deleted files, forged manifests, wrong keys and rollbacks. A test shows the HMAC limitation: whoever can verify can also forge, which is why real signing uses asymmetric keys.

## 5. Model cards and MLBOMs in agentic contexts

- A **model card** documents a model: intended use, training data overview, evaluations, limitations. An **ML-BOM** (for example CycloneDX's ML capability) is a machine-readable inventory of model, datasets and dependencies. See [CAISP ch6 lesson 04, section 4](../../caisp-course/ch6-supply-chain-attacks-in-ai/04-transparency-and-integrity-sbom-mlbom-signing.md) and [07 lesson 05](../../07-ai-governance/05-model-cards-data-documentation-and-transparency.md).
- **In agentic systems the unit is bigger than a model.** An agent is a model **plus tools, prompts, memory, policies and servers**. So you need documentation for: the model(s) used (card/MLBOM), the **tools and servers** the agent can call, the **permissions** granted, and the **data flows** between them.
- **Server card / agent card idea (hedged).** The pattern appears in two places: (1) the Agent2Agent (A2A) protocol uses an **Agent Card**, a JSON description of an agent's identity, capabilities and endpoints; (2) the MCP community has discussed machine-readable **server metadata** (a "server card" or well-known discovery document) describing a server's identity, tools and auth requirements (verify the current state of these proposals; they were evolving). The **security value** of such a card: a client or gateway can compare *declared* capabilities with *observed* behavior, pin the card hash, and refuse a server whose card changed without approval. The **risk**: the card is self-asserted, so treat it like a description (untrusted text, can be poisoned) unless it is signed and verified.
- **A practical "MCP BOM" for your organization** (lab-style, not a standard): server name and version; publisher; source and build provenance; SBOM reference; tool list with description hashes; transport and bind address; credentials and scopes; data classes touched; model(s) invoked if any (with their cards); approval and review dates; owner. This is the inventory entry from [lesson 02](02-vetting-third-party-mcp-servers.md) and a governance record for [lessons 05 and 06](05-ai-governance-frameworks.md).

## 6. Verifying integrity of third-party MCP servers before deployment

A pre-deployment verification checklist. Stop at the first failure.

1. **Identity:** the package name and publisher are the expected ones (namespace, repo link both ways).
2. **Version and digest:** exact version pinned; digest (or lock hash) matches what you vetted.
3. **Signature / attestation:** verify if the publisher provides one: expected identity and issuer, not just "valid". Otherwise rebuild from source in your pipeline and sign your build.
4. **SBOM:** generate or obtain; no unexpected new dependency or maintainer; no known critical vulnerabilities.
5. **Diff versus the approved version:** code and tool metadata ([backdoor lab](labs/backdoor-mcp-package/README.md)).
6. **Behavior test in a sandbox:** canary data, recording network, expected tool behavior only.
7. **Description scan and pinning:** [ch5 pipeline](../ch5-devsecops-for-mcp-security/labs/mcp-cicd-pipeline/README.md).
8. **Runtime constraints ready:** container/sandbox, egress allowlist, scoped credentials, gateway policy.
9. **Registered** in the inventory with an owner and a review date.

## 7. Interview questions

- *What is the difference between an SBOM and provenance?* An SBOM lists what is inside; provenance says where, how and by whom it was built.
- *Why does cosign keyless verification need `--certificate-identity` and the OIDC issuer?* Without them any validly signed artifact passes, including one signed by an attacker's own identity.
- *Does a valid signature mean the MCP server is safe?* No. It means unchanged and from the key/identity holder. It says nothing about intent.
- *What is the "server card" idea?* Machine-readable metadata about a server or agent that lets clients check declared against observed behavior; it needs signing and pinning because it is self-asserted (verify the current proposals).

## 8. References

- [CAISP ch6 lesson 04](../../caisp-course/ch6-supply-chain-attacks-in-ai/04-transparency-and-integrity-sbom-mlbom-signing.md); [CAISP model-signing lab](../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/model-signing/test_model_sign.py).
- CycloneDX (cyclonedx.org), SPDX (spdx.dev), in-toto (in-toto.io), SLSA (slsa.dev), Sigstore (sigstore.dev), OpenSSF Model Signing (verify current pages).
