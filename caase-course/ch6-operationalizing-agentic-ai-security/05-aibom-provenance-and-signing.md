# 05. AI/Agent Bill of Materials, Provenance and Signing

> **Chapter 6 · Time:** ~3 hours · **You will:** write an AIBOM for an agent harness, understand provenance tracking, and sign and verify a harness (HMAC twin plus real cosign commands).
> **Labs:** [aibom-harness](labs/aibom-harness/README.md), [sign-verify-harness](labs/sign-verify-harness/README.md)
> **Maps to:** OWASP Agentic ASI04 Agentic Supply Chain · OWASP LLM 2026 LLM04 Supply Chain [2025: LLM03] · SLSA, OWASP SCVS · NIST AI RMF MAP/GOVERN · Builds on [CAISP ch6 lesson 04 (SBOM, MLBOM, signing)](../../caisp-course/ch6-supply-chain-attacks-in-ai/04-transparency-and-integrity-sbom-mlbom-signing.md) and [cmcpse ch6 lesson 03](../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/03-transparency-and-integrity.md).

## 1. Why this matters

- An agent's behavior depends on **many things beyond code**: the model and provider version, system prompts, tools and their descriptions, MCP servers, skills, and policy files. Any of them can change silently.
- After an incident or a CVE you must answer "which deployed agents use this model, skill or MCP server?" in minutes. Only an inventory can do that.
- Regulators and customers increasingly ask for inventories and provenance (see [07](07-eu-ai-act-and-comparable-frameworks.md)).

## 2. Understand it

### 2.1 AI/Agent Bill of Materials (AIBOM)

An **AIBOM** is an SBOM extended to AI: models, datasets, prompts and agent components. Two common formats: **CycloneDX** (has a machine-learning-model component type and ML-BOM support; the lab uses the 1.6 shape) and **SPDX** (SPDX 3.0 added AI and dataset profiles). Check cyclonedx.org and spdx.dev for the current specification versions (verify at source).

For a harness, list:

| Component | Fields worth recording |
|---|---|
| Model | name, version, provider, licence, file hash if self-hosted, model card link |
| Tools | name, version, **description hash** (descriptions are attack surface) |
| MCP servers | name, version, transport, package URL (purl), hash |
| Skills / plugins | name, version, file hash |
| Prompts | name, version, hash |
| Libraries | name, version, purl |
| Relationships | harness depends on each of the above |

The lab's validator checks structure, pinned versions, 64-hex SHA-256 hashes, model licence presence, duplicate refs and dependency references, and its `diff()` highlights silent changes (a prompt edit or a model version swap). It does **not** replace validation against the official JSON schema: use CycloneDX tooling in CI.

### 2.2 Provenance tracking

**Provenance** answers "where did this come from and how was it built?" Build it from: signed **attestations** (SLSA provenance describes who built an artifact, from which source, with which builder), content hashes, a signed AIBOM stored with the release, and an **audit trail** of who approved what ([cmcpse provenance-attestations lab](../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/labs/provenance-attestations/README.md)). SLSA and SCVS are covered in [CAISP ch6 lesson 03](../../caisp-course/ch6-supply-chain-attacks-in-ai/03-supply-chain-frameworks-slsa-and-scvs.md).

### 2.3 Signing and verifying a harness

1. Build a canonical **manifest** (path to SHA-256) of the harness directory.
2. **Sign** it. Real tools: Sigstore **cosign** (`cosign sign-blob`, with a key pair or keyless using CI identity) and OpenSSF model signing for model files (check current status).
3. **Verify before run**: check the signature, check the key is trusted, then re-hash every file; reject modified, missing and **extra** files.
4. Never let the artifact pick its own algorithm; reject path tricks in the manifest.

The lab uses HMAC as a stand-in and prints the real commands (hedged; check `cosign --help` for your version):

```text
cosign generate-key-pair
cosign sign-blob --key cosign.key --bundle harness.bundle manifest.json
cosign verify-blob --key cosign.pub --bundle harness.bundle manifest.json
```

Why only a "twin": HMAC is symmetric, so anyone who can verify can also forge. Asymmetric signatures or keyless Sigstore identities fix that. Notebooks or the course's lab environment are the place to run real cosign.

## 3. Defend it

| Layer | Control | Type |
|---|---|---|
| Inventory | AIBOM generated in CI for every release; stored with the artifact | Hard |
| Pinning | No `latest`; hashes for prompts, skills, tool descriptions | Hard |
| Signing | Sign manifest and AIBOM; verify at deploy and at start | Hard |
| Provenance | Attestations from CI; protect the builder | Hard |
| Change control | AIBOM diff in review; approval for model or skill changes | Process |

**What does NOT work on its own:** an SBOM of Python packages only; a signature verified by a key that ships inside the artifact; verifying at build but not at run.

## 4. Hands-on

1. [aibom-harness](labs/aibom-harness/README.md): build and validate an AIBOM; break it five ways; diff two versions.
2. [sign-verify-harness](labs/sign-verify-harness/README.md): sign, then try modify, add, remove, forge and downgrade attacks.

## 5. Scenarios

1. *Which agents use this model?* A model version is found vulnerable. With AIBOMs you query all releases in minutes; without them you search servers by hand.
2. *Silent prompt edit.* A prompt file changes the agent's rules. The AIBOM diff shows the prompt hash changed; review catches it.
3. *Extra skill dropped in.* An attacker adds a skill file to a deployed harness. Verification fails with "unsigned extra file".

## 6. Interview questions

<details><summary><b>Q1. What does an AIBOM contain that a normal SBOM does not?</b></summary>
Models (with provider, version, licence, hashes), datasets, prompts, tools and their descriptions, MCP servers and skills, i.e. the behavior-defining components that are not code packages.
</details>

<details><summary><b>Q2. How do you sign and verify an agent harness?</b></summary>
Hash every file into a canonical manifest, sign the manifest (for example with cosign), and before running verify the signature against a trusted key, re-hash all files, and reject any modified, missing or extra file.
</details>

<details><summary><b>Q3. Why is HMAC only a teaching twin for cosign?</b></summary>
It is symmetric: verifiers hold the signing key and could forge signatures. Real signing is asymmetric (or keyless via identity), so verifiers only need a public key or identity policy.
</details>

## 7. Checklist

- [ ] Every release has an AIBOM, validated and signed.
- [ ] No floating versions; hashes for prompts, skills and tool descriptions.
- [ ] Verification happens at deploy time and at startup.

## 8. References

- CycloneDX (cyclonedx.org) ML-BOM; SPDX 3.0 AI profile; SLSA (slsa.dev); Sigstore/cosign docs; OpenSSF model signing: verify current versions.
- [CAISP ch6](../../caisp-course/ch6-supply-chain-attacks-in-ai/README.md), [cmcpse ch6](../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/README.md).
- Next: [06 NIST AI RMF, ASI controls and zero trust](06-nist-ai-rmf-asi-controls-and-zero-trust.md).
