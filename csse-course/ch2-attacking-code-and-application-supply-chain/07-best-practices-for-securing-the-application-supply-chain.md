# Lesson 07: Best Practices for Securing the Application Supply Chain

> **Chapter:** 2 · Attacking Code and Application Supply Chain · **Time:** ~5 hours
> **You will:** explain and apply six practices (SBOMs, code and commit signing, artifact signing, dependency hashing, dependency pinning, pinning GitHub Actions), and say what each one does and does not prove.

| | |
|---|---|
| **Prerequisites** | Lessons [01](01-introduction-to-the-code-supply-chain.md) to [04](04-attacks-on-build-and-cicd-systems.md) |
| **Labs** | [git-commit-signing](labs/git-commit-signing/README.md) · [dependency-confusion](labs/dependency-confusion/README.md) (hash lock) · [codecov-attack](labs/codecov-attack/README.md) · [sca](labs/sca/README.md) |
| **Related** | [CAISP ch6 sbom-and-mlbom](../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/sbom-and-mlbom/) · [CMCPSE ch6 sbom-mcp-server](../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/labs/sbom-mcp-server/) · [sign-verify-mcp-build](../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/labs/sign-verify-mcp-build/) · [provenance-attestations](../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/labs/provenance-attestations/) · [CAASE ch6 sign-verify-harness](../../caase-course/ch6-operationalizing-agentic-ai-security/) · [06 CI/CD workflow_lint](../../06-ai-devsecops/cicd/README.md) |
| **Syllabus lines** | Best practices for securing application supply chain · SBOMs · Code Signing and Commit Signing · Artifact Signing · Dependency Hashing · Dependency Pinning · Defending GitHub Actions With Pinning |

> **Safety.** Offline, with ephemeral keys and fake data. Tool names and options change: **verify at the source**.

## Why this matters

Every attack in lessons 02 to 06 broke a trust decision that nobody **verified**. These practices make the verification cheap and automatic: know **what** is in your software (SBOM), know **who** made it (signing), know **it is the same bytes** you reviewed (hashes, pinning).

## 1. SBOMs

A **Software Bill of Materials** is a machine-readable inventory of the components in a piece of software: names, versions, suppliers, hashes, licenses and relationships. It answers "are we affected?" in minutes when a new vulnerability appears (the Log4Shell lesson), and supports license and supplier review.

| Topic | Notes (verify the latest) |
|---|---|
| Formats | **CycloneDX** (also standardized as ECMA-424) and **SPDX** (3.0 is current) |
| Minimum elements | NTIA (2021) set a baseline (supplier, component name, version, other identifiers, dependency relationships, author, timestamp). CISA proposed an update in 2025. |
| Generate | at **build time** from the lock file or build graph (more accurate), or by scanning the artifact or image (Syft, Trivy, cdxgen) |
| Use | match against vulnerability databases (osv-scanner, Grype, Trivy), license checks, incident search |
| **VEX** (Vulnerability Exploitability eXchange) | says whether a known vulnerability **actually affects** your product, to cut noise |
| Policy | US Executive Order 14028 (2021) and the CISA attestation form drove SBOM adoption; the EU Cyber Resilience Act also expects SBOM-style documentation (verify dates) |

**An SBOM is an inventory, not a guarantee.** It can be wrong or stale, and it does not prove the components are safe. Sign it and attach it to the artifact so it can be trusted.

Labs and links: the [SCA lab](labs/sca/README.md) consumes a lock file as a mini inventory; the [CAISP SBOM and MLBOM lab](../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/sbom-and-mlbom/) shows an SBOM and its AI extension. Real tools: [real-tools/osv-scanner-and-syft.md](real-tools/osv-scanner-and-syft.md).

## 2. Code Signing and Commit Signing

**Commit signing** attaches a cryptographic signature to a git commit (or tag). Verifiers check the signature against keys they trust, so author spoofing fails ([git-commit-spoofing lab](labs/git-commit-spoofing/README.md)).

| Method | Notes |
|---|---|
| **SSH signing** (`gpg.format ssh`) | uses a normal SSH key; verify with an `allowed_signers` file; simple (needs a recent git, around 2.34+; verify) |
| **GPG/OpenPGP** | classic; web of trust and key management are heavier |
| **S/MIME** | uses X.509 certificates |
| **Sigstore gitsign** | keyless: a short-lived certificate from an OIDC identity, logged in a transparency log (verify current status) |

**Enforce it**: branch protection that requires signed commits, "vigilant mode" or similar platform settings, and a reviewed list of allowed signers. Client-side config alone is optional for developers.

**Limits.** A signature proves *which key* signed and that the content did not change. It does not prove the code is **good**, the key is not **stolen**, or the signer is who you think (that depends on how keys are registered and reviewed).

**Code signing** of binaries (Windows Authenticode, macOS notarization, Android and iOS signing, Linux package signing) follows the same logic at the release step; protect those keys in hardware or a managed service ([lesson 06 section 4](06-real-world-case-studies.md#4-stolen-code-sign-certificates-or-signed-malicious-apps)).

**Lab:** [git-commit-signing](labs/git-commit-signing/README.md).

## 3. Artifact Signing

Sign what you **ship**: container images, packages, binaries, SBOMs, provenance. Consumers (and admission controllers) verify before use.

| Tool or standard | Role (verify current versions) |
|---|---|
| **Sigstore: cosign, Fulcio, Rekor** | sign and verify artifacts; **keyless** signing with short-lived certificates tied to an OIDC identity; a public transparency log |
| **Notation (Notary Project)** | OCI artifact signing with certificates; the successor path from Docker Content Trust |
| **in-toto attestations** | signed statements about steps (who built what, with which inputs) |
| **SLSA provenance** | a signed attestation of how an artifact was built; SLSA v1.0 (April 2023) defines **Build track levels L0 to L3**: L1 provenance exists; L2 hosted build platform and signed provenance; L3 hardened builds (verify v1.1 status) |
| **Docker Content Trust (Notary v1)** | **retired** (announced July 2025; the hosted notary service shuts down in December 2026): migrate to Notation or cosign (verify the dates) |

**Verify the right thing.** A good verification policy checks the **signer identity** (for keyless: which workflow in which repo), the **provenance** (built from the expected source commit on a trusted builder), and that the **digest** matches what you deploy. "Has a signature" alone is not a policy.

Related offline labs: [CMCPSE sign-verify-mcp-build](../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/labs/sign-verify-mcp-build/) and [provenance-attestations](../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/labs/provenance-attestations/), and [CAISP model-signing](../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/model-signing/).

## 4. Dependency Hashing

A **hash** of the exact file you expect makes substitution fail, even if the name and version are right (dependency confusion, a tampered registry, a mirror compromise, a man in the middle).

| Ecosystem | How |
|---|---|
| Python | `pip install --require-hashes -r requirements.txt` with `--hash=sha256:...` per package (tools: pip-compile `--generate-hashes`, uv and Poetry lock files) |
| npm | `package-lock.json` stores an `integrity` value (SHA-512) per package |
| Go | `go.sum` records module hashes; the public checksum database (`sum.golang.org`) provides transparency |
| Maven and others | checksum and signature files; dependency verification features (Gradle) |
| Containers | pull by **digest** (`image@sha256:...`) |
| Downloads in CI | check a sha256 you stored in your repo before running (see the [Codecov lab](labs/codecov-attack/README.md)) |

**Limits.** A hash proves the file is the **same** one you recorded. If you recorded a malicious file, the hash agrees with it. So hash **after** vetting, review hash changes in pull requests, and get the expected hash through a channel the attacker does not control. The [dependency-confusion lab](labs/dependency-confusion/README.md) shows `resolve_with_lock` rejecting the attacker's file even when the name is squatted.

## 5. Dependency Pinning

**Pinning** fixes the versions you use: exact versions in a lock file instead of ranges like `^1.2.0` or `latest`.

| Good | Cost and fix |
|---|---|
| Builds are repeatable | you must **update on purpose**: use Dependabot or Renovate to open PRs; run SCA and tests on them |
| A newly published malicious version does not reach you automatically | pinning is not safety: pinning to a bad version keeps you on it |
| Supports reproducibility and incident response | transitive dependencies need lock files too (use them for apps; for libraries, the guidance differs: verify per ecosystem) |

Extras: use a **cool-down** (do not adopt a release younger than a few days, an idea several tools support; verify) so malicious releases are usually found before you take them; use `npm ci` rather than `npm install` in CI; pin **base images by digest**; pin **tools and actions** ([section 6](#6-defending-github-actions-with-pinning)); pin pre-commit hook revs ([lab](labs/exploiting-pre-commit-hooks/README.md)).

## 6. Defending GitHub Actions With Pinning

A tag is a **movable label**. The tj-actions/changed-files incident (March 2025) worked because existing version tags were repointed ([lesson 04](04-attacks-on-build-and-cicd-systems.md)). A **full 40-character commit SHA** cannot be repointed.

```yaml
# risky: runs whatever the tag points to today
- uses: some-org/some-action@v4
# pinned: a specific commit; the comment documents the version for humans and for update tools
- uses: some-org/some-action@0123456789abcdef0123456789abcdef01234567  # v4.1.2
```

Do all of these:

1. **Pin third-party actions to a full SHA**, and keep the version in a comment. Let Dependabot or Renovate update the SHA with a PR you review. (Tools such as pinact and Scorecard checks can find unpinned actions; verify.)
2. **Enforce it by policy**: GitHub has been adding organization and repository settings to require SHA pinning and an allowlist of actions, and **immutable releases** (verify availability and current names).
3. **Pin what the action pulls**: actions that download tools or run Docker images can themselves be unpinned; prefer actions with pinned internals or write steps that verify downloads.
4. **Least privilege**: `permissions:` read-only by default; OIDC to the cloud instead of stored keys.
5. **Mirror or vendor critical actions** into your own organization, and review them.
6. **Lint**: the repo's [workflow_lint](../../06-ai-devsecops/cicd/README.md) checks SHA pinning and `pull_request_target`; the [CAISP poisoned pipeline lab](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/poisoned-pipeline/README.md) shows the attacks.

**Limit.** Pinning to a SHA freezes you on code you reviewed once. If the action's own dependencies change at runtime, or the SHA was already malicious, pinning does not help: combine with review, allowlists and monitoring.

## Putting it together

| Question | Practice |
|---|---|
| What is in this software? | SBOM (signed, attached) |
| Who produced this commit? | commit signing with allowed signers |
| Who built this artifact, from what? | artifact signing and provenance |
| Is this the same file I vetted? | hashes and pinning |
| Can the pipeline change under me? | action pinning, allowlists, least privilege |

## Hands-on

1. Run [git-commit-signing](labs/git-commit-signing/README.md) and the hash-lock part of [dependency-confusion](labs/dependency-confusion/README.md).
2. Take one workflow from your own repo and pin every third-party action to a SHA (on a branch, do not push to anyone else's repo).
3. Generate an SBOM for a small project with a tool from [real-tools](real-tools/osv-scanner-and-syft.md) and scan it.

## Real-world scenarios

1. **A trusted action tag is repointed.** With SHA pinning you are unaffected until you update; with tags you ran the malicious code. Fix and monitor: policy plus Dependabot review.
2. **A new critical library CVE lands.** With SBOMs you query "which products contain it" in minutes. Without, you grep repositories for days.
3. **A signed image fails verification in the cluster.** The policy checks signer identity and provenance. Investigate the pipeline run; do not bypass the policy.

## Common mistakes

- Treating an SBOM as proof of safety.
- Verifying "a signature exists" but not **who** signed.
- Pinning once and never updating.
- Recording hashes of unvetted files.
- Pinning to a tag and calling it done.

## Interview preparation

<details><summary><b>Q1. What problem does an SBOM solve and what does it not?</b></summary>
It lets you quickly find which products contain a component and supports license and supplier review. It does not prove components are safe or the SBOM correct; generate it at build time, sign it and keep it current. VEX reduces noise by stating exploitability.
</details>

<details><summary><b>Q2. Why pin GitHub Actions to a SHA?</b></summary>
Tags and branches can be moved; a commit SHA cannot. In the tj-actions incident, tags were repointed to malicious code. Combine with update PRs, allowlists, least-privilege tokens and review.
</details>

<details><summary><b>Q3. Hashing versus signing?</b></summary>
A hash shows a file is identical to one you recorded; you need a trusted source for the expected hash. A signature binds the content to a signer's key, so you can verify without having recorded the hash, as long as you trust the key or identity. Use both.
</details>

<details><summary><b>Q4. What does a good artifact-verification policy check?</b></summary>
The signer identity (for example a specific workflow in a specific repository), the provenance (built from the expected source on a trusted builder), the digest, and optionally scan results. A bare signature is not a policy.
</details>

<details><summary><b>Q5. How does pinning interact with security updates?</b></summary>
Pinning stops surprise changes but also stops fixes. Use automated update PRs with tests and SCA, review them, and consider a short cool-down period for new releases.
</details>

## Checklist (definition of done)

- [ ] I can explain each of the six practices and one limit of each.
- [ ] I signed and verified a commit, and saw a tampered commit fail.
- [ ] I can write a pinned `uses:` line and a hash-checked `pip` command.

## References

- SLSA: <https://slsa.dev/>
- Sigstore and cosign: <https://docs.sigstore.dev/>
- Notation (Notary Project): <https://notaryproject.dev/>
- CycloneDX: <https://cyclonedx.org/>, SPDX: <https://spdx.dev/>, NTIA SBOM minimum elements, CISA SBOM resources: <https://www.cisa.gov/sbom>
- pip secure installs: <https://pip.pypa.io/en/stable/topics/secure-installs/>
- GitHub Docs, "Security hardening for GitHub Actions" (pin to a full commit SHA): <https://docs.github.com/actions/security-for-github-actions>
- OpenSSF Scorecard: <https://scorecard.dev/>
