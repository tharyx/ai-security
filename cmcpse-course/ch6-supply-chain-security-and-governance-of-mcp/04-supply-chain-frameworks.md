# 04. Supply Chain Security Frameworks: SLSA, SCVS and OpenSSF Practices

> **Syllabus:** Supply Chain Security Frameworks: SLSA for MCP builds, Software Component Verification Standard (SCVS), OpenSSF best practices for MCP server maintainers.
> **Time:** 1.5 hours. **Lab link:** [`provenance-attestations`](labs/provenance-attestations/README.md) (the SLSA idea in code). **General background:** [CAISP ch6 lesson 03: SLSA and SCVS](../../caisp-course/ch6-supply-chain-attacks-in-ai/03-supply-chain-frameworks-slsa-and-scvs.md). This lesson maps them to MCP builds and adds the OpenSSF material.

*Framework versions and level definitions evolve. The details below are from memory of the public documents: verify at slsa.dev, owasp.org and openssf.org before you put them in an audit.*

## 1. SLSA for MCP builds

**SLSA** (Supply-chain Levels for Software Artifacts, pronounced "salsa") is a set of levels describing how trustworthy a build and its provenance are. Version 1.0 defines the **Build track** with levels 0 to 3; later versions are adding or have added a Source track (verify current status).

| Build level | Meaning (short) | What it means for an MCP server build |
|---|---|---|
| **L0** | No guarantees | Developer builds on a laptop and uploads to npm |
| **L1** | Provenance exists | The build script produces a provenance statement (source, builder, digest). Easy to forge, but it exists and enables tooling |
| **L2** | Hosted build platform; provenance is **signed** by the platform | Build in hosted CI (not a laptop); the platform signs the provenance so consumers can verify who built it |
| **L3** | Hardened build platform; signing material is **not accessible to user build steps**; builds are isolated from each other | The pipeline's own steps (or a poisoned PR) cannot forge provenance or leak the signing identity: the [PPE controls in ch5 lesson 06](../ch5-devsecops-for-mcp-security/06-pipeline-attacks-on-mcp.md) matter here |

**What consumers do with it** ([lab deploy gate](labs/provenance-attestations/README.md)): verify provenance and require the builder id, the source repository and the ref to be the expected ones. SLSA says nothing about whether the source code is good, only that the artifact came from that source through that builder.

**Pragmatic path for an MCP server team:** 1) build only in CI from a protected branch or tag; 2) generate provenance (GitHub Artifact Attestations or the SLSA GitHub generator, verify current tooling); 3) publish with registry provenance where supported (npm provenance, PyPI trusted publishing and attestations; verify); 4) verify provenance in your deploy step; 5) harden the platform for L3.

## 2. Software Component Verification Standard (SCVS)

**OWASP SCVS** is a checklist-style standard for verifying components and managing a software supply chain. It has **three levels** of rigor (higher levels for higher-risk software) and groups requirements into **control families**, commonly listed as:

| Family | Plain meaning | MCP example |
|---|---|---|
| **Inventory** | Know every component | An inventory of MCP servers and their packages (and shadow servers) |
| **SBOM** | Machine-readable bill of materials, signed, per release | [sbom-mcp-server lab](labs/sbom-mcp-server/README.md) |
| **Build environment** | Controlled, reproducible, access-limited builds | Hosted CI, pinned build tools |
| **Package management** | Trusted sources, pinned versions, integrity checks | Internal mirror, lock with hashes, pinned host configs |
| **Component analysis** | Scan for vulnerabilities, license and quality issues | `pip-audit`/OSV in the pipeline |
| **Pedigree and provenance** | Know where components came from and who changed them | Provenance, signature verification, diff review of updates |

Use SCVS as a **maturity checklist**: pick the level by server tier ([lesson 02](02-vetting-third-party-mcp-servers.md)). A read-only docs server may target level 1; a server that sends mail or runs commands should target level 2 or 3.

## 3. OpenSSF best practices for MCP server maintainers

The **Open Source Security Foundation (OpenSSF)** publishes practical tools and guidance. Useful ones (verify current names and pages):

| Resource | What it is | Use for an MCP server |
|---|---|---|
| **OpenSSF Scorecard** | Automated checks of a repo's security posture, each scored 0 to 10 (for example branch protection, code review, pinned dependencies, token permissions, signed releases, dangerous workflows, vulnerabilities, security policy, maintained, SAST, fuzzing) | Run on **your** repo and on **candidates you vet** (low score = ask why). Not a safety guarantee |
| **OpenSSF Best Practices Badge** (formerly CII badge) | A self-assessed checklist with passing, silver and gold tiers | A maintainer signal; check what was claimed |
| **OpenSSF guides** | For example concise guides for evaluating open source software and for developing more secure software | Basis for your vetting step 2 and your contributor guide |
| **Sigstore** | Keyless signing and transparency log | Sign releases ([lesson 03](03-transparency-and-integrity.md)) |
| **SLSA, S2C2F** | Build levels; a framework for **consuming** open source safely | Section 1; your intake rules |
| **Malicious packages / package analysis** | Community efforts to report and detect malicious packages | A data source for scanning candidate dependencies (verify availability) |

**A maintainer's checklist for an MCP server** (use as your repo's security baseline; the last six are MCP-specific):

- [ ] `SECURITY.md` with a private reporting address and response times.
- [ ] 2FA for all maintainers and registry accounts; trusted publishing / OIDC instead of long-lived registry tokens.
- [ ] Branch protection, required reviews, signed commits or tags.
- [ ] CI with least-privilege token permissions; actions pinned by SHA; no dangerous `pull_request_target` patterns.
- [ ] Dependency lock with hashes; automated update PRs with review; vulnerability alerts on.
- [ ] SAST and secret scanning in CI; fuzzing where practical.
- [ ] Signed releases with provenance; SBOM published with each release.
- [ ] Scorecard run in CI with the result published.
- [ ] **MCP:** a documented list of tools with their risk (read/write/execute/send) in the README.
- [ ] **MCP:** a **changelog entry and a version bump for every change to a tool name, description or schema**, so consumers can pin and review.
- [ ] **MCP:** no install scripts; no network calls at import time; no telemetry that sends user data without clear opt-in.
- [ ] **MCP:** no secrets in descriptions; strict input schemas; safe error handling ([ch5 lesson 02](../ch5-devsecops-for-mcp-security/02-sast-and-secret-scanning.md)).
- [ ] **MCP:** documented least-privilege credentials the server needs, and how to scope them.
- [ ] **MCP:** a stated deprecation policy (for example, for the older SSE transport).

## 4. Hands-on

1. Self-assess the `notes-mcp` fixture (or a real server you use) against the SLSA levels, the six SCVS families and the checklist above. Write one row per item: met, not met, evidence.
2. If you have network access and the tool installed (`scorecard --repo=github.com/<owner>/<repo>`; verify the current CLI), run Scorecard on a public MCP server repo you use. Which checks scored low? *(Not executed by the repo author.)*

## 5. Interview questions

- *What does SLSA Build L2 add over L1?* A hosted build platform that signs the provenance, so consumers can verify who built the artifact.
- *What does SLSA not tell you?* Whether the source is safe. It covers integrity of the path from source to artifact.
- *Name the SCVS families.* Inventory, SBOM, build environment, package management, component analysis, pedigree and provenance.
- *What is Scorecard and how would you use it on a candidate MCP server?* Automated repo-posture checks; use it as one vetting signal, then review code and behavior.

## 6. References

- slsa.dev; owasp.org/www-project-software-component-verification-standard; openssf.org, scorecard.dev, bestpractices.dev (verify current URLs).
- [CAISP ch6 lesson 03](../../caisp-course/ch6-supply-chain-attacks-in-ai/03-supply-chain-frameworks-slsa-and-scvs.md).
