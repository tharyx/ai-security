# Lesson 02: Vetting Components and Automating It

> **Chapter:** 7 · Managing a Secure Software Supply Chain Program · **Time:** ~5 hours
> **You will:** design an intake process for commercial, open-source, third-party and proprietary code, automate its checks in CI, and handle dependency conflicts without trading away security.

| | |
|---|---|
| **Prerequisites** | [Lesson 01](01-supply-chain-attack-visibility.md); [CAISP vetting lesson](../../caisp-course/ch6-supply-chain-attacks-in-ai/02-vetting-software-frameworks.md) |
| **Labs** | [oss-vetting-process](labs/oss-vetting-process/README.md) · [dependency-hell](labs/dependency-hell/README.md) |
| **Syllabus lines** | Creating a vetting process for software components (Commercial, Open Source, Third Party, and Proprietary Code) used throughout SDLC · Automation of vetting and third-party code · Handling Dependency Hell |
| **Diagram** | [intake workflow](../../images/csse-ch7-vetting-intake-workflow.svg) |
| **Reuse** | [CAISP package-vetting](../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/package-vetting/) (typosquat, dependency confusion, hash pinning) · [CMCPSE MCP vetting](../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/02-vetting-third-party-mcp-servers.md) · [CAASE skill vetting](../../caase-course/ch4-computer-use-browser-and-coding-agents/labs/skill-vetting/README.md) · [CI workflow lint](../../06-ai-devsecops/cicd/README.md) |

## Why this matters

- **Dependency confusion (Alex Birsan, Feb 2021):** internal package names were claimed on public registries and big companies' builds installed them. No scanner flagged it: the name was simply new.
- **event-stream (2018):** a maintainer handed a popular package to a stranger, who added malicious code. A maintainer-change signal was available.
- **Codecov (2021):** a modified bash uploader script exfiltrated CI environment variables from customers. A third-party *tool* in the pipeline was never vetted like code.
- **3CX (2023):** a cascading attack where a compromised software dependency led to a compromised vendor product. Commercial software is also a supply chain.

## 1. Four kinds of component, four kinds of evidence

| Type | Examples | Main risk | Evidence you can ask for |
|---|---|---|---|
| **Open source** | npm, PyPI, Maven, Go modules, container base images, GitHub Actions | Malicious or abandoned code, license issues, hijacked accounts | Scorecard, advisories, maintainers, license, package age, provenance |
| **Commercial (COTS)** | SDKs, agents, databases, appliances | Vendor compromise, slow patching, opaque code | Vendor SBOM, PSIRT process, SOC 2 or ISO 27001 report, secure-development attestation, contract terms |
| **Third-party (custom)** | Outsourced development, integrators, contractors | Weak SDLC, shared credentials, code you cannot inspect | Contract security clauses, code escrow or access, SBOM per delivery, your own SAST/SCA on their code |
| **Proprietary (in-house)** | Your own services and libraries | Insecure SDLC: no review, secrets, unsigned builds | Branch protection, required review, SAST gate, signed provenance, internal SBOM |

Same gate, different checks. The lab's `check_by_type` shows the difference in code.

## 2. The process (see the diagram)

1. **Request.** A short form: what, which version, why, how it will be used (runtime, build, dev-only), what data it touches, alternatives considered, and who owns it. The form is the first control: "why do we need this?" removes a surprising number of dependencies.
2. **Triage by type** and by **risk tier**. A dev-only linter is not a payment-path library. Tier decides how deep the review goes.
3. **Automated checks** (section 4). Cheap, repeatable, run in CI.
4. **Decision** with three outcomes: *approve*, *conditional* (named owner, deadline, controls), *reject* (reason recorded, alternative suggested). Any hard fail wins.
5. **Record.** Audit log: who asked, what data, which checks, outcome, reviewer. Evidence for auditors ([control mapping](../../08-ai-compliance/03-control-mapping-and-evidence.md)).
6. **Admit.** Approved components enter an internal registry mirror or allowlist, pinned by version and hash, with an SBOM entry.
7. **Re-vet.** On new versions, new advisories, maintainer changes, and on a schedule. Remove components nobody uses.

## 3. What to check (criteria)

| Check | Good signs | Red flags |
|---|---|---|
| **Necessity** | no equivalent in stdlib or approved list | "just in case" dependency |
| **Provenance and identity** | exact name from the registry you expect; repo URL matches the package; attestation present | name one letter away from a popular package; repo link missing or unrelated |
| **Maintenance** | recent releases, several active maintainers, security policy | stale for a year, bus factor 1, ownership changed lately |
| **Security posture** | decent Scorecard result, branch protection, code review, signed releases | dangerous workflows, no review, tokens with broad permissions |
| **Vulnerabilities** | no KEV-listed issues; fixes available | unfixed critical/high, slow patch history |
| **License** | on your allow list | copyleft with distribution risk, no license, "source available" surprises |
| **Behaviour** | no install scripts, no network at install | obfuscation, post-install downloads |
| **Transitive footprint** | few dependencies | huge tree for tiny function |
| **Age** | established | brand-new package suggested by an AI assistant ([slopsquatting](../../caisp-course/ch6-supply-chain-attacks-in-ai/01-supply-chain-overview-and-ai-attacks.md)) |

## 4. Automation of vetting and third-party code

You cannot review everything by hand. Automate the **repeatable** checks and keep people for judgment.

### 4.1 Where automation plugs in

| Stage | Automated control | Tools (examples; verify maintenance) |
|---|---|---|
| Developer machine | Pre-commit secret scan, lockfile checks | TruffleHog, gitleaks |
| Pull request | Dependency review (diff of added or changed deps), license check, Scorecard on new deps, SBOM diff | GitHub dependency review, Dependabot, Renovate, OSV-Scanner, Trivy |
| Build | Hash-checked installs from lockfile, no install scripts, SBOM, provenance | `pip --require-hashes`, `npm ci`, Syft, SLSA generators |
| Registry | Allowlist or curated mirror; block unvetted names | Artifactory, Nexus, Harbor (images), private proxy |
| Deploy | Verify signature and provenance, admission policy | cosign, Notation, Kyverno or admission policies |
| Continuous | Rescan SBOMs against new advisories, alert on maintainer changes | DefectDojo, Dependency-Track, OSV |
| Pipeline code | Lint workflows, pin actions by full SHA, least-privilege tokens | the repo's [workflow_lint](../../06-ai-devsecops/cicd/README.md) |

### 4.2 Policy as code

Write the rules (license list, score thresholds, banned names, max age) as data the engine reads, store them in git, and review changes like code. The lab hard-codes example rules at the top of `vetting.py`; in real life they would live in YAML or Rego with owners and change history.

### 4.3 Automation traps

- **Alert fatigue.** Block only on high-confidence rules; route the rest to conditional review.
- **Bot PRs auto-merged.** An auto-merging update bot with no cooldown is a delivery system for a poisoned release. Require tests and a cooldown, and review major version bumps.
- **The tool is a dependency.** Scanners, Actions and plugins are components too. Pin and vet them.
- **Heuristics are not verdicts.** The lab's malicious-package check is a stub that says "no heuristic fired (this is not proof)". Say that in your own reports too.

## 5. Dependency hell and the security trade-off

**Dependency hell** = your dependency graph cannot be satisfied cleanly. The classic form is the **diamond**: A needs `lib ^1`, B needs `lib ^2`, and your app needs both A and B. Other forms: a deep tree where a tiny package breaks a major upgrade; abandoned packages with a pinned old dependency; version drift between environments.

### 5.1 Two installer behaviours

| Style | Behaviour on conflict | Example ecosystems (typical) |
|---|---|---|
| **Flat** (one version per package) | Resolution fails with an explanation | pip, Maven's "nearest wins" picks one silently (different), Go's minimal version selection picks the highest *required* |
| **Nested** (copies per dependent) | Installs both versions | npm and friends |

Hedge: real resolvers differ in details. The lab models the two ideas, not any specific tool.

### 5.2 Strategies

| Strategy | What it does | Security effect |
|---|---|---|
| **Semver ranges** (`^`, `~`) | Let the resolver pick compatible versions | Good for receiving patch fixes; risk: also receive a poisoned release (cooldown helps) |
| **Pinning** (exact versions, constraints files) | Fix the version | Reproducible, but a pin **adds** a limit; it cannot resolve a conflict, and it can freeze a vulnerable version |
| **Lockfile with hashes** | Record the full resolved tree and artifact hashes | Reproducible and tamper-evident; must be updated on purpose |
| **Overrides / resolutions** | Force one version for the whole tree | Can fix a vulnerable transitive dependency fast; can break a dependent that was not tested with it |
| **Upgrade the dependent** | Move A (or B) to a release that supports the new range | The clean fix when it exists |
| **Vendoring / forking** | Copy the code into your repo | Immune to registry changes and yanks; **you** now own patching, and SCA may not see it |
| **Replace or remove** | Use a different library | Best when the dependency is abandoned |

### 5.3 The trade-off

"Pin to the old version" feels safe because nothing changes, but if the old version has a known vulnerability, nothing changes means *you stay vulnerable*. "Upgrade everything" feels secure but can break production. The rule of thumb:

1. Find the **clean fix** first (upgrade the dependent).
2. If none, use an **override** to the *fixed* version, run the dependent's tests, and track an exception with an expiry ([lesson 05](05-program-management.md)).
3. If the dependency is dead and vulnerable, plan a **replacement**; vendoring a patched fork is a stopgap with a named owner.
4. Always keep the lockfile and the SBOM in step so you can answer "where is this version?"

The [dependency-hell lab](labs/dependency-hell/README.md) prints this table for a fixture graph, including how many vulnerable copies and out-of-range edges each strategy leaves.

## 6. Hands-on

1. Run the [vetting lab](labs/oss-vetting-process/README.md); add a policy rule and a test.
2. Run the [dependency-hell lab](labs/dependency-hell/README.md); predict each row first.
3. Take the GitHub fixture from [slsa-level-1](labs/slsa-level-1/README.md) and run `analyze_pipeline_yaml` on your own workflow files to find unpinned actions.

## 7. Scenarios

1. **AI assistant suggests `fastjsonx`.** Registry shows it was created last week, has an install script, and no repo link. *Process:* the heuristics fire, the request is rejected, and the suggested alternative is a vetted library. *Control:* assistants may only add dependencies via the request form or from the allowlist.
2. **Vendor will not provide an SBOM.** *Process:* conditional approval with a deadline and contract clause; compensating controls such as network segmentation and monitoring; escalate if the deadline passes.
3. **Log4Shell-style transitive flaw.** The direct dependency has no fix yet. *Process:* override to the fixed transitive version, run tests, record an exception with 30-day expiry, and watch for the upstream release.

## 8. Common mistakes

- One-time approval that never expires.
- Vetting package names but not versions or the GitHub Actions and build tools used in CI.
- Approving by popularity.
- Letting pinning replace patching.
- Vendored copies missing from the inventory.

## 9. Interview Q&A

<details><summary><b>Q1. How do you vet a commercial component differently from an open-source one?</b></summary>
You cannot read its code or its repo, so you lean on contract and attestations: vendor SBOM, PSIRT contact and disclosure SLA, security attestation (SOC 2, ISO 27001, secure-development attestation), patch timelines, and breach notification terms. For open source you can inspect Scorecard, maintainers, license and code.
</details>

<details><summary><b>Q2. What belongs in automation and what in human review?</b></summary>
Automate the repeatable, objective checks (license, known vulns, scores, name similarity, install scripts). Humans handle exceptions, business justification, conditional approvals, license edge cases, and judgment about risk tier.
</details>

<details><summary><b>Q3. Explain a diamond dependency and a safe resolution.</b></summary>
Two dependencies need incompatible versions of a shared library. Preferred fix: upgrade the dependent that lags behind. Otherwise override to the fixed version with testing and a time-limited exception. Pinning alone cannot satisfy incompatible ranges.
</details>

<details><summary><b>Q4. Why is a lockfile a security control?</b></summary>
It makes installs reproducible and, with hashes, detects a changed artifact. It prevents silent upgrades to a poisoned latest version, but it also freezes vulnerable versions until someone updates it on purpose.
</details>

## 10. Checklist

- [ ] I can draw the intake workflow and name the type-specific evidence.
- [ ] I can place at least six automated controls along the SDLC.
- [ ] I can compare five dependency-conflict strategies by security impact.

## 11. References

- OpenSSF Scorecard (github.com/ossf/scorecard); OpenSSF "Concise Guide for Evaluating Open Source Software".
- Alex Birsan, "Dependency Confusion" (Feb 2021).
- GitHub docs: dependency review, Dependabot cooldown, pinning actions to full SHAs; Renovate docs on release age.
- Next: [Lesson 03: standards](03-standards-and-frameworks.md).
