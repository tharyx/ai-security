# Lesson 02: Evaluating Dependencies Before Use

> **Chapter:** 6 · Common Defenses Against Supply Chain Attacks · **Time:** ~5 hours
> **You will:** judge a dependency on security, health, maintainers and license; apply integrity checks (lockfiles, hashes, registry policy); and run the package-vetting twins (GuardDog-style and packj-style).

| | |
|---|---|
| **Prerequisites** | [Chapter 2](../ch2-attacking-code-and-application-supply-chain/README.md) (typosquatting, dependency confusion) |
| **Related repo labs** | [CAISP package-vetting](../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/package-vetting) (typosquat, dependency confusion, hash pinning) · [CAISP vetting lesson](../../caisp-course/ch6-supply-chain-attacks-in-ai/02-vetting-software-frameworks.md) · [CMCPSE backdoor-mcp-package](../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/labs/backdoor-mcp-package) · [CAASE skill-vetting](../../caase-course/ch4-computer-use-browser-and-coding-agents/labs/skill-vetting) |
| **Labs** | [guarddog-malicious-package](labs/guarddog-malicious-package/README.md) · [packj-risk-scoring](labs/packj-risk-scoring/README.md) · [bomber-sbom-scan](labs/bomber-sbom-scan/README.md) |
| **Syllabus lines** | Evaluate dependencies before use · Analyze the security and compliance of dependencies · Implement integrity checks or policies |

## 1. Analyze the security and compliance of dependencies

### 1.1 Why "before use"

Adding a dependency is giving a stranger the ability to run code in your build and your production. In 2025 and 2026 npm worms (Shai-Hulud, then a second wave and a later PyPI-and-npm variant; counts hedged) showed how fast one maintainer's stolen token turns into hundreds of infected packages. Evaluate *before* the first `install`, then keep watching.

### 1.2 What to check

| Signal | What you want | Tool / source |
|---|---|---|
| **Known vulnerabilities** | none unfixed in versions you use | OSV, osv-scanner, Grype, Trivy, GitHub advisories, [bomber twin](labs/bomber-sbom-scan/README.md) |
| **Malicious behavior** | no install-time download, exfiltration, obfuscation | GuardDog, Socket-style tools, [guarddog twin](labs/guarddog-malicious-package/README.md) |
| **Project health** | active releases, several maintainers, reviewed changes, branch protection, signed releases, CI, fuzzing | **OpenSSF Scorecard** (automated checks), deps.dev |
| **Maintainers** | known people, 2FA/trusted publishing, no recent unexplained ownership change | registry pages, [packj twin](labs/packj-risk-scoring/README.md) |
| **Age and popularity** | not brand new with few users (typosquat/slopsquat signal) | registry metadata |
| **Name risk** | not one edit from a popular name; not an LLM-hallucinated name | typosquat checks, human review |
| **Capabilities** | does a date-formatting library really need network and subprocess? | packj-style capability analysis |
| **License** | compatible with how you distribute ([lesson 03](03-change-control-and-licensed-code.md#2-licensed-code)) | ScanCode, Trivy license scanning, SBOM licenses |
| **Transitive tree** | size and depth you accept | SBOM ([lesson 04](04-asset-inventory-and-sboms.md)) |

### 1.3 OpenSSF Scorecard in one page

Scorecard runs automated checks on a repository and gives each a 0 to 10 score (for example: Maintained, Code-Review, Branch-Protection, Signed-Releases, Pinned-Dependencies, Token-Permissions, Dangerous-Workflow, Vulnerabilities, Security-Policy, Fuzzing, CI-Tests, License). It is a **signal**, not a verdict. A low score on a tiny, stable library may be fine; a low score on a critical dependency is a risk to accept knowingly. Example (verify current flags):

```text
scorecard --repo=github.com/<owner>/<repo>
```

### 1.4 A simple decision flow

1. **Do we need it?** Prefer the standard library or a small copy for trivial helpers (see the left-pad lesson in chapter 2).
2. **Automated gate**: no critical vulnerabilities, no malicious findings, license allowed.
3. **Risk score**: if the score is above your threshold, a human reviews the code paths that matter (install scripts, network, process execution).
4. **Decide and record**: approve, approve with constraints (pin, vendor, sandbox), or reject. Record the decision and owner. Re-review on major changes.

### 1.5 Evaluating AI-suggested packages

Language models sometimes invent package names ("slopsquatting"). Attackers register those names. Check that every suggested package exists, is the one intended, and passes the same checks. See [CAISP package-vetting](../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/package-vetting) and the AI code gate in [02-llm-security](../../02-llm-security/README.md).

**Labs:** [guarddog-malicious-package](labs/guarddog-malicious-package/README.md), [packj-risk-scoring](labs/packj-risk-scoring/README.md) (note: GuardDog is maintained; check packj's maintenance status).

## 2. Implement integrity checks or policies

### 2.1 Policies

- **Approved sources only.** Route all installs through an internal proxy/registry (Artifactory, Nexus, a Harbor proxy cache, GitLab package registry, Verdaccio) that allows only approved packages, blocks public packages that shadow internal names, and keeps a copy if the upstream vanishes.
- **Scope and namespace rules** for internal packages (dependency confusion defense: reserve your names publicly, or configure the client to take internal names only from the internal registry).
- **Cooldown or minimum release age.** Some tools and proxies can hold back versions published in the last few days, which buys time for the community to spot a hijack. Check support in your package manager or proxy.
- **Disable install-time scripts by default** where practical (for example `npm ci --ignore-scripts`, then run known-needed scripts explicitly) and review the exceptions.
- **Exception process** with owner and expiry (see the [false-positive-analysis lab](labs/false-positive-analysis/README.md)).

### 2.2 Implement integrity checks or policies

| Control | Example |
|---|---|
| **Lockfiles committed and used** | `npm ci`, `pip install -r requirements.txt`, `poetry.lock`, `go.sum`, `Cargo.lock`. Fail the build if the lockfile is out of date. |
| **Hash pinning** | `pip install --require-hashes -r requirements.txt` (pip-compile `--generate-hashes`). npm lockfiles store `integrity` hashes. |
| **Exact versions** | no ranges in production builds |
| **Verify signatures/provenance** | where the ecosystem offers them ([lesson 01 section 3](01-proving-integrity-with-cryptography.md#3-component-signing)) |
| **Pin CI actions and base images by digest** | `uses: org/action@<full commit SHA>`, `FROM image@sha256:...` (see the tj-actions case in chapter 2; GitHub also added org-level policy support for SHA pinning, verify) |
| **Rebuild-and-compare** | reproducible builds to detect tampering |
| **Policy engine** | OPA/Conftest, Kyverno or CI rules that reject unpinned dependencies and disallowed licenses |

**Offline example.** The CAISP lab shows hash pinning and a dependency-confusion simulator ([package-vetting](../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/package-vetting)). The [bomber-sbom-scan](labs/bomber-sbom-scan/README.md) twin checks an SBOM against an advisory database after the fact.

## Defend (summary)

Evaluate before adding · automate the first pass (vulns, malicious behavior, license) · score risk and review high scores · pin versions and hashes · proxy registry with allow-lists · cooldown and no install scripts by default · re-scan SBOMs continuously.

## Hands-on

1. Run the GuardDog-style and packj-style demos. Which finding in each would make you reject the package? Which only ask for review?
2. Add a fourth fixture package to the GuardDog twin that hides a download in a `__init__.py` (inert string) and make the scanner catch it.
3. Write your team's "may I add this dependency?" checklist in ten lines.

## Scenarios

- **A new package with 12 downloads is suggested by a code assistant for a task you already do with the standard library.** What do you do? (Do not install; use the standard library; if you must, run the vetting pipeline.)
- **A popular package changes maintainers and releases a patch the same day.** What controls help? (Pinned hashes, cooldown, diff review of the release, provenance checks.)

## Interview Q&A

<details><summary>What does OpenSSF Scorecard tell you and what does it not?</summary>

It scores repository practices (review, branch protection, pinned dependencies, signed releases, and more). It does not prove the code is free of vulnerabilities or malice; use it as one input.
</details>

<details><summary>Why is a lockfile alone not an integrity guarantee?</summary>

It pins versions (and often hashes), but the first lockfile creation or a careless update can pin a malicious version. Combine it with vetting, review of lockfile changes, and provenance.
</details>

<details><summary>How do you defend against dependency confusion?</summary>

Serve internal names only from the internal registry, use scopes or namespaces, reserve names on public registries, and pin with hashes.
</details>

## References

- OpenSSF Scorecard; OSV and osv-scanner; GuardDog (Datadog); deps.dev; OpenSSF S2C2F (Secure Supply Chain Consumption Framework).
- Repo: [CAISP chapter 6](../../caisp-course/ch6-supply-chain-attacks-in-ai/README.md), [CMCPSE chapter 6](../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/README.md), [CAASE skill vetting](../../caase-course/ch4-computer-use-browser-and-coding-agents/labs/skill-vetting).
