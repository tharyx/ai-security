# Lesson 03: Change Control and Licensed Code

> **Chapter:** 6 · Common Defenses Against Supply Chain Attacks · **Time:** ~4 hours
> **You will:** configure protected branches, required reviews, CODEOWNERS and signed commits; explain license compliance and copyleft risk; and describe configuration management and change control for software delivery.

| | |
|---|---|
| **Prerequisites** | Git basics; [Chapter 2 commit spoofing and signing](../ch2-attacking-code-and-application-supply-chain/README.md); [Chapter 1 GitLab CI](../ch1-introduction-to-supply-chain-security/README.md) |
| **Related repo labs** | [06 cicd](../../06-ai-devsecops/cicd/README.md) (workflow lint, release gate, deploy approval) · [06 terraform](../../06-ai-devsecops/terraform/README.md) |
| **Labs** | [harbor-registry-policy](labs/harbor-registry-policy/README.md) (immutable tags and policy at the registry) · [false-positive-analysis](labs/false-positive-analysis/README.md) (exceptions with expiry) · [syft-in-cicd](labs/syft-in-cicd/README.md) (lint a pipeline) |
| **Syllabus lines** | Implement Change Control · Protected Branches · Licensed Code · Configuration management and change control |

## 1. Implement Change Control

**Change control** means every change to code, pipeline and infrastructure is **proposed, reviewed, approved, traceable and reversible**. It stops two kinds of supply-chain attack: a malicious change from a compromised account, and a bad change that nobody noticed.

### 1.1 Protected Branches

Git hosts let you protect important branches and tags. In GitLab these are **protected branches** and **protected tags**; GitHub offers **branch protection rules** and newer **rulesets**. Typical settings:

| Setting | Why |
|---|---|
| **No direct push** to `main` / release branches | every change goes through a merge request |
| **No force-push, no deletion** | history cannot be rewritten |
| **Required approvals** (at least 1 or 2, from someone other than the author) | second pair of eyes |
| **Dismiss stale approvals on new commits** | approval applies to what is merged |
| **Code owner approval required** | the right people see the right files |
| **Required status checks** (tests, SCA, SAST, secrets scan) | automated gates |
| **Required signed commits** (verified signatures) | stronger identity of authors (see below) |
| **Linear history / merge queue** | predictable, testable merges |
| **Protected tags** for releases | only release managers can create release tags |
| **Applies to admins too** | no silent bypass; log bypasses |

**CODEOWNERS.** A file mapping paths to owners, for example (GitHub and GitLab syntax differ slightly; check docs):

```text
# CODEOWNERS (example)
*                      @org/dev-team
/.gitlab-ci.yml        @org/platform-security
/.github/workflows/    @org/platform-security
/infra/                @org/platform-security @org/cloud-team
/deploy/               @org/release-managers
```

Put **pipeline definitions, deployment config and dependency manifests** under owners with security review. Many supply-chain attacks (poisoned pipeline execution) change CI files, not application code ([CAISP ch4 PPE lab](../../caisp-course/ch4-ai-attacks-and-defenses-devops/README.md), [06 cicd workflow lint](../../06-ai-devsecops/cicd/README.md)).

**Signed commits.** A commit's author field is just text; anyone can claim to be someone else (commit spoofing, see chapter 2). A **signature** (GPG, SSH or Sigstore-based "gitsign") proves the commit was made by a holder of a registered key. Require "verified" commits on protected branches, and remember the limit: a signature proves *key control*, not good intent.

**GitLab specifics (conceptual).** Protected branches and tags with allowed roles; merge request approval rules; push rules (for example reject unsigned commits, block secrets); **protected variables** exposed only to protected branches and tags; project and group access tokens with narrow scopes and expiry; avoid giving Maintainer/Owner broadly (role misconfiguration is a known privilege-escalation path, see [chapter 2 GitLab lab](../ch2-attacking-code-and-application-supply-chain/README.md)).

**Registry-side change control.** The same idea applies to images: **immutable tags**, robot accounts that can only push from CI, and pull policies. See [harbor-registry-policy](labs/harbor-registry-policy/README.md).

## 2. Licensed Code

Open-source licenses are **legal conditions**. Breaking them is a compliance and business risk, and license changes are also a supply-chain event.

### 2.1 License families

| Family | Examples (SPDX IDs) | What it asks of you (simplified, not legal advice) |
|---|---|---|
| **Permissive** | MIT, BSD-2/3-Clause, Apache-2.0, ISC | keep notices; Apache adds a patent grant and notice rules |
| **Weak copyleft** | LGPL-2.1/3.0, MPL-2.0, EPL-2.0 | changes to the licensed files (or library) must stay open; linking rules matter |
| **Strong copyleft** | GPL-2.0/3.0 | if you distribute a combined work, the whole work may need the same license |
| **Network copyleft** | AGPL-3.0 | offering the software as a network service can trigger source-offer duties |
| **Source-available / non-open** | BSL, SSPL and others (not OSI-approved) | restrictions such as no competing service; read carefully |
| **No license** | n/a | all rights reserved: you have no permission to use it |

Relicensing happens: several well-known infrastructure projects moved some versions to source-available terms in 2023 to 2024, and at least one later added an OSI-approved option again (details hedged; check the projects). Pin versions and monitor license changes in dependency updates.

### 2.2 License compliance in practice

1. **Inventory** every component and its license from the SBOM ([lesson 04](04-asset-inventory-and-sboms.md)); use SPDX license identifiers.
2. **Policy**: allow list (for example MIT, Apache-2.0, BSD), review list (LGPL, MPL), deny list for your distribution model (for example AGPL in a SaaS product, or GPL in a distributed binary).
3. **Automate** in CI with a license scanner (ScanCode, Trivy license scanning, FOSSA, ORT, language tools). Fail on denied licenses; route "unknown" to review.
4. **Notices**: generate third-party notice files from the SBOM.
5. **Copied code** counts: snippets copied from forums, repos or AI assistants can carry license obligations. Scan code, not only manifests.
6. **Contributor license** (DCO or CLA) for projects you accept contributions into.

The deny/allow decision depends on how you **distribute** (ship binaries, run SaaS, internal only). Ask legal for edge cases; this lesson is not legal advice.

## 3. Configuration management and change control

Beyond code, the *configuration* that decides how software is built and run needs the same discipline.

| Area | Control |
|---|---|
| **Infrastructure as code** | all infra and pipeline config in Git, reviewed, plan output scanned before apply ([06 terraform](../../06-ai-devsecops/terraform/README.md)) |
| **Environments** | promotion dev → staging → prod with the same artifact (build once, deploy many) |
| **Drift detection** | compare running state to declared state; alert on manual changes |
| **GitOps** | a controller applies what Git declares, so Git permissions are your change control |
| **Secrets** | stored in a secret manager, rotated, never in Git |
| **Approvals** | production deploys need an approval from someone other than the author; record who and why ([06 deploy approval](../../06-ai-devsecops/cicd/README.md)) |
| **Emergency changes** | allowed, but logged and reviewed after the fact |
| **Change records** | link tickets, merge requests, pipeline runs and deployed digests so you can answer "what changed, who approved it" |
| **Baselines** | hardened base images and standard configurations, versioned |

**A lightweight change flow:** branch → merge request with template (what, why, risk, rollback) → automated checks → owner review → merge → pipeline builds, signs and records provenance → approval gate → deploy → monitor → roll back by redeploying the previous signed digest.

## Defend (summary)

Protected branches and tags · CODEOWNERS on pipelines and infra · required reviews and checks · signed commits · protected variables · immutable tags · license policy in CI · IaC with review and drift detection · approvals and an audit trail.

## Hands-on

1. Write a CODEOWNERS file for a repo with `app/`, `infra/`, `.gitlab-ci.yml` and `requirements.txt`.
2. Run [syft-in-cicd](labs/syft-in-cicd/README.md) and its lint function. Which setting would you add to enforce SBOM generation on protected branches only?
3. List the licenses in the [syft-app-sbom](labs/syft-app-sbom/README.md) output and classify each as allow, review or deny for a SaaS product.

## Scenarios

- **A contributor's account is taken over and pushes to a feature branch that edits the CI file.** What stops it reaching production? (Protected branches, required reviews, CODEOWNERS on the CI file, protected variables not exposed to unprotected branches.)
- **A dependency switches from MIT to a source-available license in a minor version.** How do you find out before shipping? (License scanning on each dependency update, with a deny rule.)

## Interview Q&A

<details><summary>Why require code owner review on CI files?</summary>

CI files control what runs with your secrets. A single unreviewed edit can exfiltrate them or ship a backdoor, and the application code can stay clean.
</details>

<details><summary>What does a signed commit prove and not prove?</summary>

It proves the commit was created by someone holding a registered signing key. It does not prove the person is honest or that the key was not stolen.
</details>

<details><summary>Why is AGPL special?</summary>

Its network-use clause can require offering source to users who interact with the software over a network, which matters for SaaS even without distributing binaries.
</details>

## References

- GitLab and GitHub documentation on protected branches, CODEOWNERS, signed commits, rulesets (verify current pages).
- SPDX license list (spdx.org); ScanCode Toolkit; OpenSSF Scorecard (Branch-Protection, Code-Review checks).
- Repo: [06 cicd](../../06-ai-devsecops/cicd/README.md), [06 terraform](../../06-ai-devsecops/terraform/README.md).
