# 05. CI/CD Pipeline Integration and Policy as Code for MCP

> **Syllabus:** CI/CD Pipeline Integration for MCP Security: embedding MCP-specific security checks into pipelines, automated vulnerability scanning for MCP server dependencies, policy as code for MCP deployments, security gates, break-build policies and approval workflows. (The "cases of pipeline-based attacks" line is in [lesson 06](06-pipeline-attacks-on-mcp.md).)
> **Time:** 2 hours. **Lab:** [`mcp-cicd-pipeline`](labs/mcp-cicd-pipeline/README.md). **Background:** [06 AI DevSecOps cicd](../../06-ai-devsecops/cicd/README.md) (workflow lint, release gate, deploy approval).

## 1. Why this matters

The pipeline is where every earlier idea becomes **automatic and unskippable**. It is also where secrets live, so it must be secured itself (lesson 06). This lesson covers what to run, in what order, and how a gate decides.

## 2. What to embed: the MCP pipeline stages

| Stage | Runs on | Catches | Lab stage |
|---|---|---|---|
| Secret scan | every push and PR, plus history | credentials in code, configs, descriptions | `secrets` |
| SAST with MCP rules | PR | shell exec, path traversal, SSRF, 0.0.0.0, verbose errors | `sast` |
| Dependency audit | PR and nightly | known-vulnerable or unpinned packages | `deps` |
| Tool-description scan | PR | hidden instructions, sensitive paths, invisible Unicode, concealment | `tool-descriptions` |
| Manifest / description pinning | PR | any change to a tool name, description or schema that nobody approved (rug pull in the making) | `manifest-pin` |
| Unit + abuse-case tests, fuzz regression | PR | regressions of earlier findings | (see [03](03-dast-fuzzing-and-runtime-testing.md)) |
| Build: SBOM, provenance, signing | main / release | tampering after the build | [chapter 6](../ch6-supply-chain-security-and-governance-of-mcp/README.md) |
| Policy gate | last, `needs` all above | decides pass / fail / needs approval | `policy-gate` |
| DAST in staging | after deploy to staging | runtime and HTTP issues | [03](03-dast-fuzzing-and-runtime-testing.md) |

The GitHub Actions workflow fixture is [`fixtures/mcp-security.yml`](labs/mcp-cicd-pipeline/fixtures/mcp-security.yml). It is a **fixture, not in `.github/`**, so it never runs in this repo. The lab's Python `pipeline_runner.py` runs the same stages locally, so you can see the logic without a CI server.

## 3. Automated vulnerability scanning for MCP server dependencies

An MCP server is mostly dependencies: the official SDK, an HTTP framework, a database driver, an HTTP client. Rules:

- **Pin and lock:** exact versions in a lock file, with hashes where the ecosystem supports it (`pip install --require-hashes`, `npm ci` with a lockfile, `uv.lock`).
- **Audit on every PR and nightly:** new advisories appear after you merged. Tools: `pip-audit`, `npm audit`, OSV-Scanner, Trivy, Grype, GitHub Dependabot (verify current versions and flags).
- **Policy for findings:** block on critical/high **reachable** vulnerabilities; allow waivers with an expiry date and an owner.
- **Check the registry source:** the package must come from the expected index (defeats dependency confusion; see [chapter 6](../ch6-supply-chain-security-and-governance-of-mcp/02-vetting-third-party-mcp-servers.md)).
- **Audit the launcher too:** the server you *run* (`npx -y some-mcp`) is a dependency. Pin the version in host configs.

The lab uses a small local `advisories.json` (fictional advisories) so it works offline; the workflow fixture also shows the real `pip-audit` command (needs network, not run by the repo author). General background: [CAISP ch4 lesson 06 SCA](../../caisp-course/ch4-ai-attacks-and-defenses-devops/06-devsecops-tooling-for-ai.md#software-composition-analysis-for-ai-projects) and its [third-party-vulns lab](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/third-party-vulns/README.md).

## 4. Manifest and description pinning

Keep a **lock file for tool metadata**: for each tool, a hash of `description + inputSchema`, committed and reviewed.

```text
mcp-manifest.json        <- what the server says about its tools (generated or hand-written)
mcp-manifest.lock.json   <- hashes of the APPROVED versions
```

The pipeline compares them. A changed hash means a human must approve. This is the build-time twin of the runtime rug-pull defence in [chapter 4](../ch4-defending-and-hardening-mcp-servers/labs/defend-rug-pull/) and of the hash pinning in [04 mcp-server](../../04-mcp-security/mcp-server/README.md). Do both: the build-time lock stops a poisoned description from shipping; the runtime pin stops a server from changing it after you approved it.

## 5. Policy as code for MCP deployments

**Policy as code** = security rules written in a machine-readable file, versioned in git, reviewed by code owners, and evaluated by the pipeline. Benefits: reviewable, testable, identical in every repo, auditable.

The lab policy ([`policy/mcp-policy.yaml`](labs/mcp-cicd-pipeline/policy/mcp-policy.yaml)):

```yaml
block_on_severity: high
required_stages: [sast, secrets, deps, tool-descriptions, manifest-pin]
approvals:
  required_for: [PIN-CHANGED, PIN-ADDED]
  approvers: [secops-lead, mcp-platform-owner]
  forbid_self_approval: true
never_waivable: [DESC-POISON, SECRET, SAST-MCP001]
```

Reading it: findings at "high" or worse break the build; a build that did not run all required stages fails; a changed or added tool can be waived **only** by a named approver who is not the author; poisoning, secrets and shell execution can never be waived.

Other policy engines you will meet (examples; verify versions): **Open Policy Agent (OPA) with Rego** and Conftest for Kubernetes/Terraform/JSON; **Kyverno** for Kubernetes; **Checkov** for IaC; **GitHub rulesets and CODEOWNERS** for approvals. Sample MCP deployment rules to express as policy:

- Containers run as non-root, read-only root filesystem, no host network.
- The server listens on loopback or sits behind the gateway; no `0.0.0.0` without an ingress that enforces auth.
- Images and artifacts are **signed and the signature is verified** at deploy ([chapter 6 signing lab](../ch6-supply-chain-security-and-governance-of-mcp/labs/sign-verify-mcp-build/README.md)).
- Host configs may only reference approved registries and pinned versions (no `@latest`, no `npx -y` of unpinned names).
- Secrets come from the vault reference, not literals.
- Egress is allowlisted per server.

## 6. Security gates, break-build policies and approval workflows

| Concept | Meaning | Good practice |
|---|---|---|
| **Gate** | A decision point that must pass for the change to move on | One required status check (`policy-gate`) that needs all other jobs |
| **Break-build** | The pipeline fails and blocks merge/deploy | Block on high/critical; warn on lower; fail closed when a scanner crashes |
| **Waiver** | Documented exception | Owner, reason, expiry; never for secrets or poisoning |
| **Approval workflow** | Human sign-off for risky changes | Code owners for descriptions, schemas, pipeline files, policy files; no self-approval; two people for production |
| **Environment protection** | Deploy needs approval and holds the secrets | Secrets only in the deploy environment, not in PR jobs |
| **Staged rollout** | Monitor first, enforce later | Run a new rule in *warn* mode for a week, measure false positives, then enforce |

Pitfalls: gates that run only on some branches; "allowed to fail" jobs that nobody reads; a policy file that the PR author can edit and approve themselves (protect `policy/`, `.github/` and the manifest with CODEOWNERS); scanners that print full secrets into logs.

## 7. Hands-on

```text
.venv/Scripts/python cmcpse-course/ch5-devsecops-for-mcp-security/labs/mcp-cicd-pipeline/demo.py
.venv/Scripts/python -m pytest cmcpse-course/ch5-devsecops-for-mcp-security/labs/mcp-cicd-pipeline -v
```

Exercises: (1) edit a description in the good project and see which stage trips; (2) add `secrets-vault` to `required_stages` and watch the gate fail until you add the stage; (3) change `block_on_severity` to `critical` and explain what you just allowed (a test shows it).

## 8. Interview questions

- *What is policy as code and why use it?* Rules in versioned, reviewed, executable files; consistent, auditable, testable.
- *How do you stop someone deleting the security job from the workflow?* A required gate with a list of required stages, CODEOWNERS on workflow files, and branch protection requiring the gate.
- *What should never be waivable?* Hardcoded secrets, poisoned descriptions, shell execution reachable from a tool.

## 9. References

- [Repo: workflow_lint, release_gate, deploy_approval](../../06-ai-devsecops/cicd/README.md)
- GitHub Docs: workflow syntax, rulesets, environments, CODEOWNERS (verify current). OPA/Rego docs (openpolicyagent.org).
