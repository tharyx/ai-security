# 06. Pipeline-Based Attacks on AI and MCP Deployments

> **Syllabus:** Cases of pipeline-based attacks on AI and MCP deployments (under CI/CD Pipeline Integration for MCP Security). Hands-on: execute a poisoned pipeline attack targeting an MCP deployment.
> **Time:** 2 hours. **Lab:** [`ppe-mcp-deployment`](labs/ppe-mcp-deployment/README.md). **Read first (do not repeat here):** [CAISP ch4 lesson 04: attacks on pipelines and PPE](../../caisp-course/ch4-ai-attacks-and-defenses-devops/04-pipeline-attacks-and-ppe.md), [lesson 05: case studies](../../caisp-course/ch4-ai-attacks-and-defenses-devops/05-case-studies.md) and the [CAISP poisoned-pipeline lab](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/poisoned-pipeline/README.md).

## 1. Why this matters

Whoever controls the pipeline controls what runs in production, and the pipeline usually holds the keys: registry tokens, cloud credentials, signing keys, deploy tokens. For an MCP project there is an extra prize: the **tool description and manifest**. Changing one line there changes what agents do, and it can slip through a code review that only reads code.

## 2. Recap in five lines

- **PPE (Poisoned Pipeline Execution)** = the attacker makes CI run their code (OWASP CICD-SEC-4 in the Top 10 CI/CD Security Risks; verify the current list).
- **Direct PPE:** the PR edits the pipeline file. **Indirect PPE:** the PR edits something the pipeline runs (Makefile, scripts, test config, `postinstall`). **Public PPE:** an untrusted fork PR triggers a privileged workflow (`pull_request_target`, the "pwn request").
- Prizes: secrets, write access to the repo and registry, the build output.
- Fixes: pipeline file from the protected branch, no secrets for untrusted code, protected paths and approvals, least-privilege tokens, egress control.
- Background and the AI-specific cases (Hugging Face, SAP AI Core, NotPetya) are in the CAISP lessons linked above.

## 3. Cases (what to learn from each)

| Case | One-line summary | Lesson for MCP |
|---|---|---|
| **Hugging Face (Wiz, April 2024)** | A malicious pickle model reached code execution on an inference service, with risk of cross-tenant access and a shared CI/CD takeover angle; fixed by the vendor. [CAISP case 1](../../caisp-course/ch4-ai-attacks-and-defenses-devops/05-case-studies.md#case-1-hugging-face-ai-platform-wiz-research-april-2024) | Model/tool artifacts are code. Treat anything loaded by the pipeline or server as executable. Isolate tenants. |
| **NotPetya (June 2017)** | Destructive malware spread through a compromised update of M.E.Doc accounting software. [CAISP case 2](../../caisp-course/ch4-ai-attacks-and-defenses-devops/05-case-studies.md#case-2-notpetya-june-2017) | A trusted update channel is an attack path. This is the template for a poisoned MCP package update such as `postmark-mcp` (chapter 6). |
| **SAP AI Core "SAPwned" (Wiz, 2024)** | Several vulnerabilities allowed reaching cluster admin and customer secrets in a shared AI platform. [CAISP case 3](../../caisp-course/ch4-ai-attacks-and-defenses-devops/05-case-studies.md#case-3-sap-ai-core-vulnerabilities-sapwned-wiz-research-2024) | Multi-tenant execution of user code needs strong isolation. A hosted MCP platform that runs customer servers has the same risk. |
| **tj-actions/changed-files (March 2025)** | Reported: a widely used GitHub Action was modified so that workflows using it printed secrets into their logs (CVE-2025-30066). Many version tags were reportedly re-pointed at the malicious commit; it was reportedly linked to an earlier compromise of another action. *Verify details in the GitHub advisory; reports vary on scale and origin.* | **Pin third-party actions to a full commit SHA**, not a tag. Restrict `permissions:`. Do not print secrets. Any CI dependency is a supply-chain dependency, including the ones your MCP pipeline uses. |
| **postmark-mcp (Sept 2025)** | A fake npm package impersonating Postmark added a hidden BCC in a later version (v1.0.16, after 15 benign versions). Reported by Koi Security and Snyk. | Not a pipeline attack on *you*, but the same trust problem one step away: your pipeline (and developers) pulled a poisoned dependency. Pin, diff and scan; see [chapter 6](../ch6-supply-chain-security-and-governance-of-mcp/01-mcp-supply-chain-overview.md). |

## 4. MCP-specific PPE paths

| Path | How the attacker gets code execution or a secret | Where it is shown in the lab |
|---|---|---|
| Edit the workflow or pipeline file | Direct PPE: add a step that sends the token out | `direct_ppe` |
| Edit `Makefile`, test scripts, `conftest.py` | Indirect PPE | `indirect_makefile` |
| Edit the **deploy script** | Indirect PPE in the step that holds the token | `indirect_deploy_script` |
| Edit the **server config** with a `postinstall`-style hook | The build runs attacker code | `config_hook` |
| Edit the **tool description** | A pipeline step pastes the description into a shell command (script injection, like the classic `${{ github.event.pull_request.title }}` bug) | `tool_description_injection` |
| Edit the description so it **poisons agents** | No pipeline code runs; the *deployed* server later misleads agents | caught by the description scan and manifest pin ([lesson 05](05-cicd-integration-and-policy-as-code.md)) |
| Compromise a CI dependency | A tag is re-pointed to malicious code | pin by SHA |
| Registry or artifact swap after build | The deploy step pulls a different artifact | signing and verification ([chapter 6](../ch6-supply-chain-security-and-governance-of-mcp/03-transparency-and-integrity.md)) |

## 5. The attack and the fix, in the lab

Everything runs in a **simulated CI with a fake shell**. The only thing stolen is a canary. See the [lab README](labs/ppe-mcp-deployment/README.md) for the output.

| Control | Which attacks it stops |
|---|---|
| Pipeline definition read from the **protected base branch** | direct PPE |
| **No secrets in PR runs**; deploy only on push to main | all five attacks lose the token |
| Secrets scoped to the **deploy stage** only | indirect PPE in test/build |
| Untrusted text passed via **env variable and quoted**, never pasted into a command | description injection |
| `ignore_scripts` (no config hooks) | config hook |
| **Description scan** as an early stage | description injection and poisoning |
| **Protected paths + CODEOWNERS** (`.ci/`, `scripts/`, `Makefile`, config, manifest) | blocks the merge of all five without a code owner who is not the author |
| **Environment approval** for deploy | a bad merge still needs a human |
| **Egress allowlist** on the runner | exfiltration fails even after a bad merge |
| Short-lived, scoped tokens (OIDC instead of long-lived secrets) | limits the damage; mentioned, not simulated |

Honest limit: in the fixed setup the attacker's code **still runs** in the PR job (for the Makefile case). It just finds nothing to steal and cannot reach out. That is why runner isolation (ephemeral, no network) is the next layer.

## 6. Hands-on

```text
.venv/Scripts/python cmcpse-course/ch5-devsecops-for-mcp-security/labs/ppe-mcp-deployment/demo.py
.venv/Scripts/python -m pytest cmcpse-course/ch5-devsecops-for-mcp-security/labs/ppe-mcp-deployment -v
```

Exercises: (1) disable one control at a time in `SECURE` (for example `secrets_on_pr_runs=True`) and find which attacks come back; (2) write a sixth attack, a PR that edits `requirements.lock` to point to an attacker-controlled index, and a rule to stop it; (3) compare with the [CAISP poisoned-pipeline lab](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/poisoned-pipeline/README.md) (GitHub-style YAML, `pull_request_target`).

## 7. Interview questions

- *Direct versus indirect PPE?* Direct edits the pipeline file; indirect edits a file the pipeline executes. Pipeline-file protection does not stop indirect PPE: you also need no-secrets-for-untrusted-code.
- *Why are tool descriptions a pipeline risk and an agent risk?* As text pasted into commands they cause injection in CI; as model-visible text they steer agents in production.
- *What did tj-actions teach?* Pin actions by commit SHA, minimise token permissions, and treat every CI dependency as part of your supply chain.

## 8. References

- OWASP Top 10 CI/CD Security Risks (owasp.org); GitHub Security Lab write-ups on "pwn requests" and script injection.
- GitHub advisory for CVE-2025-30066 (verify), and vendor write-ups (March 2025).
- [Repo: cicd workflow_lint](../../06-ai-devsecops/cicd/README.md) lints for `pull_request_target`.
