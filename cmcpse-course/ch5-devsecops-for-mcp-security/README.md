# Chapter 5: DevSecOps for MCP Security

> **Time:** ~18 hours. **You will:** run a secure development lifecycle for MCP servers, scan code and secrets, fuzz tools, plan and report a pentest, build a security pipeline with a policy gate, understand pipeline attacks, and deploy a runtime AI firewall in front of a server.

## Syllabus coverage

Every syllabus line of the chapter, in course order.

| Syllabus item | Where to study | Lab |
|---|---|---|
| Introduction to DevSecOps for MCP | [01 DevSecOps and the MCP SDLC](01-devsecops-and-the-mcp-sdlc.md); repo: [06 AI DevSecOps](../../06-ai-devsecops/README.md) | n/a |
| &nbsp;&nbsp;DevSecOps and DevOps principles in the agentic context | [01, section 2](01-devsecops-and-the-mcp-sdlc.md#2-devops-and-devsecops-principles-in-the-agentic-context); [CAISP ch4 lesson 01](../../caisp-course/ch4-ai-attacks-and-defenses-devops/01-devops-devsecops-and-ai-in-devops.md) | n/a |
| &nbsp;&nbsp;The MCP security development lifecycle | [01, section 3](01-devsecops-and-the-mcp-sdlc.md#3-the-mcp-security-development-lifecycle) ([SVG](../../images/cmcpse-ch5-mcp-sdlc.svg)) | draw your own (exercise in 01) |
| &nbsp;&nbsp;Shifting security left for MCP server development | [01, section 4](01-devsecops-and-the-mcp-sdlc.md#4-shifting-security-left-for-mcp-server-development) | [mcp-cicd-pipeline](labs/mcp-cicd-pipeline/README.md) |
| &nbsp;&nbsp;The role of automation in MCP security | [01, section 5](01-devsecops-and-the-mcp-sdlc.md#5-the-role-of-automation) | [mcp-cicd-pipeline](labs/mcp-cicd-pipeline/README.md) |
| Static Analysis of MCP Server Code | [02 SAST and secret scanning](02-sast-and-secret-scanning.md); [CAISP ch4 static analysis](../../caisp-course/ch4-ai-attacks-and-defenses-devops/06-devsecops-tooling-for-ai.md#static-analysis-of-models-and-applications) | [sast-vulnerable-mcp-server](labs/sast-vulnerable-mcp-server/README.md) |
| &nbsp;&nbsp;SAST tools applicable to MCP server codebases | [02, section 2](02-sast-and-secret-scanning.md#2-sast-tools-that-fit-mcp-server-codebases) | optional Bandit and Semgrep section in the [lab README](labs/sast-vulnerable-mcp-server/README.md) |
| &nbsp;&nbsp;Identifying vulnerabilities in tool and resource implementations | [02, sections 3 and 5](02-sast-and-secret-scanning.md#5-identifying-vulnerabilities-in-tool-and-resource-implementations); repo: [04 tool-security](../../04-mcp-security/tool-security/README.md) | [sast-vulnerable-mcp-server](labs/sast-vulnerable-mcp-server/README.md) (rules MCP001 to MCP006) |
| &nbsp;&nbsp;Scanning for hardcoded secrets in MCP server code | [02, section 4](02-sast-and-secret-scanning.md#4-scanning-for-hardcoded-secrets) | `secret_scan.py` in the same lab (FAKE keys only) |
| &nbsp;&nbsp;Code review practices and checklists specific to MCP | [02, section 6](02-sast-and-secret-scanning.md#6-code-review-practices-and-checklist-for-mcp) | review the vulnerable server with the checklist |
| Dynamic Analysis and Runtime Testing | [03 DAST, fuzzing and runtime testing](03-dast-fuzzing-and-runtime-testing.md); [CAISP ch4 dynamic analysis](../../caisp-course/ch4-ai-attacks-and-defenses-devops/06-devsecops-tooling-for-ai.md#dynamic-analysis-of-models-and-applications) | [fuzz-mcp-tools](labs/fuzz-mcp-tools/README.md) |
| &nbsp;&nbsp;DAST approaches for MCP servers over HTTP/SSE transport | [03, section 2](03-dast-fuzzing-and-runtime-testing.md#2-dast-for-mcp-servers-over-http-and-sse) (SSE is deprecated history; current transports stated) | HTTP test table; fuzz lab for tool inputs |
| &nbsp;&nbsp;Fuzzing MCP tool inputs for unexpected behavior | [03, section 3](03-dast-fuzzing-and-runtime-testing.md#3-fuzzing-mcp-tool-inputs) | [fuzz-mcp-tools](labs/fuzz-mcp-tools/README.md) |
| &nbsp;&nbsp;Runtime security testing of agentic pipelines | [03, section 4](03-dast-fuzzing-and-runtime-testing.md#4-runtime-security-testing-of-agentic-pipelines); repo: [05 monitoring-and-response](../../05-agent-security/monitoring-and-response/README.md) | scenario table in 03; [CAISP llm-agent-vuln-scan](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/llm-agent-vuln-scan/README.md) |
| Penetration testing methodology for MCP environments | [04 Penetration testing methodology](04-penetration-testing-methodology.md) | scope and report exercise in 04 |
| &nbsp;&nbsp;Scoping an MCP assessment | [04, section 2.1](04-penetration-testing-methodology.md#21-scoping-an-mcp-assessment) | write a scope for the notes server |
| &nbsp;&nbsp;Reconnaissance and enumeration | [04, section 2.2](04-penetration-testing-methodology.md#22-reconnaissance-and-enumeration); repo: [04 secure-operations (shadow servers)](../../04-mcp-security/secure-operations/README.md) | enumerate the lab server with `tools/list` |
| &nbsp;&nbsp;Exploitation and chaining | [04, sections 2.3 and 2.4](04-penetration-testing-methodology.md#23-exploitation-and-chaining) | [fuzz-mcp-tools](labs/fuzz-mcp-tools/README.md), [ppe-mcp-deployment](labs/ppe-mcp-deployment/README.md) |
| &nbsp;&nbsp;Reporting findings professionally | [04, section 2.5](04-penetration-testing-methodology.md#25-reporting-findings-professionally) and [report-template.md](report-template.md) | write two findings from the fuzz output |
| CI/CD Pipeline Integration for MCP Security | [05 CI/CD integration and policy as code](05-cicd-integration-and-policy-as-code.md); repo: [06 cicd](../../06-ai-devsecops/cicd/README.md) | [mcp-cicd-pipeline](labs/mcp-cicd-pipeline/README.md) |
| &nbsp;&nbsp;Embedding MCP-specific security checks into pipelines | [05, section 2](05-cicd-integration-and-policy-as-code.md#2-what-to-embed-the-mcp-pipeline-stages) | [workflow fixture](labs/mcp-cicd-pipeline/fixtures/mcp-security.yml) and runner |
| &nbsp;&nbsp;Automated vulnerability scanning for MCP server dependencies | [05, sections 3 and 4](05-cicd-integration-and-policy-as-code.md#3-automated-vulnerability-scanning-for-mcp-server-dependencies); [CAISP third-party-vulns](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/third-party-vulns/README.md) | `deps` stage |
| &nbsp;&nbsp;Policy as code for MCP deployments | [05, section 5](05-cicd-integration-and-policy-as-code.md#5-policy-as-code-for-mcp-deployments) | [mcp-policy.yaml](labs/mcp-cicd-pipeline/policy/mcp-policy.yaml) |
| &nbsp;&nbsp;Security gates, break-build policies, and approval workflows | [05, section 6](05-cicd-integration-and-policy-as-code.md#6-security-gates-break-build-policies-and-approval-workflows); repo: [release_gate, deploy_approval](../../06-ai-devsecops/cicd/README.md) | exit codes and approvals in `pipeline_runner.py` |
| &nbsp;&nbsp;Cases of pipeline-based attacks on AI and MCP deployments | [06 Pipeline-based attacks](06-pipeline-attacks-on-mcp.md); [CAISP ch4 04](../../caisp-course/ch4-ai-attacks-and-defenses-devops/04-pipeline-attacks-and-ppe.md) and [05 case studies](../../caisp-course/ch4-ai-attacks-and-defenses-devops/05-case-studies.md) | [ppe-mcp-deployment](labs/ppe-mcp-deployment/README.md) |
| AI Firewalls and Runtime Protection | [07 AI firewalls at the gateway](07-ai-firewalls-at-the-gateway.md); [CAISP ch4 AI firewalls](../../caisp-course/ch4-ai-attacks-and-defenses-devops/06-devsecops-tooling-for-ai.md#ai-firewalls-for-guarding-models) | [mcp-ai-firewall-deploy](labs/mcp-ai-firewall-deploy/README.md) |
| &nbsp;&nbsp;AI firewall concepts for agentic workloads | [07, section 2](07-ai-firewalls-at-the-gateway.md#2-ai-firewall-concepts-for-agentic-workloads); repo: [09 lesson 06](../../09-enterprise-architecture/06-secure-llm-ai-gateway.md) | [ch4 mcp-ai-firewall](../ch4-defending-and-hardening-mcp-servers/labs/mcp-ai-firewall/) |
| &nbsp;&nbsp;Protecting MCP tool invocations at runtime | [07, section 3](07-ai-firewalls-at-the-gateway.md#3-protecting-mcp-tool-invocations-at-runtime) | tool allowlist and filtering in [mcp-ai-firewall-deploy](labs/mcp-ai-firewall-deploy/README.md) |
| &nbsp;&nbsp;Detecting prompt injection at the gateway level | [07, section 4](07-ai-firewalls-at-the-gateway.md#4-detecting-prompt-injection-at-the-gateway) | injection scoring and `tune.py` |
| &nbsp;&nbsp;Rate limiting and abuse prevention for MCP endpoints | [07, section 5](07-ai-firewalls-at-the-gateway.md#5-rate-limiting-and-abuse-prevention) | `rate_limits` in `firewall.yaml` |
| &nbsp;&nbsp;Guardrails for tool output before it reaches the LLM | [07, section 6](07-ai-firewalls-at-the-gateway.md#6-guardrails-for-tool-output-before-it-reaches-the-llm); [CAISP guard-io](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/guard-io/README.md) | `output` section: redaction, size cap |
| Hands-on Exercises: | see the lab index below | |
| &nbsp;&nbsp;Run SAST scanning against a deliberately vulnerable MCP server codebase | [02](02-sast-and-secret-scanning.md) | [sast-vulnerable-mcp-server](labs/sast-vulnerable-mcp-server/README.md) |
| &nbsp;&nbsp;Fuzz MCP tool inputs using a Python-based fuzzing framework | [03](03-dast-fuzzing-and-runtime-testing.md) | [fuzz-mcp-tools](labs/fuzz-mcp-tools/README.md) |
| &nbsp;&nbsp;Set up a CI/CD security pipeline with automated MCP security checks | [05](05-cicd-integration-and-policy-as-code.md) | [mcp-cicd-pipeline](labs/mcp-cicd-pipeline/README.md) |
| &nbsp;&nbsp;Execute a poisoned pipeline attack targeting an MCP deployment | [06](06-pipeline-attacks-on-mcp.md) | [ppe-mcp-deployment](labs/ppe-mcp-deployment/README.md) |
| &nbsp;&nbsp;Deploy and configure an AI firewall for an MCP server | [07](07-ai-firewalls-at-the-gateway.md) | [mcp-ai-firewall-deploy](labs/mcp-ai-firewall-deploy/README.md) |

## Lab index

| Lab | Course exercise | Offline | Tests | Reuses |
|---|---|---|---|---|
| [sast-vulnerable-mcp-server](labs/sast-vulnerable-mcp-server/README.md) | SAST against a vulnerable MCP server | yes | AST rules, secret scanner, fixed server clean | [CAISP ai-code-weaknesses](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/ai-code-weaknesses/README.md) idea |
| [fuzz-mcp-tools](labs/fuzz-mcp-tools/README.md) | Fuzz MCP tool inputs | yes (sandboxed recorders) | five bug classes found, fixed server clean | targets the SAST lab servers |
| [mcp-cicd-pipeline](labs/mcp-cicd-pipeline/README.md) | CI/CD security pipeline | yes | stages, gate, approvals, workflow lint | SAST lab scanner |
| [ppe-mcp-deployment](labs/ppe-mcp-deployment/README.md) | Poisoned pipeline against MCP | yes (fake shell, canary) | five attacks, fixes, merge gate, bad-merge defence | [CAISP poisoned-pipeline](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/poisoned-pipeline/README.md), pipeline lab scanner |
| [mcp-ai-firewall-deploy](labs/mcp-ai-firewall-deploy/README.md) | Deploy and configure an AI firewall | yes | policy validation, modes, rate limits, output guardrails, tuning | [ch4 mcp-ai-firewall](../ch4-defending-and-hardening-mcp-servers/labs/mcp-ai-firewall/) |

Run all of them:

```text
.venv/Scripts/python -m pytest cmcpse-course/ch5-devsecops-for-mcp-security -v
```

## Learning order

1. [01](01-devsecops-and-the-mcp-sdlc.md): draw your own MCP SDLC.
2. [02](02-sast-and-secret-scanning.md), then the [SAST lab](labs/sast-vulnerable-mcp-server/README.md).
3. [03](03-dast-fuzzing-and-runtime-testing.md), then the [fuzz lab](labs/fuzz-mcp-tools/README.md).
4. [04](04-penetration-testing-methodology.md): write a scope and two findings with the [template](report-template.md).
5. [05](05-cicd-integration-and-policy-as-code.md), then the [pipeline lab](labs/mcp-cicd-pipeline/README.md).
6. [06](06-pipeline-attacks-on-mcp.md), then the [PPE lab](labs/ppe-mcp-deployment/README.md).
7. [07](07-ai-firewalls-at-the-gateway.md), then the [firewall lab](labs/mcp-ai-firewall-deploy/README.md).
8. The Q&As below.

## Exam tips for this chapter

- **Know the six MCP SAST rules** and the fix for each: shell exec, path join, SSRF, secret in description, 0.0.0.0, verbose errors.
- **Description is attack surface.** Pin it and require approval when it changes.
- **Pentest phases in order:** scoping, recon and enumeration, exploitation and chaining, reporting. Chaining and written authorization are favourite questions.
- **PPE:** direct vs indirect; fixes are base-branch pipeline files, no secrets for untrusted code, CODEOWNERS, egress control.
- **Gateway:** inspect responses too; start in monitor mode; rate limit per identity; regexes are evadable.
- **Transport:** stdio and Streamable HTTP are current; HTTP+SSE is the older, deprecated transport the syllabus still mentions.

## 15 exam-style questions

<details><summary>1. What does "shift left" mean for MCP server development?</summary>

Run security checks as early and as close to the developer as possible: secret scans at commit, SAST and description scans in the pull request, instead of finding the same problems in a pentest. Later checks (DAST, runtime protection) still exist for what static checks cannot see.
</details>

<details><summary>2. Why is a tool description a security concern that normal SAST misses?</summary>

It is text the model reads and obeys. A changed description can steer agent behavior (tool poisoning) without changing any code. So MCP pipelines add a description scan, a pinned manifest (hash of description and schema), and approval for changes.
</details>

<details><summary>3. List the six MCP-specific SAST rules used in this chapter.</summary>

MCP001 shell execution, MCP002 path join without canonicalization, MCP003 SSRF fetch without allowlist, MCP004 secret in a tool description, MCP005 bind to 0.0.0.0, MCP006 verbose exceptions returned to the client.
</details>

<details><summary>4. Why is `resolve()` alone not enough to stop path traversal?</summary>

It normalizes the path (removes `..`, follows symlinks) but does not check where it ended up. You must also verify the result is inside the allowed base (`is_relative_to`, `commonpath`), and reject otherwise. A plain `startswith` check is weak because of prefix tricks (`/data` vs `/data-evil`).
</details>

<details><summary>5. How do secret scanners find secrets, and what do you do with a hit?</summary>

Known formats (regex), generic assignments to variables named key/secret/token, and entropy checks. Treat every hit as real: revoke and rotate first, then remove from code and history. Scan history, descriptions, configs, logs and containers too. Never print the full value in CI logs.
</details>

<details><summary>6. What is the difference between SAST and DAST for an MCP server?</summary>

SAST reads source without running it (fast, early, finds patterns). DAST attacks the running server from outside (finds runtime, configuration and HTTP issues: auth, Origin handling, error leakage, rate limits). They complement each other.
</details>

<details><summary>7. Which MCP transports are current, and what happened to SSE?</summary>

stdio and Streamable HTTP are the standard transports. The older HTTP+SSE transport (2024-11-05) was superseded in the 2025-03-26 revision and is deprecated, but many servers still expose it, so DAST should test both. Verify the latest revision at modelcontextprotocol.io.
</details>

<details><summary>8. Explain the oracle problem in fuzzing and give two MCP oracles.</summary>

A fuzzer needs a rule that says "this run was a bug". MCP examples: an exception escapes the handler (crash); a canary file outside the allowed folder appears in a response (path traversal); the server builds a shell string containing metacharacters from input (command injection); a traceback appears in an error response (info leak).
</details>

<details><summary>9. Why run a fuzzer with recorders and canaries instead of the real system?</summary>

Fuzzing triggers the bugs it finds. A real command injection would run a real command. Recorders capture the command or URL instead, and canaries prove a file escape without touching real data.
</details>

<details><summary>10. What should be in the scope of an MCP penetration test?</summary>

Servers and versions, hosts/clients, gateways, registries, CI pipelines, test accounts and data, the model and its version, rules for destructive tools, third-party SaaS permission, hours, rate limits, stop conditions, authorization and data handling, and the report format. Production data and DoS are normally out of scope.
</details>

<details><summary>11. What is chaining, and why does it matter in a report?</summary>

Combining individually moderate issues into one high-impact path, for example injection in content, plus an over-privileged tool, plus a write-back channel to leak data. The report should rate the chain, show evidence per link, and name the cheapest link to cut.
</details>

<details><summary>12. What is policy as code and what does a break-build policy look like?</summary>

Security rules in a versioned, reviewed, machine-readable file that the pipeline evaluates. Example: block on high severity, require all scan stages to run, allow waivers only from named approvers who are not the author, and never waive secrets or poisoned descriptions. A crashing scanner fails the build (fail closed).
</details>

<details><summary>13. What is Poisoned Pipeline Execution, and how do you defend an MCP pipeline against it?</summary>

An attacker with PR access gets CI to run their code (direct: edit the pipeline file; indirect: edit files it runs such as Makefile, scripts, config hooks, or text it pastes into commands). Defend with pipeline files from the protected branch, no secrets in untrusted runs, secrets only in an approved deploy stage, CODEOWNERS on pipeline/config/manifest, data passed via quoted env variables, disabled hooks, egress allowlists, and short-lived tokens.
</details>

<details><summary>14. What did the tj-actions/changed-files incident (March 2025) teach?</summary>

As reported, a popular GitHub Action was tampered with so it leaked workflow secrets into logs, and tags were re-pointed at the malicious code. Lesson: pin third-party actions to full commit SHAs, minimise token permissions, and treat CI dependencies as supply chain. Verify the details in the GitHub advisory.
</details>

<details><summary>15. How do you roll out an AI firewall safely and what are its limits?</summary>

Policy as code with validation that fails closed; start in monitor mode; measure false positives and negatives on labelled traffic; choose the threshold with evidence; enforce per tool with a rollback plan; audit with argument hashes, not values. Limits: pattern and classifier detection can be evaded, so keep least privilege, approvals and egress control underneath.
</details>

## References

- Lessons 01 to 07 and the [report template](report-template.md).
- OWASP MCP Top 10 (beta), OWASP Top 10 CI/CD Security Risks, OWASP LLM Top 10 2025 and 2026 lists: verify names and versions at owasp.org.
- MCP specification: modelcontextprotocol.io/specification (verify the current revision; the notes in this repo assume 2025-11-25 as a known revision and a later 2026 revision as the latest).
- Next chapter: [6 Supply chain security and governance of MCP](../ch6-supply-chain-security-and-governance-of-mcp/README.md).
