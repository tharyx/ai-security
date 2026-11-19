# Chapter 4: AI Attacks and Defenses in DevOps

This chapter follows a model from data to production and shows how its pipeline is attacked and defended. It also covers the course outcomes "Analyze attacks on AI deployment pipelines", "Implement DevSecOps security tooling for AI" and "Conduct poisoned pipeline attack exercises".

## Syllabus coverage

| Syllabus item | Where to study | Lab |
|---|---|---|
| Introduction to AI in DevOps | [01 DevOps, DevSecOps and AI in DevOps](01-devops-devsecops-and-ai-in-devops.md) | n/a |
| Definition and Principles of DevOps and DevSecOps | [01, section "Definition and principles of DevOps and DevSecOps"](01-devops-devsecops-and-ai-in-devops.md#definition-and-principles-of-devops-and-devsecops), repo: [06-ai-devsecops](../../06-ai-devsecops/README.md) | n/a |
| The Role of AI in Enhancing DevOps Practices | [01, section "The role of AI in enhancing DevOps practices"](01-devops-devsecops-and-ai-in-devops.md#the-role-of-ai-in-enhancing-devops-practices) (includes risks of AI coding assistants) | [ai-code-weaknesses](labs/ai-code-weaknesses/README.md) |
| Types of AI Attacks on DevOps Teams | [02 Types of AI attacks on DevOps teams](02-ai-attacks-on-devops-teams.md) | [llm-agent-vuln-scan](labs/llm-agent-vuln-scan/README.md) |
| Model Creation and Deployment Process/Pipeline | [03 Model creation and deployment pipeline](03-model-creation-and-deployment-pipeline.md) (with diagram), repo: [06 cicd](../../06-ai-devsecops/cicd/README.md) | n/a (diagram exercise) |
| Attacks on Pipelines | [04 Attacks on pipelines and PPE](04-pipeline-attacks-and-ppe.md) (Poisoned Pipeline Execution, direct and indirect, CICD-SEC-4), repo: [06 cicd](../../06-ai-devsecops/cicd/README.md) | [poisoned-pipeline](labs/poisoned-pipeline/README.md) |
| Cases of Attacks in DevOps and AI | [05 Case studies](05-case-studies.md) | [picklescan](labs/picklescan/README.md), [poisoned-pipeline](labs/poisoned-pipeline/README.md) |
| Hugging Face Artificial Intelligence (AI) Platform | [05, case 1](05-case-studies.md#case-1-hugging-face-ai-platform-wiz-research-april-2024) | [picklescan](labs/picklescan/README.md) |
| Notpetya Attack | [05, case 2](05-case-studies.md#case-2-notpetya-june-2017) | [poisoned-pipeline](labs/poisoned-pipeline/README.md) (update/pipeline trust) |
| SAP AI Core Vulnerabilities | [05, case 3](05-case-studies.md#case-3-sap-ai-core-vulnerabilities-sapwned-wiz-research-2024), repo: [06 kubernetes](../../06-ai-devsecops/kubernetes/README.md) | n/a (case analysis, tenant isolation checklist in the lesson) |
| DevSecOps Tooling and Defenses for AI Projects | [06 DevSecOps tooling](06-devsecops-tooling-for-ai.md), repo: [06-ai-devsecops](../../06-ai-devsecops/README.md) | all labs below |
| Software Composition Analysis for AI Projects | [06, section "Software Composition Analysis for AI projects"](06-devsecops-tooling-for-ai.md#software-composition-analysis-for-ai-projects), repo: [06 runtime-security](../../06-ai-devsecops/runtime-security/README.md) (vulnerability register) | [third-party-vulns](labs/third-party-vulns/README.md) |
| Static Analysis of Models and Applications | [06, section "Static Analysis of Models and Applications"](06-devsecops-tooling-for-ai.md#static-analysis-of-models-and-applications), repo: [06 docker](../../06-ai-devsecops/docker/README.md) | [ai-code-weaknesses](labs/ai-code-weaknesses/README.md), [picklescan](labs/picklescan/README.md) |
| Dynamic Analysis of Models and Applications | [06, section "Dynamic Analysis of Models and Applications"](06-devsecops-tooling-for-ai.md#dynamic-analysis-of-models-and-applications), repo: [02 security-testing](../../02-llm-security/security-testing/README.md) | [llm-agent-vuln-scan](labs/llm-agent-vuln-scan/README.md) |
| AI Firewalls for Guarding Models | [06, section "AI Firewalls for Guarding Models"](06-devsecops-tooling-for-ai.md#ai-firewalls-for-guarding-models), repo: [06 runtime-security](../../06-ai-devsecops/runtime-security/README.md) | [llm-guard-sanitize](labs/llm-guard-sanitize/README.md), [guard-io](labs/guard-io/README.md) |
| Hands-On Exercises: Analyzing and Fixing Vulnerabilities in Third-Party Components | [06 (SCA)](06-devsecops-tooling-for-ai.md#software-composition-analysis-for-ai-projects) | [third-party-vulns](labs/third-party-vulns/README.md) |
| Hands-On Exercises: Finding and Fixing Weaknesses in AI Code | [06 (static analysis)](06-devsecops-tooling-for-ai.md#static-analysis-of-models-and-applications), [01 (AI coding assistant risks)](01-devops-devsecops-and-ai-in-devops.md) | [ai-code-weaknesses](labs/ai-code-weaknesses/README.md) |
| Hands-On Exercises: Scanning a Malicious Pickle File using Picklescan | [06 (static analysis of models)](06-devsecops-tooling-for-ai.md#static-analysis-of-models-and-applications), repo: [06 docker](../../06-ai-devsecops/docker/README.md) | [picklescan](labs/picklescan/README.md) + [notebook](notebooks/picklescan-real-tool.ipynb) |
| Hands-On Exercises: Scanning an LLM for Agent Based Vulnerabilities | [06 (dynamic analysis)](06-devsecops-tooling-for-ai.md#dynamic-analysis-of-models-and-applications) | [llm-agent-vuln-scan](labs/llm-agent-vuln-scan/README.md) + [notebook](notebooks/agent-scan-garak.ipynb) |
| Hands-On Exercises: Sanitizing Prompts with LLM Guard | [06 (AI firewalls)](06-devsecops-tooling-for-ai.md#ai-firewalls-for-guarding-models) | [llm-guard-sanitize](labs/llm-guard-sanitize/README.md) + [notebook](notebooks/llm-guard-real.ipynb) |
| Hands-On Exercises: Guarding LLM Input and Output | [06 (AI firewalls)](06-devsecops-tooling-for-ai.md#ai-firewalls-for-guarding-models) | [guard-io](labs/guard-io/README.md) + [notebook](notebooks/llm-guard-real.ipynb) |
| Course outcome: Analyze attacks on AI deployment pipelines | [03](03-model-creation-and-deployment-pipeline.md), [04](04-pipeline-attacks-and-ppe.md), [05](05-case-studies.md) | [poisoned-pipeline](labs/poisoned-pipeline/README.md) |
| Course outcome: Implement DevSecOps security tooling for AI | [06](06-devsecops-tooling-for-ai.md) | [third-party-vulns](labs/third-party-vulns/README.md), [ai-code-weaknesses](labs/ai-code-weaknesses/README.md), [guard-io](labs/guard-io/README.md) |
| Course outcome: Conduct poisoned pipeline attack exercises | [04](04-pipeline-attacks-and-ppe.md) | [poisoned-pipeline](labs/poisoned-pipeline/README.md) |

## Lab index

All labs are offline with tests (`.venv/Scripts/python -m pytest caisp-course/ch4-ai-attacks-and-defenses-devops`). Notebooks are for the real tools and were **not executed by the repo author**: run them in Colab or in your course lab, and expect version changes.

| Lab | Course exercise | Offline twin (tests) | Real-tool notebook | Existing repo lab it extends |
|---|---|---|---|---|
| [third-party-vulns](labs/third-party-vulns/README.md) | Analyzing and Fixing Vulnerabilities in Third-Party Components | yes (fictional advisories) | optional `pip-audit` step in the README | [runtime-security vuln register](../../06-ai-devsecops/runtime-security/lab/) |
| [ai-code-weaknesses](labs/ai-code-weaknesses/README.md) | Finding and Fixing Weaknesses in AI Code | yes (AST scanner) | optional Bandit/Semgrep step in the README | [cicd workflow_lint](../../06-ai-devsecops/cicd/lab/workflow_lint.py) (same lint idea) |
| [picklescan](labs/picklescan/README.md) | Scanning a Malicious Pickle File using Picklescan | yes | [picklescan-real-tool.ipynb](notebooks/picklescan-real-tool.ipynb) | [06 docker pickle_scan](../../06-ai-devsecops/docker/lab/pickle_scan.py) |
| [llm-agent-vuln-scan](labs/llm-agent-vuln-scan/README.md) | Scanning an LLM for Agent Based Vulnerabilities | yes (probe suite, mock agent) | [agent-scan-garak.ipynb](notebooks/agent-scan-garak.ipynb) | [05 permissions](../../05-agent-security/permissions/lab/), [04 tool-security](../../04-mcp-security/tool-security/lab/) |
| [llm-guard-sanitize](labs/llm-guard-sanitize/README.md) | Sanitizing Prompts with LLM Guard | yes (input scanners) | [llm-guard-real.ipynb](notebooks/llm-guard-real.ipynb) | [02 prompt-injection](../../02-llm-security/prompt-injection/lab/) |
| [guard-io](labs/guard-io/README.md) | Guarding LLM Input and Output | yes (input + output pipeline) | [llm-guard-real.ipynb](notebooks/llm-guard-real.ipynb) | [02 data-leakage](../../02-llm-security/data-leakage/lab/) |
| [poisoned-pipeline](labs/poisoned-pipeline/README.md) | Poisoned pipeline attack exercises (course outcome) | yes (simulated CI) | n/a | [06 cicd](../../06-ai-devsecops/cicd/lab/) |

## Learning order

1. [01](01-devops-devsecops-and-ai-in-devops.md) and [02](02-ai-attacks-on-devops-teams.md) (1.5 hours of reading).
2. [03](03-model-creation-and-deployment-pipeline.md): look at the diagram, draw your own pipeline.
3. [04](04-pipeline-attacks-and-ppe.md), then the [poisoned-pipeline lab](labs/poisoned-pipeline/README.md).
4. [05 case studies](05-case-studies.md) (write the half-page exercise for one case).
5. [06 tooling](06-devsecops-tooling-for-ai.md), then the labs in this order: third-party-vulns, ai-code-weaknesses, picklescan, llm-agent-vuln-scan, llm-guard-sanitize, guard-io.
6. Notebooks when you have a Colab session.
7. The Q&As below.

## Exam tips for this chapter

- **PPE:** be able to define it, name CICD-SEC-4, and give a direct and an indirect example. Name the fix: no secrets for untrusted code, protected pipeline files, approvals.
- **Case facts to memorize:** Hugging Face (Wiz, April 2024: malicious pickle model on the Inference API, cross-tenant and shared CI/CD risk, fixed). NotPetya (June 2017: compromised update of M.E.Doc accounting software, a supply chain attack). SAP AI Core "SAPwned" (Wiz: five vulnerabilities, cluster admin and customer credentials, reported January 2024, public July 2024, fixed by 15 May 2024, SAP said no customer data was impacted).
- **Tool types:** SCA = known vulnerabilities in components; SAST = code patterns without running; DAST = running app tests; model scan = pickle and format checks; AI firewall = runtime input and output guard. Say what each cannot find.
- **Hard vs soft:** scanners and firewalls are soft. Isolation, signing, least privilege and safe formats are hard.
- **AI coding assistants:** list the risks (insecure code, hallucinated packages, secret leakage, prompt injection, excessive agency) and the controls (approved tools, SAST/SCA, review, sandbox).

## 15 exam and interview questions

<details><summary><b>Q1. What are DevSecOps principles, and what is added for AI?</b></summary>
Automation, collaboration, continuous delivery with security gates, infrastructure as code, monitoring, least privilege and supply chain integrity. For AI add controls for datasets, model files, prompts, evals and vector indexes, and secure the AI helpers in the pipeline.
</details>

<details><summary><b>Q2. List risks of AI coding assistants and how you control them.</b></summary>
Insecure suggestions, hallucinated dependencies, secrets and code leaving the company, prompt injection through repo files, excessive agency, licensing, overreliance. Controls: approved tools, secret scanning, SAST and SCA on all code, mandatory review and tests, sandboxed agents with scoped tokens, logging.
</details>

<details><summary><b>Q3. Give examples of attackers using AI against DevOps teams.</b></summary>
Convincing phishing and business email compromise, voice and video deepfake requests for access or approvals, faster reconnaissance, and criminal LLM services reported in 2023 (WormGPT, FraudGPT, many of them scams or wrappers). Defense: phishing-resistant MFA, verification procedures, mail authentication and threat intelligence.
</details>

<details><summary><b>Q4. How are models and prompts attacked in the pipeline?</b></summary>
Trojaned model files, poisoned data, prompt injection of agents that read PRs and tickets, hallucinated dependencies, poisoned pipelines, over-privileged training roles and compromised multi-tenant platforms.
</details>

<details><summary><b>Q5. Describe the model creation and deployment pipeline.</b></summary>
Collect, prepare, train or fine-tune, evaluate, register, package, deploy, run and monitor, with feedback returning to data. A CI/CD layer builds and ships every stage, so it is the most valuable target.
</details>

<details><summary><b>Q6. How does a model pipeline differ from a normal CI/CD pipeline?</b></summary>
Data is a core input, model files can run code on load, evals are statistical so backdoors can pass, training clusters have broad access, and a new model changes behavior without a code diff.
</details>

<details><summary><b>Q7. Define Poisoned Pipeline Execution, direct and indirect.</b></summary>
PPE (OWASP CICD-SEC-4): an attacker with repo or PR access but not build access changes what the pipeline runs. Direct: edit the pipeline definition. Indirect: edit a file the pipeline uses, such as a Makefile, script or test. The pipeline then runs attacker code with its secrets.
</details>

<details><summary><b>Q8. What are the main defenses against PPE?</b></summary>
No secrets or write tokens for untrusted code, secrets in protected environments on the protected branch, never run PR code in privileged triggers such as pull_request_target, code-owner review of pipeline files, approval for fork workflows, pinned actions, ephemeral runners, short-lived credentials.
</details>

<details><summary><b>Q9. What happened in the Hugging Face case (2024) and what do you learn?</b></summary>
Wiz showed a malicious pickle model could run code on the Inference API, with potential cross-tenant access and a shared CI/CD risk; Hugging Face fixed it. JFrog separately found malicious models. Learn: model files are code, isolate tenants, scan and sandbox, prefer safetensors.
</details>

<details><summary><b>Q10. Why is NotPetya relevant to AI security?</b></summary>
In June 2017 it spread through a compromised update of M.E.Doc, a Ukrainian accounting software, a classic software supply chain attack. Poisoned model or pipeline updates are trusted the same way. Use provenance checks, staged rollout, segmentation, SBOM/AI-BOM and backups.
</details>

<details><summary><b>Q11. What did the SAP AI Core ("SAPwned") research find?</b></summary>
Five vulnerabilities let researchers reach cluster admin on SAP AI Core's Kubernetes and read customers' cloud credentials and private AI artifacts. Reported 25 January 2024, public 17 July 2024, fixed by 15 May 2024, and SAP said no customer data was impacted. Lesson: tenant isolation and least-privilege credentials.
</details>

<details><summary><b>Q12. What does SCA do for an AI project and what can it miss?</b></summary>
It finds known vulnerabilities and license issues in packages, images and (with an AI-BOM) models and datasets, and gives an SBOM. It misses unpublished flaws, malicious new packages and backdoored models.
</details>

<details><summary><b>Q13. How do you statically analyze a model and an AI application?</b></summary>
Model: scan pickle-based files for dangerous imports (picklescan, ModelScan), check the format, hash and signature. Application: SAST with AI rules (unsafe deserialization, model output into eval or shell, trust_remote_code, hardcoded keys, unpinned downloads). Neither reveals behavioral backdoors.
</details>

<details><summary><b>Q14. How do you dynamically test an LLM application or agent?</b></summary>
DAST on the surrounding web/API, red-team probe suites (garak, PyRIT, promptfoo or your own) against a test copy with canaries, agent probes for goal hijack, tool misuse and excessive permissions, measure impact, repeat for non-determinism and run a small suite in CI.
</details>

<details><summary><b>Q15. What is an AI firewall, give examples, and name its limits.</b></summary>
A layer that inspects prompts, outputs and tool calls to block, redact or log (examples: LLM Guard, Lakera Guard, Azure Prompt Shields; verify features at source). Limits: soft control, false positives and negatives, added latency, and it cannot fix excess permissions or secrets in prompts.
</details>

## References

- OWASP Top 10 CI/CD Security Risks: https://owasp.org/www-project-top-10-ci-cd-security-risks/
- Wiz Research (Hugging Face, April 2024; SAP AI Core, July 2024); JFrog Security Research (2024)
- LLM Guard: https://llm-guard.com ; picklescan, garak, PyRIT, promptfoo, Bandit, Semgrep, pip-audit documentation
- Repo: [06-ai-devsecops](../../06-ai-devsecops/README.md), [02-llm-security/security-testing](../../02-llm-security/security-testing/README.md)
