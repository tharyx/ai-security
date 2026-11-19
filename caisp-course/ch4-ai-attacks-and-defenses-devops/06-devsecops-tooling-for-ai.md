# 06. DevSecOps Tooling and Defenses for AI Projects

> **Syllabus:** "Software Composition Analysis for AI Projects", "Static Analysis of Models and Applications", "Dynamic Analysis of Models and Applications", "AI Firewalls for Guarding Models".
> **Time:** 2 hours + labs. Repo companions: [06 cicd](../../06-ai-devsecops/cicd/README.md) (release gate), [06 docker](../../06-ai-devsecops/docker/README.md) (pickle scan), [06 runtime-security](../../06-ai-devsecops/runtime-security/README.md) (vulnerability register, gateway, monitoring).

## Why this matters

Tools do the repeatable checks so people can think about the hard problems. For AI you need the familiar three (SCA, SAST, DAST) **extended to models and prompts**, and a new runtime layer, the AI firewall. No tool is complete. Each one is a soft layer that must sit on top of hard controls (isolation, least privilege, signing).

## Where the tools sit

| Stage (see the [pipeline picture](03-model-creation-and-deployment-pipeline.md)) | Tool type |
|---|---|
| Commit and pull request | Secret scan, SAST, SCA, IaC scan |
| Build | SCA, image scan, SBOM, sign |
| Model register / promote | Model file scan, eval and red-team suite, license check |
| Deploy | Policy as code, admission control, DAST |
| Run | AI firewall, rate limits, monitoring, SCA alerts |

## Software Composition Analysis for AI projects

**SCA** finds known vulnerabilities and license problems in the components you use, and produces an SBOM.

What to cover in an AI project (more than `requirements.txt`):

| Component | Why it matters | Tools and ideas |
|---|---|---|
| Python/JS packages | ML libraries are large and move fast | `pip-audit`, OSV-Scanner, Dependabot, Trivy, Snyk, GitHub dependency review |
| Container base images and GPU stack | CUDA and OS layers carry CVEs | Trivy, Grype, Docker Scout |
| Models and datasets | Provenance, license, known-bad models | AI-BOM (CycloneDX supports ML components), hashes, hub metadata |
| Transitive dependencies | Most findings come from them | Lock files, full dependency graph |
| Model-serving frameworks | Public services get attacked | Track advisories for your serving stack |

Practice points: pin with hashes, scan on every PR and on a schedule (new CVEs appear after release), decide a policy (block on critical, ticket on high), keep an exception process with expiry, and re-run your AI evals after upgrades. Lab: [third-party-vulns](labs/third-party-vulns/README.md) (offline analyzer + optional real `pip-audit`).

Limits: SCA only knows **published** vulnerabilities. It does not find a backdoored model or a malicious new package that has no advisory yet.

## Static Analysis of Models and Applications

**Static analysis** inspects things without running them.

**Applications (SAST).** Look at the source for dangerous patterns. AI-specific rules to add:

- `pickle.load`, `torch.load` without `weights_only=True`, `yaml.load`, `trust_remote_code=True`;
- model output flowing into `eval`, `exec`, shell, SQL, templates;
- hardcoded keys and tokens; disabled TLS verification;
- unpinned `from_pretrained` downloads;
- prompts built by string concatenation with user input; overly broad tool lists.

Tools: Bandit, Semgrep (custom rules), CodeQL, SonarQube, Ruff security rules, secret scanners (gitleaks, TruffleHog, detect-secrets). Lab: [ai-code-weaknesses](labs/ai-code-weaknesses/README.md).

**Models (static model analysis).** Look at the model file without loading it:

| Check | Tool idea |
|---|---|
| Does a pickle-based file import dangerous objects? | `picklescan`, ModelScan, Fickling (analysis), the repo's pickle scanner. Lab: [picklescan](labs/picklescan/README.md) |
| Is the format data-only? | Prefer safetensors |
| Are the hash and signature right? | Sigstore/cosign, OpenSSF Model Signing |
| Are there embedded or unexpected layers/operators? | Format-specific inspection (ONNX checkers, graph review) |
| License and provenance | Model card review, AI-BOM |

Limits: a static scan can be evaded and can say nothing about **behavior** (a backdoor in weights looks like numbers). That is why you also need dynamic testing.

## Dynamic Analysis of Models and Applications

**Dynamic analysis** runs the thing and watches what happens.

| Target | Technique | Tools |
|---|---|---|
| Web/API around the model | DAST: scan a running app for injection, auth and config flaws | OWASP ZAP, Burp Suite, Nuclei |
| The model's behavior | Red-team probes: prompt injection, jailbreaks, data leakage, encoding tricks | garak, PyRIT, promptfoo, in-house suites ([02 security-testing](../../02-llm-security/security-testing/README.md)) |
| Agents | Probe goal hijack, tool misuse, excessive permissions; check impact | Lab: [llm-agent-vuln-scan](labs/llm-agent-vuln-scan/README.md) |
| Robustness | Adversarial inputs, drift and stress tests | TextAttack, ART (Adversarial Robustness Toolbox) |
| Model loading and serving | Run the model in a sandbox and watch syscalls, files, network (a behavioral check for model files) | gVisor, Falco, container sandboxes |
| Runtime | Monitoring, canaries, anomaly alerts | See [06 runtime-security](../../06-ai-devsecops/runtime-security/README.md) |

Tips: run probes against a **test copy** with canary data, measure **impact** (a tool ran, a canary leaked), repeat runs because real models are non-deterministic, and put a small suite in CI so regressions fail the build. Vendor claims about detection rates are not evidence for your system: test on your own data.

## AI Firewalls for Guarding Models

An **AI firewall** (also called an AI gateway or guardrail layer) sits between users and a model, and often between the model and its tools. It inspects traffic in both directions and can allow, block, redact or log.

```text
user -> [ input checks ] -> model -> [ output checks ] -> user
                |                          |
        logging, policy, rate limits, tool-call checks
```

What they commonly do:

| Direction | Function |
|---|---|
| Input | Prompt-injection and jailbreak detection, PII and secret detection with redaction, topic and policy rules, length limits |
| Output | Sensitive-data and PII redaction, link and markdown-image control, toxicity and policy checks, relevance and hallucination checks |
| Tool calls | Allowlist tools and arguments, require approval for risky calls |
| Operations | Rate limits, cost budgets, logging and audit, alerting |

Examples to know by name (check each product's documentation for current features; this course makes no vendor claims):

- **LLM Guard** (open-source scanner library for prompts and outputs).
- **Lakera Guard** (commercial prompt-injection and content protection API).
- **Prompt Shields** (part of Azure AI Content Safety).
- Cloud model guardrails (for example in managed model services) and open-source guardrail frameworks such as NeMo Guardrails or Guardrails AI.

How to judge one: what threats does it cover; detection quality on **your** attacks and benign traffic (false positives matter); latency and cost; can it fail closed; what is logged and where data goes; can you tune it; does it work for tool calls and RAG content.

What it cannot do: stop everything (new paraphrases get through), replace least privilege, or fix a design that puts secrets in the prompt. Treat it as one soft layer. Labs: [llm-guard-sanitize](labs/llm-guard-sanitize/README.md), [guard-io](labs/guard-io/README.md), and the real library in [the notebook](notebooks/llm-guard-real.ipynb) (not executed by the repo author).

## Putting it together: a minimal CI gate for an AI repo

1. Secret scan and SAST (with AI rules) on every PR.
2. SCA and image scan; fail on critical.
3. Model file scan and format check before registering a model.
4. Small red-team and eval suite; fail on regression.
5. Signed artifacts; deploy only signed, approved, scanned models from a protected branch.
6. AI firewall and monitoring at runtime.

The repo's [release gate](../../06-ai-devsecops/cicd/README.md) implements the "all evidence must exist" logic for steps 1 to 5.

## Interview Q&A

<details><summary><b>Q1. What does SCA add for an AI project that a plain dependency check misses?</b></summary>
Coverage of model and dataset provenance (an AI-BOM), the GPU and container stack, and transitive dependencies in ML libraries, plus re-running evals after upgrades. It still cannot find a backdoor or an unpublished malicious package.
</details>

<details><summary><b>Q2. Static versus dynamic analysis of a model: when do you need each?</b></summary>
Static (pickle/format scan, hashes, signatures) catches code-execution tricks and tampering before loading. Dynamic (red-team probes, sandboxed runs, behavior monitoring) catches behavior problems such as backdoors, leaks and injection. You need both.
</details>

<details><summary><b>Q3. What is an AI firewall and what are its limits?</b></summary>
A layer that inspects prompts, outputs and tool calls to block, redact or log. Limits: it is a soft control with false negatives and positives, it cannot fix excessive permissions or secrets in the prompt, and it adds latency. Use it with least privilege and data minimization.
</details>

<details><summary><b>Q4. Which AI-specific SAST rules would you add first?</b></summary>
Unsafe deserialization (pickle, torch.load, yaml.load), model output into eval/exec/shell/SQL, trust_remote_code=True, hardcoded keys, disabled TLS verification and unpinned model downloads.
</details>

## References

- OWASP ZAP, Semgrep, Bandit, pip-audit, OSV-Scanner documentation
- picklescan (PyPI/GitHub), ModelScan (Protect AI), garak (NVIDIA), PyRIT (Microsoft), promptfoo
- LLM Guard documentation: https://llm-guard.com ; vendor docs for Lakera Guard and Azure AI Content Safety (verify at source)
- Repo: [06-ai-devsecops](../../06-ai-devsecops/README.md), [02 security-testing](../../02-llm-security/security-testing/README.md)
