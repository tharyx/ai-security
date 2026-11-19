# Chapter 7: Emerging Threats, AI Governance and Compliance

Course outcomes: *Defend against AI worms and backdoor threats; Apply NIST RMF and ISO/IEC 42001 standards; Learn the EU AI Act and US AI legislation.*

> **Educational, not legal advice.** Laws and standards change. Anything marked "verify at source" must be checked on the official site before you rely on it.

## Syllabus coverage

| Syllabus item | Where to study | Lab |
|---|---|---|
| Emerging Threats in AI | [01 Emerging threats in AI](01-emerging-threats-in-ai.md) | |
| Model-mediated supply chain attacks | [01, section 2.1](01-emerging-threats-in-ai.md#21-model-mediated-supply-chain-attacks); also [Model threats](../../02-llm-security/model-threats/README.md) | [Model threats lab](../../02-llm-security/model-threats/lab/) |
| Self propagating AI model worms | [01, section 2.2](01-emerging-threats-in-ai.md#22-self-propagating-ai-model-worms) | [labs/ai-worm-simulation](labs/ai-worm-simulation/) |
| Backdoors in Fine-Tuning | [01, section 2.3](01-emerging-threats-in-ai.md#23-backdoors-in-fine-tuning) | [labs/fine-tuning-backdoor](labs/fine-tuning-backdoor/) |
| AI assisted evolving firmware | [01, section 2.4](01-emerging-threats-in-ai.md#24-ai-assisted-evolving-firmware-forward-looking) (forward-looking, conceptual) | Concept only; no lab |
| Models without provenance | [01, section 2.5](01-emerging-threats-in-ai.md#25-models-without-provenance); signing in [Chapter 6](../ch6-supply-chain-attacks-in-ai/README.md) | [Chapter 6 labs](../ch6-supply-chain-attacks-in-ai/README.md) |
| AI Governance and Compliance | [02 Governance](02-governance-standards-and-frameworks.md); [Module 07](../../07-ai-governance/README.md); [Module 08](../../08-ai-compliance/README.md) | [07 lab](../../07-ai-governance/lab/), [08 lab](../../08-ai-compliance/lab/) |
| Standards, Guidelines, Frameworks, Checklists for AI Security | [02, sections 1, 3 and 4](02-governance-standards-and-frameworks.md#3-the-landscape-what-each-one-is-what-it-is-and-when-to-use-it) | |
| NIST RMF | [02, section 2](02-governance-standards-and-frameworks.md#2-nist-rmf-two-different-things) (AI RMF + AI 600-1, and SP 800-37); [07 lesson 03](../../07-ai-governance/03-ai-risk-management.md) | [07 risk register lab](../../07-ai-governance/lab/) |
| ISO/IEC 42001 | [07 lesson 04](../../07-ai-governance/04-iso-42001-ai-management-system.md); [02, section 3](02-governance-standards-and-frameworks.md) | [07 lab](../../07-ai-governance/lab/) |
| Other standards and guidelines | [02, section 3](02-governance-standards-and-frameworks.md) (ISO 23894, 27001, OWASP, CSA AICM and MAESTRO, SAIF, NCSC); [08 lesson 05](../../08-ai-compliance/05-iso-standards-and-law-vs-standard.md) | [08 lab](../../08-ai-compliance/lab/) |
| AI Acts, Bills, and Legislations | [03 EU summary](03-eu-ai-act-summary.md), [04 US legislation](04-us-ai-legislation.md) | [08 lab](../../08-ai-compliance/lab/) |
| EU AI Act | [03 EU AI Act summary](03-eu-ai-act-summary.md); full: [08 lesson 01](../../08-ai-compliance/01-eu-ai-act.md) | [AI Act classifier lab](../../08-ai-compliance/lab/ai_act_classifier.py) |
| US Legislations | [04 US AI legislation](04-us-ai-legislation.md) | |
| Hands-On Exercises: Working with AI Agents | [Agent security module](../../05-agent-security/README.md); lab below | [labs/working-with-ai-agents](labs/working-with-ai-agents/) |
| Hands-On Exercises: Abusing AI Agents | [Agent permissions](../../05-agent-security/permissions/README.md), [multi-agent trust](../../05-agent-security/multi-agent-trust/README.md), [monitoring and response](../../05-agent-security/monitoring-and-response/README.md), [mini project](../../05-agent-security/mini-project/README.md); lab below | [labs/abusing-ai-agents](labs/abusing-ai-agents/) |

Not fully covered: **AI assisted evolving firmware** has no public incident to cite and is taught as a conceptual, forward-looking risk on purpose. There is no notebook in this chapter; the labs are offline.

## Learning order

1. [01 Emerging threats](01-emerging-threats-in-ai.md), then run the worm and backdoor labs.
2. [02 Governance](02-governance-standards-and-frameworks.md), then read [07 lessons 03 and 04](../../07-ai-governance/03-ai-risk-management.md).
3. [03 EU AI Act summary](03-eu-ai-act-summary.md), then [08 lesson 01](../../08-ai-compliance/01-eu-ai-act.md).
4. [04 US legislation](04-us-ai-legislation.md).
5. The two agent labs (build, then abuse and harden).

## Run the labs

From the repository root (`.venv/Scripts/python` on Windows). All labs are offline and use harmless canaries.

```bash
.venv/Scripts/python -m pytest caisp-course/ch7-emerging-threats-governance-compliance
cd caisp-course/ch7-emerging-threats-governance-compliance/labs/ai-worm-simulation && ../../../../.venv/Scripts/python demo.py
```

(Each `demo.py` is run from its own lab folder: `ai-worm-simulation`, `fine-tuning-backdoor`, `working-with-ai-agents`, `abusing-ai-agents`.)

### Lab 1: AI worm simulation (8 tests; 53 tests in the whole chapter)

Ten mock email agents with RAG over their inboxes and an auto-reply tool. A harmless canary "worm" copies itself from inbox to inbox. Real output:

```text
case                         infected agents, rounds 1-6    msgs held benign
no defenses                  [1, 4, 7, 10, 10, 10]          2550    0    6
rate limit (1 msg/agent)     [1, 2, 3, 3, 3, 3]               10    0    8
taint (no fan-out)           [1, 1, 1, 1, 1, 1]                9    0    9
replication block            [1, 1, 1, 1, 1, 1]                9    0    9
approval, nobody approves    [1, 1, 1, 1, 1, 1]                0   15    0
approval, careful human      [1, 1, 1, 1, 1, 1]                9    6    9
all hard layers              [1, 1, 1, 1, 1, 1]                9    0    9
```

Rate limiting only slows the worm; taint, replication detection and no-auto-send each stop it alone.

### Lab 2: Fine-tuning backdoor (6 tests)

A toy model with a year-string trigger. The backdoor survives a clean-data "safety fine-tune"; a probe finds the trigger; an adapter diff flags it. See the output in [lesson 01, section 2.3](01-emerging-threats-in-ai.md#23-backdoors-in-fine-tuning). It is a teaching toy, not proof about real models.

### Lab 3: Working with AI agents (5 tests)

A plan, tool, observe loop with a calculator (AST-based, no `eval`), a sandboxed file reader and a notes tool. Real output:

```text
TASK: calculate 2*(3+4) then read hello.txt then note: checked hello then list notes
  step 1: calculator({'expression': '2*(3+4)'}) -> 14
  step 2: read_file({'path': 'hello.txt'}) -> Hello from the sandbox directory.
  step 3: notes_add({'text': 'checked hello'}) -> saved note #1
  step 4: notes_list({}) -> checked hello
FINAL: Done. Results: 14 | Hello from the sandbox directory. | saved note #1 | checked hello
Try escaping the sandbox: ERROR: PermissionError: path outside sandbox: ../../etc/pass
```

### Lab 4: Abusing AI agents (36 tests)

The same agent, with extra powerful tools, is attacked five ways (indirect injection exfiltration, secret read through path traversal, excessive agency delete, goal hijack, runaway loop). Then it is hardened with eight switchable layers: tool allowlist per task, plan lock, path sandbox, approvals, budgets, final-answer gate (hard), sanitizing and structured output (soft). Real output:

```text
attack       vulnerable   hardened (all layers)
exfil        ATTACK WORKED blocked
secret_read  ATTACK WORKED blocked
delete       ATTACK WORKED blocked
hijack       ATTACK WORKED blocked
loop         ATTACK WORKED blocked

Benign task on hardened agent: Done. Results: Q3 report: revenue is stable. Costs are down. | 42
Loop attack on vulnerable agent: 25 tool calls, final = 'STOPPED: step budget exhausted'
Loop attack on hardened agent  : 1 tool calls, denials = []
```

Tests prove each attack is stopped by at least two single layers alone, including hard ones. Goal hijack is contained by the hard `final_gate` layer (the harness builds the answer from its own tool results and discards model-written text), and `test_goal_hijack_contained_with_soft_layers_off` proves it with sanitizing and structured output off. A hijacked answer that merely echoes data can still mislead, so keep human review on high-impact answers. For depth see [05-agent-security](../../05-agent-security/README.md). This lab loads the base agent from the sibling `working-with-ai-agents` lab by path.

## Exam tips

- Know that **NIST RMF** can mean the AI RMF (GOVERN, MAP, MEASURE, MANAGE) or SP 800-37 (seven steps). The course means the AI RMF.
- Separate **law** (EU AI Act, state laws), **certifiable standard** (ISO/IEC 42001, 27001), **framework** (NIST AI RMF), and **checklist** (OWASP).
- For every emerging threat, name the **hard control outside the model**.
- Say "forward-looking" for evolving firmware; do not claim incidents.
- US: no federal AI Act; executive orders cannot repeal state law; state laws differ. Always add "verify at source" for dates.
- EU: Omnibus dates are 2 Dec 2027 (Annex III) and 2 Aug 2028 (Annex I).

## 15 exam-style questions

<details><summary><b>Q1. What is a model-mediated supply chain attack?</b></summary>

The model or assistant is the delivery path: it suggests or writes insecure code or a malicious dependency (for example a hallucinated package name that an attacker registered, called slopsquatting). Defend with a dependency allowlist, lockfile with hashes, CI gates and review of AI-written code.
</details>

<details><summary><b>Q2. How does an AI worm like Morris II spread?</b></summary>

A self-replicating prompt sits in an email. An assistant that reads it (often via RAG) follows it, copies it into its output and sends it on through an auto-send tool. It needs a model that obeys data, an auto-send tool and a channel read by other AIs. It was a 2024 research demonstration.
</details>

<details><summary><b>Q3. Which worm defenses are hard and which only slow?</b></summary>

Hard: no auto-send without approval, taint policy (no fan-out from untrusted content), replication detection. Rate limits only slow it (3 agents still infected after 6 rounds in the lab). Also purge poisoned items from the RAG index.
</details>

<details><summary><b>Q4. What does a sleeper-agent style backdoor do, and what did the Anthropic paper (Jan 2024) report?</b></summary>

It behaves normally until a trigger appears. The paper reported that deliberately trained backdoors could persist through standard safety training, so passing normal tests is not enough. Research setting; verify details.
</details>

<details><summary><b>Q5. Why did the toy backdoor survive the clean "safety fine-tune"?</b></summary>

Training updates only what the data touches; clean data without the trigger never changes the trigger's weight. Real model persistence is an empirical finding, not a guarantee.
</details>

<details><summary><b>Q6. How do you defend against fine-tuning backdoors?</b></summary>

Trusted signed models and adapters, controlled fine-tuning data, adapter and weight diffs, trigger scans and red teaming, and least privilege for model output (sandbox, no auto-merge). Detection is incomplete, so the output's power must be limited.
</details>

<details><summary><b>Q7. How should you describe AI-assisted evolving firmware?</b></summary>

As an emerging, forward-looking risk: AI might help attackers vary or customize firmware implants to evade signature detection. It still needs access and persistence. Use secure boot, signed firmware, attestation, SBOM and behavior monitoring. No incident is claimed.
</details>

<details><summary><b>Q8. What is a model without provenance and how do you handle it?</b></summary>

An unsigned model of unknown origin (pickle code execution, tampering, impersonation risk). Use verified publishers, signatures (OMS, Sigstore), safetensors, scanning, an internal registry with hash pinning, and a sandboxed test load.
</details>

<details><summary><b>Q9. What are the two meanings of NIST RMF?</b></summary>

NIST AI RMF 1.0 (AI 100-1) with four functions GOVERN, MAP, MEASURE, MANAGE (plus the GenAI Profile AI 600-1); and NIST SP 800-37 RMF with seven steps (Prepare, Categorize, Select, Implement, Assess, Authorize, Monitor) for information systems.
</details>

<details><summary><b>Q10. What is ISO/IEC 42001 and how does it relate to 23894 and 27001?</b></summary>

42001 is the certifiable AI management system standard. 23894 is guidance for AI risk management inside it. 27001 is the information security management system that provides the base. All are voluntary unless a customer or regulator requires them.
</details>

<details><summary><b>Q11. Law, standard, framework, checklist: examples?</b></summary>

Law: EU AI Act, US state laws. Standard: ISO/IEC 42001. Framework: NIST AI RMF. Checklist or catalog: OWASP lists, MITRE ATLAS.
</details>

<details><summary><b>Q12. What are the EU AI Act dates after the Digital Omnibus?</b></summary>

Regulation (EU) 2026/1744 entered into force on 27 July 2026. Stand-alone high-risk (Annex III) obligations apply from 2 December 2027, embedded high-risk (Annex I) from 2 August 2028. Prohibitions and GPAI duties were not moved. Verify at source.
</details>

<details><summary><b>Q13. Is there a US federal AI law? Can an executive order cancel state laws?</b></summary>

No comprehensive federal AI statute, and no federal statute broadly preempts state AI laws. Executive orders (EO 14110 revoked Jan 2025; AI Action Plan 23 July 2025; EO 14365 Dec 2025 creating an AI Litigation Task Force) cannot repeal state law. Verify at source.
</details>

<details><summary><b>Q14. Name key state laws.</b></summary>

California SB 53 (frontier AI transparency) and Texas TRAIGA (HB 149), both effective 1 January 2026; Colorado SB24-205 replaced by SB 26-189 (effective 1 January 2027); NYC Local Law 144 (automated employment decision tools); Utah AI laws. Also the federal TAKE IT DOWN Act on non-consensual intimate imagery including AI deepfakes. Verify at source.
</details>

<details><summary><b>Q15. How do you harden an agent against indirect injection and tool misuse?</b></summary>

Per-task tool allowlist, plan lock (calls must match planned steps), path sandbox, human approval for sensitive tools, step and call budgets, plus soft layers (sanitizing data, structured output). Hard layers must hold even if the model is fooled. See the abusing-ai-agents lab and 05-agent-security.
</details>

## References

- Lessons in this chapter: [01](01-emerging-threats-in-ai.md), [02](02-governance-standards-and-frameworks.md), [03](03-eu-ai-act-summary.md), [04](04-us-ai-legislation.md).
- Repo: [05-agent-security](../../05-agent-security/README.md), [02 model threats](../../02-llm-security/model-threats/README.md), [07 AI governance](../../07-ai-governance/README.md), [08 AI compliance](../../08-ai-compliance/README.md).
- Primary sources: NIST AI 100-1, AI 600-1, SP 800-37; ISO/IEC 42001; EUR-Lex (Regulation 2024/1689 and 2026/1744); Morris II paper (2024); Anthropic "Sleeper Agents" (Jan 2024); OWASP GenAI Security Project.
