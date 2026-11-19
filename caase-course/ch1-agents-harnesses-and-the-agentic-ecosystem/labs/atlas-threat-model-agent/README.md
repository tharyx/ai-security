# Lab: Threat-model an agentic system with MITRE ATLAS and OWASP ASI

**Course exercise:** Threat Modeling an Agentic AI System Using MITRE ATLAS.
**Time:** 60 minutes. Standard library plus `pyyaml`. Offline.

## What it does

You describe an agentic system as YAML (components, their type, whether they read untrusted input, side effects, reversibility, privileges, data sensitivity, controls, and the system's autonomy level). `threatmodel.py` applies rules per component type and produces **findings**: each has a threat, **ATLAS tactics**, **OWASP ASI items**, **OWASP LLM 2026** ids, a likelihood (1 to 5), an impact (1 to 5), a score and a level, plus the **controls that are missing**.

Two example systems are included: `system.yaml` (a weak design of an inbox assistant) and `system-hardened.yaml` (the same assistant after review).

Risk method (see [lesson 04, section 2.6](../../04-threat-modeling-and-risk-frameworks.md#26-rating-agentic-specific-risks)):

- **Impact** from the top two of privileges, data sensitivity, blast radius and irreversibility, plus 1 if autonomy is 3 or higher.
- **Likelihood** starts from exposure (untrusted input or internet exposure: 4; reachable by injection from elsewhere in the system, for side-effect components: 4; third-party: 3; otherwise 2) and drops by one for each control that mitigates that threat.
- **Score** = likelihood x impact. Levels: low under 5, medium 5 to 9, high 10 to 14, critical 15 and above.

> Tactic names follow the course's 14 (for example "ML Model Access"). Current ATLAS renamed some (for example "AI Model Access"). Check atlas.mitre.org. The mapping is a **starting point for a human review**, not an authoritative classification.

## Files

| File | Purpose |
|---|---|
| `system.yaml`, `system-hardened.yaml` | Example systems (made up) |
| `threatmodel.py` | `load`, `analyze`, `summary`, `report`, `impact_of`, `likelihood_of`, `RULES` |
| `demo.py` | Prints the weak design's report and compares both |
| `test_caase_ch1_threatmodel.py` | 11 tests |

## Run

```text
.venv/Scripts/python caase-course/ch1-agents-harnesses-and-the-agentic-ecosystem/labs/atlas-threat-model-agent/demo.py
.venv/Scripts/python -m pytest caase-course/ch1-agents-harnesses-and-the-agentic-ecosystem/labs/atlas-threat-model-agent -v
```

Real output (table shortened to the first rows; the demo prints all 12):

```text
# Threat model: Inbox Assistant (example, weak design)

autonomy=3  findings=12  total_score=191  critical/high=12

| Level | Score | Component | Threat | ATLAS tactics | ASI | LLM 2026 |
|---|---|---|---|---|---|---|
| critical | 20 (L4 x I5) | send_mail_tool | Tool misuse or exfiltration through a side-effect tool | Exfiltration, Impact | ASI02 | LLM03 |
| critical | 20 (L4 x I5) | send_mail_tool | Identity and privilege abuse (shared or broad credentials) | Privilege Escalation, Credential Access | ASI03 | LLM03 |
| critical | 20 (L4 x I5) | code_runner | Unexpected code execution | Execution, Privilege Escalation | ASI05 | LLM10 |
| critical | 16 (L4 x I4) | mail_reader | Prompt injection through untrusted content | Initial Access, Execution | ASI01 | LLM01 |
| critical | 16 (L4 x I4) | notes_memory | Memory and context poisoning | Persistence, Defense Evasion | ASI06 | LLM05 |
| critical | 16 (L4 x I4) | helper_agent | Insecure inter-agent communication and cascades | Initial Access, Defense Evasion | ASI07, ASI08 | LLM06 |
| critical | 16 (L4 x I4) | system | Unchecked autonomy: runaway or rogue behaviour, misplaced human trust | Impact, Defense Evasion | ASI09, ASI10 | LLM03 |
| critical | 15 (L3 x I5) | crm_mcp | Malicious or compromised third-party tool, server or skill | Resource Development, Initial Access | ASI04 | LLM04 |
| high | 12 (L3 x I4) | model_router | Model access abuse and data leaving the boundary | ML Model Access, Reconnaissance, Collection | - | LLM02, LLM06 |
...

weak      findings=12 total_score=191 max=20 critical/high=12 ASI hit=10/10 tactics hit=12/14
hardened  findings= 9 total_score= 36 max= 6 critical/high= 0 ASI hit=7/10 tactics hit=8/14
```

The hardened design lowers the total from 191 to 36. The seven remaining ASI items are still present (a hardened system is **not** risk free); they are now medium or low and have controls.

## What the five biggest changes were

| Change in `system-hardened.yaml` | Effect |
|---|---|
| Autonomy 3 to 2, and approval on the mail tool, memory and code runner | Lower impact everywhere; removes the system-level "unchecked autonomy" finding |
| Mail tool: scoped credential, recipient allowlist and egress filter | Tool misuse and identity abuse drop from critical to medium or low |
| Third-party MCP server and skill hub: signing, allowlist, sandbox | Supply-chain risk drops |
| Model route kept local with DLP and a budget | Data no longer leaves the boundary |
| Memory writes gated by provenance and approval | Poisoning drops |

## Exercises

1. Describe **your own agent** in a new YAML file and run `report`. Argue with at least two findings.
2. Add a rule for a **scheduler** or **messaging gateway** component (autonomy without a human). Map it to ATLAS tactics and an ASI item, and add tests.
3. Add a `reversible: false` flag to a `code_runner` and see the impact change.
4. Write the **residual risk** statement for the top finding, in the report form shown in lesson 04.

## Limits

The rules are simple and deliberately readable. They miss attack paths that need several components (a chain from a skill to memory to a tool). Use a real threat modeling method ([CAISP chapter 5](../../../../caisp-course/ch5-threat-modeling-ai-systems/README.md)) for chains.
