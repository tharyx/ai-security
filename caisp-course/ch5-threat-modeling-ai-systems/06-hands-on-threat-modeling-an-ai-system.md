# Lesson 06: Hands-on: threat modeling an AI system

> **Chapter 5** · **Time:** ~3 hours · **You will:** take the support chatbot (LLM + RAG + a ticket tool) from a YAML DFD to a ranked risk register, harden it, and compare before and after.

| | |
|---|---|
| **Syllabus line** | Hands-On Exercises: Threat Modeling an AI System |
| **Lab folder** | [`labs/threat-model-ai-system/`](labs/threat-model-ai-system/) |
| **Files** | [`dfd.yaml`](labs/threat-model-ai-system/dfd.yaml) (system) · [`threat_library.yaml`](labs/threat-model-ai-system/threat_library.yaml) (20 paraphrased entries) · [`tm_tool.py`](labs/threat-model-ai-system/tm_tool.py) (validator, STRIDE, rating, register, Mermaid) · [`demo.py`](labs/threat-model-ai-system/demo.py) · [`test_tm_tool.py`](labs/threat-model-ai-system/test_tm_tool.py) (17 tests) |
| **Prerequisites** | Lessons [01](01-threat-modeling-foundations.md) to [05](05-rating-and-managing-risks.md) |
| **Needs** | Python 3.11+, `pydantic`, `pyyaml` (already in the repo's venv). No network, no API keys. |

The course exercise uses a commercial tool (IriusRisk). This lab teaches the same steps with code, so you can run it on a laptop and keep the model in Git.

---

## 1. The pipeline

```text
dfd.yaml --load_dfd--> validate_dfd --stride_threats + threat_library.yaml--> rate --> build_register --> table / JSON / CSV
                                  \--> to_mermaid --> diagram
```

## 2. Step by step

All commands run from the repository root. Prefix with `.venv/Scripts/python` on Windows.

### Step 1: run the tests

```bash
python -m pytest caisp-course/ch5-threat-modeling-ai-systems
```

Expected: `17 passed`.

### Step 2: read the system

Open [`dfd.yaml`](labs/threat-model-ai-system/dfd.yaml). Find the five assets, four zones, ten elements and thirteen flows. Compare with the [DFD picture](../../images/caisp-ch5-llm-dfd.svg).

### Step 3: validate and generate threats

```bash
python caisp-course/ch5-threat-modeling-ai-systems/labs/threat-model-ai-system/tm_tool.py \
    caisp-course/ch5-threat-modeling-ai-systems/labs/threat-model-ai-system/dfd.yaml | head -12
```

Real output from our run (top of the register, sorted by residual severity):

```text
ID    STRIDE SEVERITY  STATUS     OWASP LLM (2023)         THREAT / WHERE
T040  E      CRITICAL  open       LLM07, LLM08             Tool runs with more rights than the user who asked @ ticket_tool (Ticket tool)
T069  T      CRITICAL  open       LLM01                    Indirect prompt injection through retrieved or ingested content @ F6: Retriever -> Chat API and orchestrator (context chunks)
T019  T      CRITICAL  open       LLM01                    Indirect prompt injection through retrieved or ingested content @ ingest (Ingestion pipeline)
T087  T      CRITICAL  open       LLM01                    Indirect prompt injection through retrieved or ingested content @ F11: Public web pages and uploaded files -> Ingestion pipeline (raw documents)
T015  I      CRITICAL  open       LLM06                    Another tenant or user's data is retrieved or revealed @ retriever (Retriever)
```

The exit code is `1` because open High or Critical threats exist. In CI this blocks the merge, like a failing test.

**What to notice:** 96 threats in total (STRIDE per element on 10 elements and 13 flows). The Critical ones follow the paths that the DFD marks: untrusted content (F6, F11), the tool (E), and the vector store (I).

### Step 4: look at the full record of one threat

```bash
python caisp-course/ch5-threat-modeling-ai-systems/labs/threat-model-ai-system/tm_tool.py \
    caisp-course/ch5-threat-modeling-ai-systems/labs/threat-model-ai-system/dfd.yaml --format json | head -40
```

Each record has the STRIDE letter, the library id, OWASP LLM categories (2023 names), ATLAS technique names, the BIML-style component and theme, likelihood, impact, inherent and residual severity, present and missing controls, and a suggested treatment.

For `T040` (real values):

```text
controls_present = []   controls_missing = ['authn', 'human_approval', 'tool_authz']
likelihood = 7.5  impact = 7.25  severity = CRITICAL  status = open
treatment = mitigate now (or avoid the feature)
```

### Step 5: harden the design and compare

```bash
python caisp-course/ch5-threat-modeling-ai-systems/labs/threat-model-ai-system/demo.py
```

Real output (shortened):

```text
System: Support chatbot with RAG and a ticket tool
DFD issues: none

STRIDE per element produced 96 threats. Top 8:
...
Open threats by residual severity: {'CRITICAL': 13, 'HIGH': 21, 'MEDIUM': 42, 'LOW': 0, 'NOTE': 0}
After adding tool_authz, human_approval, validation, limits, ACL filter, flow checks:
Open threats by residual severity: {'CRITICAL': 2, 'HIGH': 8, 'MEDIUM': 36, 'LOW': 0, 'NOTE': 0}
Blocking (open High/Critical): 34 -> 10
```

The demo adds controls in the YAML data (not in code): `tool_authz`, `human_approval`, `schema_validation`, `rate_limit`, `token_budget`, `acl_filter` and `integrity_check` on the orchestrator, ticket tool, retriever and vector DB, and checks on the flows that carry untrusted content. Blocking findings go from 34 to 10.

> The 10 that remain are a useful lesson. Some come from the `GENERIC` fallback (no library entry), some from controls we did not add. A threat model is never "done": you decide which remaining risks to mitigate, transfer or accept.

### Step 6: draw the DFD from the same file

```bash
python caisp-course/ch5-threat-modeling-ai-systems/labs/threat-model-ai-system/tm_tool.py \
    caisp-course/ch5-threat-modeling-ai-systems/labs/threat-model-ai-system/dfd.yaml --mermaid
```

Real output (start):

```text
flowchart LR
  subgraph internet["Internet (untrusted)"]
    user["Customer"]
    kb_source["Public web pages and uploaded files"]
  end
  subgraph app["Our application network (semi)"]
    orchestrator(("Chat API and orchestrator"))
    ...
  user -->|"F1: user prompt"| orchestrator
```

Paste the output into <https://mermaid.live>. Each `subgraph` is a trust zone; circles are processes, cylinders are data stores, rectangles are entities.

### Step 7: break it on purpose (predict, then run)

1. **Invalid DFD.** Add `{id: F14, source: user, target: vdb}` to `flows:`. *Predict:* error. *Real message:* `flow F14: external_entity -> data_store has no process end. Data never moves by itself; a process must read or write it.` The tool exits with code 2.
2. **Remove a control.** Delete `authn` from `vdb`. *Predict:* threats on `vdb` with `authn` in `mitigated_by` (TL-05) go up.
3. **Raise an asset.** Set asset `A1` (customer PII) to `9`. *Predict:* business impact of `TL-10` (cross-tenant disclosure) rises. A test checks this.
4. **Add a new tool** (an `email_tool` with `tags: [tool, side_effect]` and a flow from the orchestrator). *Predict:* new Elevation-of-privilege threats appear for the new element.
5. **Write a library entry** for one `GENERIC` row (lesson 04) and see the count drop.

### Step 8: write the deliverable

For the top five threats, fill a risk-register row (see lesson 05, section 4) with a treatment, an owner and a review date. Then add one security requirement per treatment, for example *"The ticket tool must call the ticket API with the end user's token, never a shared service account."*

## 3. How this maps to the course exercise (IriusRisk)

| Course step (tool-based) | In this lab |
|---|---|
| Import / draw architecture | `dfd.yaml`, `to_mermaid()` |
| Questionnaire and templates | `tags:` on elements and flows |
| Rules generate threats and countermeasures | `threat_library.yaml` + `stride_threats()` |
| Risk rating | `rate()`, OWASP matrix |
| Mark countermeasures implemented | `controls:` lists; `status: controlled` |
| Reports | `--format json`, `--format csv`, table |

## 4. Limits of this lab (say them in an interview)

* The library has 20 entries written by us. It is a teaching sample, not a complete AI threat catalogue.
* The scores are plausible defaults, not calibrated numbers. Your organization must set its own.
* Control effect is crude: each present, relevant control lowers the vulnerability score by 3. Real effectiveness depends on correct implementation, which you test separately.
* It models design-level threats, not implementation bugs.

## 5. Checklist (definition of done)

- [ ] All 17 tests pass.
- [ ] I can explain every column of the register.
- [ ] I produced a Mermaid diagram and checked the trust zones.
- [ ] I added one new threat-library entry and one new element.
- [ ] I wrote treatments, owners and review dates for the top five risks.
- [ ] I can explain why a prompt rule alone did not lower a High threat.

## 6. References

* Lessons [03](03-stride-for-llm-apps.md), [04](04-ai-threat-libraries.md) and [05](05-rating-and-managing-risks.md) of this chapter
* [Module 01 lab `threat_model.py`](../../01-ai-security-fundamentals/lab/threat_model.py) for rule-based design analysis (taint, lethal trifecta)
* Mermaid documentation: mermaid.js.org
