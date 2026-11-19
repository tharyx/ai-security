# Lab: Vetting an Open-Weight Model's Provenance Before Routing Production Traffic

**Syllabus exercise:** Vetting an Open-Weight Model's Provenance Before Routing Production Traffic to It · **Lesson:** [04](../../04-vetting-harnesses-models-and-marketplaces.md) · **Offline, 11 tests.** Builds on [CAISP package-vetting and model-code-injection-scan](../../../../caisp-course/ch6-supply-chain-attacks-in-ai/labs).

`model_vetting.py` takes a **model card** (dict), the **hashes you computed** from downloaded files, and a policy, and returns a routing decision: `production`, `sandbox` or `reject`. Names and organizations are fictional. Nothing is downloaded.

| Check | Reject | Sandbox only |
|---|---|---|
| Hashes | declared hash mismatch; unlisted extra file | no published hashes |
| Format | pickle-style file (`.bin`, `.pt`, `.pkl`, `.ckpt`) | `trust_remote_code` required |
| Source | org looks like a typosquat of an allowlisted org | org not on the allowlist; no model card; training data undisclosed |
| Licence | not allowed (for example non-commercial) or missing | needs legal review (custom licences) |
| Evals | n/a | missing or below minimum (injection resistance, harmful refusal) |

## Run

```text
.venv/Scripts/python -m pytest caase-course/ch6-operationalizing-agentic-ai-security/labs/model-provenance-vetting
.venv/Scripts/python caase-course/ch6-operationalizing-agentic-ai-security/labs/model-provenance-vetting/demo.py
```

Real output:

```text
good                     -> production all checks passed
tampered weights         -> reject     hash mismatch for model.safetensors
unknown uploader         -> sandbox    org 'random-uploader' not on the allowlist
typosquat org            -> reject     org 'examp1e-lab' looks like a typosquat of 'example-lab'
non-commercial licence   -> reject     licence 'cc-by-nc-4.0' not allowed for production
weak injection eval      -> sandbox    eval injection_resistance=0.3 below minimum 0.7
```

`production` still means: behind guardrails, observability and a kill switch. Record the decision (and the card and hashes) in the AIBOM ([aibom-harness](../aibom-harness/README.md)).

## Break it yourself

1. Add a rule: reject models whose card lists no base model. Add a test.
2. Raise `min_eval` for injection resistance to 0.9 and see how many cards drop to sandbox. Where do real thresholds come from? (Your own evals on your own use case.)
3. Real step (optional): download a small model on your course lab machine, compute its SHA-256 and compare with the model card page.
