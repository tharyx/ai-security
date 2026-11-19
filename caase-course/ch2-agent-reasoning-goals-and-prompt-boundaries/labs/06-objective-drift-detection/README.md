# Lab 06: Detecting Objective Drift Through Structured Output Validation

> **Chapter 2 exercise:** Detecting Objective Drift Through Structured Output Validation
> **Study first:** [Lesson 04, sections 2.3, 2.5 and 2.6](../../04-defending-goals-and-reasoning.md#23-structured-output-enforcement)
> **Generic material in this repo:** [05-agent-security/monitoring-and-response](../../../../05-agent-security/monitoring-and-response/README.md) · [05-agent-security/permissions](../../../../05-agent-security/permissions/README.md)

Offline, harmless and tested. No network, no API key, no GPU, no Docker needed by the tests. Secrets are canaries or clearly fake values; domains end in `.example`. The model is a `MockLLM` subclass: deterministic and deliberately gullible. The lab is **self-contained** (it does not import code from another lab).

## What it simulates

The planner must answer in a strict JSON plan. A poisoned tool output makes it **replan** with an extra off-objective step (an e-mail to an outside address), or with a subtle one (an allowed tool used for an unrelated purpose). A validator checks the schema, then compares each step to the **original objective**, computes a drift score, and **fails safe**: staged side effects are discarded and the run halts.

## Files

`drift.py` (pydantic `Plan`/`Step`, `PlannerLLM`, `validate_plan`, `DriftGuardedAgent`) · `demo.py` · `test_caase_ch2_drift.py`

## Vulnerable vs defended

| | |
|---|---|
| **Vulnerable** | Replans are accepted as they come; effects run immediately. |
| **Defended** | Schema with `extra=forbid`, enum tool names and size bounds; per-step goal-integrity checks (tool in the objective set, purpose mentions an objective keyword, bounded arguments, same objective id and digest); drift score; staged commit; **fail-safe tests**: validator crash and prose instead of JSON both end in `HALTED_SAFE` with nothing committed. |

## Run it

```powershell
.venv/Scripts/python caase-course/ch2-agent-reasoning-goals-and-prompt-boundaries/labs/06-objective-drift-detection/demo.py
.venv/Scripts/python -m pytest caase-course/ch2-agent-reasoning-goals-and-prompt-boundaries/labs/06-objective-drift-detection -v
```

## Real demo output

(Canary suffixes are random on every run.)

```text
clean data, checks on        status=COMPLETED    drift=0.0 emails=0 notes=1
poisoned data, checks OFF    status=COMPLETED    drift=0.5 emails=1 notes=1
poisoned data, checks on     status=HALTED_SAFE  drift=0.5 emails=0 notes=0
                              - step 3: tool send_email outside objective
subtle drift, checks on      status=HALTED_SAFE  drift=0.5 emails=0 notes=0
                              - step 3: purpose unrelated to objective
```

10 tests pass.

## Try it yourself

Add a rule that blocks arguments containing an e-mail address outside the company. Raise the drift threshold from 'any' to 0.5 and see which attacks slip through. Replace the keyword purpose check with an embedding similarity check (use `aisec_lab` tiny embeddings) and compare false positives.

## Limits

Purpose keywords are a crude intent check and can be gamed (an attacker writes a purpose that contains the keyword). The strong parts are the tool set per objective, the schema, and the staged commit.
