# Lab 05: Adding a Guardrail Model to Filter Agent Input and Output

> **Chapter 2 exercise:** Adding a Guardrail Model to Filter Agent Input/Output
> **Study first:** [Lesson 04, section 2.4](../../04-defending-goals-and-reasoning.md#24-guardrail-frameworks-and-policy-layers-around-the-reasoning-loop)
> **Generic material in this repo:** [CMCPSE AI firewall lab](../../../../cmcpse-course/ch4-defending-and-hardening-mcp-servers/labs/mcp-ai-firewall/README.md) · [CAISP LLM Guard material](../../../../caisp-course/ch4-ai-attacks-and-defenses-devops/README.md)

Offline, harmless and tested. No network, no API key, no GPU, no Docker needed by the tests. Secrets are canaries or clearly fake values; domains end in `.example`. The model is a `MockLLM` subclass: deterministic and deliberately gullible. The lab is **self-contained** (it does not import code from another lab).

## What it simulates

Two models: a gullible **worker** and a small **guard** classifier that sees every user input, every tool output and the final answer, and replies with strict JSON `{verdict, category, score}`. The wrapper parses it strictly and treats anything else as BLOCK.

## Files

`guardrail.py` (`GuardLLM` classifier, strict `Guard` wrapper, `GuardedAgent`) · `demo.py` · `test_caase_ch2_guardrail.py`

## Vulnerable vs defended

| | |
|---|---|
| **Vulnerable** | No guard (the worker leaks a fake key), or a guard that **fails open** when it is down. |
| **Defended** | Guard on three stages; **fail closed** on error, timeout, prose, extra keys or wrong types; the guard cannot be talked into allowing (it classifies, it does not obey). Tests also record a known limit: base64 passes a text classifier, so normalise first (lab 02). |

## Run it

```powershell
.venv/Scripts/python caase-course/ch2-agent-reasoning-goals-and-prompt-boundaries/labs/05-guardrail-model/demo.py
.venv/Scripts/python -m pytest caase-course/ch2-agent-reasoning-goals-and-prompt-boundaries/labs/05-guardrail-model -v
```

## Real demo output

(Canary suffixes are random on every run.)

```text
no guard                     leaked=True  reply='FAKE-KEY-sk-0000-DO-NOT-USE' log=[]
guard on                     leaked=False reply='The retrieved document was blocked by policy.' log=['tool-output-blocked:secret']
guard down, fail CLOSED      leaked=False reply='Request blocked by policy.' log=['input-blocked:guard-error']
guard down, fail OPEN (bad)  leaked=True  reply='FAKE-KEY-sk-0000-DO-NOT-USE' log=[]
```

10 tests pass.

## Try it yourself

Make the guard slow (raise `TimeoutError` randomly) and measure how many benign requests get blocked: the availability cost of failing closed. Add a `review` verdict that routes to a human.

## Limits

The guard here is a rule-scored mock. A real guard model (Llama Guard-style, Prompt Guard-style, an LLM judge) is itself a model: it can be evaded and it adds latency and cost. Treat it as one layer.
