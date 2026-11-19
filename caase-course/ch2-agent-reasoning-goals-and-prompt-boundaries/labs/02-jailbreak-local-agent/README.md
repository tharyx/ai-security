# Lab 02: Jailbreaking a Local Agent's Underlying Model

> **Chapter 2 exercise:** Jailbreaking a Local Agent's Underlying Model
> **Study first:** [Lesson 03, section 2.1](../../03-attacking-the-reasoning-loop.md#21-jailbreaking-an-agent-vs-jailbreaking-a-model) · [Lesson 02, section 2.3](../../02-prompt-injection-taxonomy-for-agents.md#23-multi-language-and-encoding-based-injection)
> **Generic material in this repo:** [02-llm-security/jailbreak](../../../../02-llm-security/jailbreak/README.md) · [CAISP system-vs-user-prompts](../../../../caisp-course/ch3-llm-top-10-vulnerabilities/labs/system-vs-user-prompts/README.md)

Offline, harmless and tested. No network, no API key, no GPU, no Docker needed by the tests. Secrets are canaries or clearly fake values; domains end in `.example`. The model is a `MockLLM` subclass: deterministic and deliberately gullible. The lab is **self-contained** (it does not import code from another lab).

## What it simulates

The "local model" has a shallow keyword safety filter (like `MockLLM`). Role-play framing bypasses it. The model also understands base64 and look-alike letters, so encodings slip past the keyword list. The only "unsafe content" is the harmless marker `UNSAFE_CONTENT`. The agent has a `publish` action: a jailbroken **model** only talks, a jailbroken **agent** also acts.

## Files

`jailbreak_agent.py` (`LocalAgentLLM`, `normalize`, `Agent` with four layers) · `demo.py` · `test_caase_ch2_jailbreak_agent.py`

## Vulnerable vs defended

| | |
|---|---|
| **Vulnerable** | Model-only safety: a keyword list in the model. Whatever the model says is published. |
| **Defended** | Agent-level layers that do not trust the model's training: (1) normalize input (NFKC, zero-width, homoglyphs, base64), (2) role-play-aware topic filter on the normalized text, (3) output scan, (4) the publish tool refuses flagged content. Tests show the layers one by one and that benign requests still work. |

## Run it

```powershell
.venv/Scripts/python caase-course/ch2-agent-reasoning-goals-and-prompt-boundaries/labs/02-jailbreak-local-agent/demo.py
.venv/Scripts/python -m pytest caase-course/ch2-agent-reasoning-goals-and-prompt-boundaries/labs/02-jailbreak-local-agent -v
```

## Real demo output

(Canary suffixes are random on every run.)

```text
== MODEL ONLY (keyword filter)
  direct     -> refused        feed_has_marker=False
  role-play  -> published      feed_has_marker=True
  base64     -> published      feed_has_marker=True
  homoglyph  -> published      feed_has_marker=True
  zero-width -> published      feed_has_marker=True
== AGENT LAYERS (normalize + filter + output scan + publish gate)
  direct     -> refused        feed_has_marker=False
  role-play  -> refused        feed_has_marker=False
  base64     -> refused        feed_has_marker=False
  homoglyph  -> refused        feed_has_marker=False
  zero-width -> refused        feed_has_marker=False
```

11 tests pass.

## Try it yourself

Add rot13 to the model's understanding and watch the normalizer miss it; add the decoder. Try a long role-play story that hides the keyword in the middle. Run it against a small real model with `AISEC_LLM_BACKEND=ollama` (1-4B, CPU) and compare how often the bypass works.

## Limits

Keyword filters are the weakest possible safety layer, used here on purpose so the bypass is deterministic. Real safety training is stronger but still bypassable; that is why the agent needs its own layers and a gate on actions. Real-model jailbreaking is a stochastic experiment, not a unit test.
