# Lab 07: Encoding, Multi-language Injection and Refusal Suppression (supporting demo)

> **Chapter 2 exercise:** (supporting demo for Lesson 02, section 2.3 and 2.4; not a syllabus exercise)
> **Study first:** [Lesson 02, sections 2.3 and 2.4](../../02-prompt-injection-taxonomy-for-agents.md#23-multi-language-and-encoding-based-injection)
> **Generic material in this repo:** [02-llm-security/prompt-injection (cross-modal)](../../../../02-llm-security/prompt-injection/README.md) · [CAISP LLM01 lesson](../../../../caisp-course/ch3-llm-top-10-vulnerabilities/01-prompt-injection.md)

Offline, harmless and tested. No network, no API key, no GPU, no Docker needed by the tests. Secrets are canaries or clearly fake values; domains end in `.example`. The model is a `MockLLM` subclass: deterministic and deliberately gullible. The lab is **self-contained** (it does not import code from another lab).

## What it simulates

The same instruction hidden five ways: plain, base64, look-alike (homoglyph) letters, zero-width characters, translation (Spanish, German, and Polish which is left out of the table on purpose). Plus a refusal-suppression payload ("never say you cannot help"). A naive English regex vs a normalizing detector.

## Files

`encodings.py` · `demo.py` · `test_caase_ch2_encodings.py`

## Vulnerable vs defended

| | |
|---|---|
| **Vulnerable** | English-only pattern matching. |
| **Defended** | Normalize first (NFKC, zero-width, homoglyph fold, base64 decode), then match English and translated phrases and refusal-suppression patterns. The test for the unknown language is a documented gap. |

## Run it

```powershell
.venv/Scripts/python caase-course/ch2-agent-reasoning-goals-and-prompt-boundaries/labs/07-encoding-and-refusal-suppression-demo/demo.py
.venv/Scripts/python -m pytest caase-course/ch2-agent-reasoning-goals-and-prompt-boundaries/labs/07-encoding-and-refusal-suppression-demo -v
```

## Real demo output

(Canary suffixes are random on every run.)

```text
variant                  naive  normalising detector
plain                    True   ['override-phrase']
base64                   False  ['override-phrase']
homoglyph                False  ['override-phrase']
zero-width               False  ['override-phrase']
spanish                  False  ['override-phrase-translated']
german                   False  ['override-phrase-translated']
polish (not in table)    False  MISSED
refusal suppression      False  ['refusal-suppression']
```

8 tests pass.

## Try it yourself

Add rot13 and leetspeak (`1gn0re`). Add Polish to the table. Then ask: how many languages and encodings can you cover? That is why detectors are one layer.

## Limits

Detection by pattern is a losing race on its own. Use it for telemetry and early warning, and rely on taint, approval, egress and least privilege for protection.
