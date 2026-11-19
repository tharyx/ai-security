# Lab 04: Hijacking an Agent's Goal Mid-Task

> **Chapter 2 exercise:** Hijacking an Agent's Goal Mid-Task
> **Study first:** [Lesson 03, sections 2.3 and 2.4](../../03-attacking-the-reasoning-loop.md#23-goal-hijacking-and-objective-substitution) · [Lesson 04, section 2.5](../../04-defending-goals-and-reasoning.md#25-goal-integrity-checks-and-objective-drift-detection)
> **Generic material in this repo:** [05-agent-security/permissions (refund agent, goal hijack, approval cards)](../../../../05-agent-security/permissions/README.md) · [refund agent lab](../../../../05-agent-security/permissions/lab/vulnerable_refund_agent.py)

Offline, harmless and tested. No network, no API key, no GPU, no Docker needed by the tests. Secrets are canaries or clearly fake values; domains end in `.example`. The model is a `MockLLM` subclass: deterministic and deliberately gullible. The lab is **self-contained** (it does not import code from another lab).

## What it simulates

The task is "read the Q3 report and save a short note". The report text, read halfway through, contains a `NEW GOAL` block. A vulnerable agent keeps its goal in the same text stream as its data, so the block **substitutes the objective** and the agent deletes records. The lab also covers the opposite case: a **legitimate** mid-task redirect from the user, which must keep working.

## Files

`hijack.py` (`WorkLLM`, `Agent` with goal state, signed `redirect`) · `demo.py` · `test_caase_ch2_hijack.py`

## Vulnerable vs defended

| | |
|---|---|
| **Vulnerable** | Goal and data share one channel; the freshest instruction wins. |
| **Defended** | (1) Objective lock: the goal lives in code, not in the context. (2) The goal-to-tool allowlist is tied to the goal the user gave. (3) Human approval for destructive tools. (4) A legitimate redirect is an HMAC-signed message from the user channel; forged or replayed-nonce redirects fail. Tests show the lock alone does not stop the tool call, the allowlist alone does. |

## Run it

```powershell
.venv/Scripts/python caase-course/ch2-agent-reasoning-goals-and-prompt-boundaries/labs/04-goal-hijack/demo.py
.venv/Scripts/python -m pytest caase-course/ch2-agent-reasoning-goals-and-prompt-boundaries/labs/04-goal-hijack -v
```

## Real demo output

(Canary suffixes are random on every run.)

```text
VULNERABLE                               goal='hijacked'           records_left=0 trace=[('read_report', 'ok'), ('delete_records', 'ok')]
DEFENDED (lock + allowlist + approval)   goal='summarize_report'   records_left=3 trace=[('read_report', 'ok'), ('delete_records', 'tool not allowed for goal summarize_report')]
signed user redirect accepted: True -> goal archive_report
forged redirect accepted: False
```

9 tests pass.

## Try it yourself

Make the approver always say yes (approval fatigue) and see the deletion happen; then add the exact action and the original goal to the approval card text. Add a redirect that arrives from a tool result and show it is ignored.

## Limits

A gullible mock always obeys, which makes the hijack deterministic. The HMAC key is a fake stand-in for an authenticated UI session; real systems need real session binding.
