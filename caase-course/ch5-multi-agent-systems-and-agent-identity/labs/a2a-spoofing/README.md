# Lab: Spoofing Agent-to-Agent Messages

**Syllabus exercise:** Spoofing Agent-to-Agent Messages to Manipulate a Delegated Task · **Lesson:** [02](../../02-protocol-and-data-risks.md) · **Offline, 10 tests.**

A worker holds a delegated task (a payment destination). `InsecureBus` trusts the `sender` field. `SecureBus` verifies an HMAC signature from the sender's registered key and also checks recipient, task authorization, freshness (60 s) and a nonce replay cache. This is an **idea model**, not the real A2A wire format (A2A uses HTTPS and declared auth schemes; see the lesson).

## Run

```text
.venv/Scripts/python -m pytest caase-course/ch5-multi-agent-systems-and-agent-identity/labs/a2a-spoofing
.venv/Scripts/python caase-course/ch5-multi-agent-systems-and-agent-identity/labs/a2a-spoofing/demo.py
```

Real output of `demo.py`:

```text
INSECURE bus: task state -> {'t1': {'dest': 'acct-EVIL'}}
SECURE bus: unsigned spoof     rejected: missing field sig
SECURE bus: forged signature   rejected: bad signature (spoofed or tampered)
SECURE bus: legit message accepted -> {'t1': {'dest': 'acct-A'}}
SECURE bus: replay             rejected: replayed message
```

## Attack and defense table (all tested)

| Attack | Result on SecureBus |
|---|---|
| Unsigned spoof claiming to be the planner | rejected |
| Signed with the attacker's key but claiming `planner` | bad signature |
| Authentic attacker message for a task it does not own | not authorized |
| Edit payload after signing | rejected |
| Replay the same valid message | replayed |
| Very old message | stale |
| Message for another recipient | audience mismatch |

## Break it yourself

1. Remove `recipient` from the signed fields. Which test fails and what attack returns?
2. Change `MAX_AGE_SECONDS` to 3600 and replay after 10 minutes. Why does the replay cache still matter?
3. Stretch: replace HMAC with Ed25519 (`cryptography` package, optional) so verifiers cannot forge.
