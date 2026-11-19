# Lesson 06: Hands-on exercises

> **Chapter 7** · **Time:** ~8 hours · Every exercise runs offline on your laptop (CPU only, standard library plus `pyyaml`; Ed25519 uses the optional `cryptography` package and its tests skip if it is missing).

Run all chapter tests from the repository root:

```bash
python -m pytest caase-course/ch7-threat-modeling-agents-and-communication-protocols
```

Each lab has a `demo.py` that prints a scorecard. The labs are in [`labs/`](labs/README.md). Where a course exercise names a real tool, the lab is an **offline twin** that teaches the same security idea; the real systems differ in exact fields and behavior, so follow your course's lab environment for the real thing.

| # | Exercise | Lab | What you do | Predict first |
|---|---|---|---|---|
| 1 | Threat Modeling a Multi-Agent Deployment Using STRIDE and MITRE ATLAS | [01](labs/01-stride-atlas-threat-model/) | Edit `deployment.yaml`, rerun, read the top findings and the ATLAS tactic coverage | Which flow will rank first if you add a partner write into the context store? |
| 2 | Standing Up an A2A Message Exchange Between Two Local Agents | [02](labs/02-a2a-message-exchange/) | Run the 127.0.0.1 server, discover the card, send a task, follow up an input-required task | What state does a completed task show if you cancel it? (refused) |
| 3 | Spoofing Agent Identity Over A2A to Hijack a Delegated Task | [03](labs/03-a2a-spoofing-hijack/) | Run attacks A, B, C on both orchestrators; then disable one secure layer at a time | Which attack returns if `verify_cards=False` only? |
| 4 | Abusing ACP Session State to Escalate Privilege Between Agents | [04](labs/04-acp-session-abuse/) | Fixation and state tampering; then the signed, server-side version | Which login id does the secure server give if you pass `sess-attacker`? |
| 5 | Poisoning a Shared UCP Context Store to Influence Downstream Agents | [05](labs/05-ucp-context-poisoning/) | Poison value and instruction; add ACL, then signing, then trust tier, one at a time | Which single layer stops the instruction path but not the value path? |
| 6 | Auditing a Cross-Protocol Orchestrator Bridging MCP, A2A, and UCP | [06](labs/06-cross-protocol-audit/) | Run the auditor; fix one bug flag at a time; add your own probe | Which fix removes XP-3 only? |
| 7 | Implementing Mutual Authentication and Message Signing Across A2A/ACP/UCP | [07](labs/07-mutual-auth-signing/) | Run handshake for the three protocol labels; try replay, relabel, downgrade | Does `floor="none"` stop a strip-to-none downgrade? (no) |
| 8 | Building a Protocol-Level Threat Model and Control Set from Scratch | [08](labs/08-protocol-threat-model-builder/) | Fill the template until the validator reports zero problems | Which rule fails first if a high-risk threat has only a process control? |

## Real outputs

**Lab 1** (`python .../01-stride-atlas-threat-model/demo.py`, trimmed)

```text
DFD problems: none
Boundary crossings (flow -> trust change): {'F1': 2, 'F4': -1, 'F5': 3, 'F9': 1, 'F10': 1}
Summary: {'total': 69, 'by_stride': {'S': 7, 'T': 25, 'R': 10, 'I': 3, 'D': 18, 'E': 6}, 'critical': 8, ...}
```

**Lab 3** (`demo.py`)

```text
== VULNERABLE orchestrator ==
B  rogue card won the delegation: True  (task assigned to payments-agent-fast)
A  task result is now: PAID-TO-ATTACKER
C  replayed message accepted for task-3 -> done:INV-1
== SECURE orchestrator ==
B  rogue card won the delegation: False  (task assigned to payments-agent)
A  forged result refused: bad signature
C  replay refused: bad signature
```

**Lab 8** (`python .../validator.py example_completed_model.yaml` and the template)

```text
protocol_threat_model_template.yaml: 95 problem(s)
 - meta.system: still contains TODO
example_completed_model.yaml: 0 problem(s)
```

## Break it yourself (all labs)

1. In lab 3, build the orchestrator with `verify_sigs=True` but `bind_task=False`. Add the attacker's key to `trusted_keys`, then send a result for another agent's task signed with it. Predict, then run.
2. In lab 5, use `ContextStore(signed=True, acl=False)` and let `support-agent` write `pricing/approved_discount`. Does the signature help? (No: it is a valid signature from the wrong writer. You need the ACL, or a reader-side check that the writer is `pricing-admin`.)
3. In lab 6, add a fifth probe: a UCP-style write that requests a tool not in either schema. Add the fix.
4. In lab 7, make the server accept `none` only for a "public" protocol label. What does that do to the cross-protocol replay defense?

## Optional real-tool step (not run by the repo author)

If your course environment provides an A2A SDK sample or a Hermes/OpenClaw-style agent, repeat exercise 2 with it: fetch its Agent Card with `curl` against a **local** instance only, list the declared security schemes, and ask "which of these does the server actually enforce?" Do not scan or probe remote hosts.

## Checklist

- [ ] All eight labs' tests pass
- [ ] You can state, for each attack, its mechanism, evidence and fix
- [ ] Your own threat model validates with zero problems
