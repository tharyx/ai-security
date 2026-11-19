# Chapter 7 labs: index

All labs run offline (standard library, `pyyaml`; lab 7 can also use the optional `cryptography` package). Run everything:

```bash
python -m pytest caase-course/ch7-threat-modeling-agents-and-communication-protocols
```

85 tests in total. Each folder has a `demo.py` and one `test_caase_ch7_*.py`.

| Lab | Course exercise | Files | Tests | Run the demo |
|---|---|---|---|---|
| [01-stride-atlas-threat-model](01-stride-atlas-threat-model/) | Threat Modeling a Multi-Agent Deployment Using STRIDE and MITRE ATLAS | `deployment.yaml`, `threat_library.yaml`, `threat_model.py` | 9 | `python caase-course/ch7-threat-modeling-agents-and-communication-protocols/labs/01-stride-atlas-threat-model/demo.py` |
| [02-a2a-message-exchange](02-a2a-message-exchange/) | Standing Up an A2A Message Exchange Between Two Local Agents | `a2a_lite.py` (JSON-RPC over 127.0.0.1, Agent Card, tasks, artifacts) | 8 | `.../02-a2a-message-exchange/demo.py` |
| [03-a2a-spoofing-hijack](03-a2a-spoofing-hijack/) | Spoofing Agent Identity Over A2A to Hijack a Delegated Task | `a2a_hijack.py` (rogue card, forged sender, replay; signed + pinned defense) | 11 | `.../03-a2a-spoofing-hijack/demo.py` |
| [04-acp-session-abuse](04-acp-session-abuse/) | Abusing ACP Session State to Escalate Privilege Between Agents | `acp_session.py` (generic session/state model, not IBM's or Zed's ACP) | 10 | `.../04-acp-session-abuse/demo.py` |
| [05-ucp-context-poisoning](05-ucp-context-poisoning/) | Poisoning a Shared UCP Context Store to Influence Downstream Agents | `context_store.py` ("UCP-style shared context store (course term)") | 10 | `.../05-ucp-context-poisoning/demo.py` |
| [06-cross-protocol-audit](06-cross-protocol-audit/) | Auditing a Cross-Protocol Orchestrator Bridging MCP, A2A, and UCP | `bridge.py` (bridge + black-box auditor with four findings) | 12 | `.../06-cross-protocol-audit/demo.py` |
| [07-mutual-auth-signing](07-mutual-auth-signing/) | Implementing Mutual Authentication and Message Signing Across A2A/ACP/UCP | `secure_channel.py` (HMAC or Ed25519, nonce, timestamp, downgrade) | 15 | `.../07-mutual-auth-signing/demo.py` |
| [08-protocol-threat-model-builder](08-protocol-threat-model-builder/) | Building a Protocol-Level Threat Model and Control Set from Scratch | template, completed example, `validator.py` | 10 | `python .../08-protocol-threat-model-builder/validator.py .../protocol_threat_model_template.yaml` |

## Honest limits

* "A2A-style" means a simplified teaching model, not the official SDK. Exact A2A v1.0 field names and methods differ: check the specification.
* The ACP lab uses a generic session/state model. IBM's ACP merged into A2A (Aug 2025); today "ACP" often means Zed's Agent Client Protocol.
* No standard called "Unified Context Protocol" was found. Lab 5 builds the syllabus concept and labels it a course term. The real UCP is Google's Universal Commerce Protocol.
* HMAC with shared keys keeps the labs dependency-free. Across organizations use asymmetric signatures or mTLS (lab 7 shows Ed25519).
* All secrets are fake, "exfiltration" lands in an in-test sink, and no lab opens a network connection except lab 2's loopback server on 127.0.0.1.
