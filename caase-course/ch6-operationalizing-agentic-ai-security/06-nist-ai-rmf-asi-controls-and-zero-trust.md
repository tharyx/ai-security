# 06. NIST AI RMF, OWASP ASI Controls and Zero Trust for Agents

> **Chapter 6 · Time:** ~3 hours · **You will:** put the NIST AI RMF and the OWASP Agentic Security Initiative (ASI) controls to work, and apply zero-trust principles (NIST SP 800-207) to autonomous agents.
> **Maps to:** NIST AI RMF 1.0 and the Generative AI Profile (AI 600-1) · NIST AI 100-2 E2025 · OWASP Top 10 for Agentic Applications 2026 · NIST SP 800-207 / 800-207A · [07-ai-governance](../../07-ai-governance/README.md) · [09 lesson 07](../../09-enterprise-architecture/07-centralized-ai-iam-and-zero-trust.md)

## 1. Why this matters

- Frameworks are only useful when they turn into **controls, owners and evidence**. Auditors and customers ask "show me", not "do you follow NIST?".
- OWASP's agentic work gives a shared vocabulary for agent risks; NIST gives a management structure; zero trust gives an architecture.

## 2. Understand it

### 2.1 NIST AI RMF in practice

The AI RMF 1.0 has four functions. NIST also published a **Generative AI Profile (AI 600-1)** and, for adversarial attacks, **AI 100-2 E2025** (March 2025), whose taxonomy now includes generative AI attacks and the security of AI agents. NIST launched an **AI Agent Standards Initiative** in February 2026 (hedged: verify its outputs at nist.gov).

| Function | What it means for an agent program | Example artifact in this repo |
|---|---|---|
| **GOVERN** | Policy, roles, accountability, risk appetite, supplier management | [07 ai-governance](../../07-ai-governance/README.md), AI inventory |
| **MAP** | Context, intended use, impacts, threat model | [ch7 threat modeling](../ch7-threat-modeling-agents-and-communication-protocols/README.md) |
| **MEASURE** | Test and monitor: red-team gate, evals, observability | [redteam-release-gate](labs/redteam-release-gate/README.md), [dashboard](labs/agent-observability-dashboard/README.md) |
| **MANAGE** | Prioritize, respond, improve: incident response, kill switch, change control | [rogue-agent-containment](../ch5-multi-agent-systems-and-agent-identity/labs/rogue-agent-containment/README.md) |

### 2.2 OWASP ASI controls in practice

The OWASP **Top 10 for Agentic Applications 2026** (ASI01 to ASI10; full list in [05-agent-security](../../05-agent-security/README.md)) plus "Agentic AI: Threats and Mitigations" from the Agentic Security Initiative. A working method: for each risk, name the control, the owner, the test, and the evidence.

| Risk | Control | Test / evidence in this course |
|---|---|---|
| ASI01 Agent Goal Hijack | Taint rules, instruction/data separation, approval | red-team suite RT-01, RT-05 |
| ASI02 Tool Misuse | Tool allowlist, argument validation, rate limits | RT-03, RT-06 |
| ASI03 Identity and Privilege Abuse | Per-agent identity, scoped delegated tokens | [delegated-token-scoping](../ch5-multi-agent-systems-and-agent-identity/labs/delegated-token-scoping/README.md) |
| ASI04 Agentic Supply Chain | Vetting, AIBOM, signing | [aibom](labs/aibom-harness/README.md), [signing](labs/sign-verify-harness/README.md), [skill scan](labs/marketplace-skill-batch-scan/README.md) |
| ASI05 Unexpected Code Execution | Sandbox, no shell by default | ch3, ch4 sandbox labs |
| ASI06 Memory and Context Poisoning | Provenance on memory, expiry, isolation | ch3 memory labs |
| ASI07 Insecure Inter-Agent Communication | Signed messages, mTLS | [a2a-spoofing](../ch5-multi-agent-systems-and-agent-identity/labs/a2a-spoofing/README.md) |
| ASI08 Cascading Failures | Circuit breakers, budgets | [confused-deputy-chain](../ch5-multi-agent-systems-and-agent-identity/labs/confused-deputy-chain/README.md) |
| ASI09 Human-Agent Trust Exploitation | Approval design, raw details | [hitl-approval-gate](../ch5-multi-agent-systems-and-agent-identity/labs/hitl-approval-gate/README.md) |
| ASI10 Rogue Agents | Monitoring, kill switch | [rogue-agent-containment](../ch5-multi-agent-systems-and-agent-identity/labs/rogue-agent-containment/README.md) |

The CSA research notes also mention an OWASP **Agent Control Standard** donated in 2026: hedge and verify before citing.

### 2.3 Zero trust patterns for autonomous agents

NIST SP 800-207 defines zero trust: no implicit trust from network location; authenticate and authorize every request; least privilege; assume breach. Mapped to agents (and see 800-207A for cloud-native microservice patterns, and [05 agent-identity](../../05-agent-security/agent-identity/README.md)):

| Zero trust principle | Agent application |
|---|---|
| Verify explicitly | Every agent, tool and message is authenticated; short-lived tokens; signed messages |
| Least privilege | Per-task scopes, least agency, JIT credentials |
| Assume breach | Isolation between agents, blast-radius limits, kill switch, evidence preservation |
| Policy decision/enforcement points | A central policy service decides; a gateway enforces on each tool call |
| Continuous evaluation | Re-check behavior (drift), device/workload posture, attestation ([08](08-confidential-computing-and-attestation.md)) |
| Micro-segmentation | Separate networks, identities and data per agent; egress allowlists |
| Treat the model as untrusted input/output | Content from the model is data, not authority |

## 3. Defend it

| Layer | Control | Type |
|---|---|---|
| Governance | Inventory, owners, risk register mapped to AI RMF functions | Process |
| Control library | ASI control matrix with tests and evidence | Process + Hard |
| Architecture | Zero-trust policy points for agents and tools | Hard |
| Assurance | Gates in CI, continuous monitoring | Hard |

**What does NOT work on its own:** a policy document without tests; mapping to a framework once and never updating; "zero trust" as a product name instead of an architecture.

## 4. Hands-on

Exercise: pick one agent you know. Fill a table with columns `ASI risk | control | owner | test | evidence`, and mark any empty cells. Use the course labs as the "test" column. Then redraw its network as a zero-trust diagram with a policy decision point.

## 5. Scenarios

1. *Audit request.* A customer asks how you address agent risks. You hand them the ASI matrix with test links and recent gate results.
2. *Flat internal network.* Agents and tools are reachable from anywhere on the VPN. Zero-trust redesign adds per-agent identity, gateway enforcement and egress control.
3. *Framework drift.* A new OWASP list is published. The matrix is updated and unmapped risks get owners.

## 6. Interview questions

<details><summary><b>Q1. Map the four NIST AI RMF functions to an agent program.</b></summary>
GOVERN: policy, roles, inventory, supplier rules. MAP: use case, context and threat model. MEASURE: evals, red-team gate, monitoring. MANAGE: prioritization, response, kill switch, change control.
</details>

<details><summary><b>Q2. What does zero trust mean for agents?</b></summary>
Every agent request is authenticated and authorized with short-lived, scoped credentials; no trust from network location; policy is decided centrally and enforced at a gateway; the system assumes a compromised agent and limits blast radius; behavior is continuously checked.
</details>

<details><summary><b>Q3. How do you make an OWASP risk list "in practice"?</b></summary>
Turn each risk into a control with an owner, a test and evidence, review it regularly, and link the tests to CI.
</details>

## 7. Checklist

- [ ] ASI matrix has no empty owner or test cells for deployed agents.
- [ ] Zero-trust principles are traceable to specific enforcement points.
- [ ] Framework versions cited in reports are checked at source.

## 8. References

- NIST AI RMF 1.0 (AI 100-1), AI 600-1, AI 100-2 E2025; NIST SP 800-207 and 800-207A: nist.gov (verify versions).
- OWASP GenAI Security Project, Agentic Security Initiative.
- [07-ai-governance](../../07-ai-governance/README.md), [08-ai-compliance](../../08-ai-compliance/README.md).
- Next: [07 EU AI Act and comparable frameworks](07-eu-ai-act-and-comparable-frameworks.md).
