# Lab: A Human-in-the-Loop Approval Gate for a Multi-Agent Workflow

**Syllabus exercise:** Adding a Human-in-the-Loop Approval Gate to a Multi-Agent Workflow · **Lesson:** [05](../../05-oversight-containment-and-failsafes.md) · **Offline, 11 tests.** Related: the existing approval-card lab in [05 permissions](../../../../05-agent-security/permissions/README.md) and the chapter-4 [human-approval-checkpoints](../../../ch4-computer-use-browser-and-coding-agents/labs/human-approval-checkpoints) lab.

A planner/executor workflow where every action goes through a `Gate`:

| Risk | Style | Behavior |
|---|---|---|
| low | autonomous | runs, logged |
| medium | **HOTL** | runs now; a human can veto and the action is undone |
| high | **HITL** | blocked until one independent approval |
| irreversible | **HITL x2** | blocked until two distinct approvals |

**HITL vs HOTL in one line:** HITL = a human must say yes *before* it happens; HOTL = it happens, a human watches and can stop or undo it.

## Run

```text
.venv/Scripts/python -m pytest caase-course/ch5-multi-agent-systems-and-agent-identity/labs/hitl-approval-gate
.venv/Scripts/python caase-course/ch5-multi-agent-systems-and-agent-identity/labs/hitl-approval-gate/demo.py
```

Real output of `demo.py`:

```text
card 1: draft_email     risk=low          status=executed
card 2: update_record   risk=medium       status=executed
card 3: transfer_funds  risk=high         status=pending
transfers so far: []
alice approving her own request -> approver must be independent of the requester and the agents
after bob approves: [{'to': 'acct-A', 'amount': 500}]
HOTL veto restored record r1 -> v0
audit: ['auto draft_email by executor', 'hotl update_record by executor (veto window open)', 'blocked transfer_funds by executor awaiting approval', "executed transfer_funds approved by ['bob']", 'veto by bob']
```

## Attacks the gate resists (all tested)

Swapping arguments after the approver looked (hash mismatch), self-approval or agent approval, approval after expiry, double use of one approval, a single approver for an irreversible action, tainted content raising risk, unknown actions defaulting to high, and a flood of pending cards (fatigue cap).

## Break it yourself

1. Let `risk` come from the model's output instead of the `RISK` table. What can an injected prompt now do?
2. Remove the hash check. Reproduce the swap attack.
3. Stretch: add a veto deadline to HOTL cards and test that a late veto is refused.
