# Lab: Detecting and Safely Terminating a Rogue Agent

**Syllabus exercise:** Detecting and Safely Terminating a Rogue Agent · **Lesson:** [05](../../05-oversight-containment-and-failsafes.md) · **Offline, 10 tests.** Related: [05 monitoring-and-response](../../../../05-agent-security/monitoring-and-response/README.md).

Two modules:

- `rogue_agent.py`: runtime with credentials, a journaled store, a hash-chained audit log, a `Monitor`, and `terminate()` which runs **quarantine, drain, preserve, revoke, roll back, destroy and verify** in that order.
- `failsafe.py`: a simulated valve safety controller (agent proposes, controller disposes): limits, interlocks, heartbeat watchdog, e-stop, human reset. Teaching model only, not a certified safety design.

## Run

```text
.venv/Scripts/python -m pytest caase-course/ch5-multi-agent-systems-and-agent-identity/labs/rogue-agent-containment
.venv/Scripts/python caase-course/ch5-multi-agent-systems-and-agent-identity/labs/rogue-agent-containment/demo.py
```

Real output of `demo.py`:

```text
monitor findings: [('repeated_denials', '4 denied calls (probing)')]
config before termination: TAMPERED
steps: quarantine -> drain -> preserve -> revoke -> rollback -> destroy -> verified
dead-lettered=2 revoked=1 rolled_back=1
evidence sha256: 1575e5194a0ae50d ...
config after termination: original

Physical-world fail-safe (simulated valve)
set_flow 20 -> accepted {'valve': 'open', 'pump': 'off'}
set_flow 500 -> rejected: flow 500 above limit 50
after 29s without heartbeat: {'valve': 'closed', 'pump': 'off'} | tripped: heartbeat lost
```

(The evidence hash differs per run because tokens are random.)

## What the tests assert

- A benign agent is not flagged; the probing agent is (repeated denials, rate, loops).
- After termination: steps in the right order, queued tasks parked not run, credential rejected, business data rolled back, **evidence file exists, its SHA-256 matches, and it contains the context that was later destroyed**, other agents keep working.
- Audit chain detects tampering.
- Failsafe: heartbeat loss trips to the safe state; limits live in the controller; interlocks hold; e-stop needs a named human to reset.

## Break it yourself

1. Move the `preserve` step after `destroy`. Which assertion fails?
2. Let the agent call `heartbeat()` itself in a loop. Why is that a bad design? (Hint: who owns the watchdog?)
3. Stretch: add a drift-based detector from [ch6 observability](../../../ch6-operationalizing-agentic-ai-security/labs/agent-observability-dashboard/README.md).
