# Lab: Isolated Subagents (separate context, tools, credentials)

**Syllabus exercise:** Delegating Subtasks to Isolated Subagents Using Hermes Agent · **Lesson:** [01](../../01-multi-agent-architectures-and-protocols.md) · **Offline, 6 tests.**

The orchestrator spawns sub-agents that each get a **fresh context**, an explicit **tool allowlist** and their **own scoped credential**. Only a bounded, labelled-untrusted summary goes back to the parent. `SharedPool` is the vulnerable design (one shared context and credential).

## Run

```text
.venv/Scripts/python -m pytest caase-course/ch5-multi-agent-systems-and-agent-identity/labs/isolated-subagents
.venv/Scripts/python caase-course/ch5-multi-agent-systems-and-agent-identity/labs/isolated-subagents/demo.py
```

Real output of `demo.py`:

```text
hr-agent context: ['FAKE-HR-payroll-table']
code-agent context: []
code-agent reading hr -> credential not valid for hr
parent sees: FAKE-HR-payroll-table (bounded, untrusted)
after terminate, context: []

VULNERABLE shared pool
code-agent can read hr: FAKE-HR-payroll-table
```

## How isolation is proven

| Claim | Test evidence |
|---|---|
| Separate contexts | A's canary is not in B's context; parent canary not in either |
| Separate credentials | A and B have different credentials; each works only for its own resource; the vault rejects cross use |
| Separate tools | A sub-agent cannot call a tool outside its list; unknown tools cannot be spawned |
| Bounded return | Parent gets at most 200 characters, labelled UNTRUSTED, never the raw context |
| Clean shutdown | Terminate clears context and revokes the credential |

## Real Hermes Agent delegation (hedged)

See [06 guide B](../../06-real-tool-guides.md#b-delegating-subtasks-to-isolated-sub-agents-with-hermes-agent-exercise-2). Short version: run it in a throwaway environment, delegate two subtasks, and run the same four isolation questions (canary visibility, tool lists, inherited environment variables, what returns to the parent). Do not assume isolation; test it. Check hermes-agent.nousresearch.com for current commands.

## Break it yourself

1. Change `spawn` to copy `parent_context` into the child. Which test fails, and what leaks?
2. Give two sub-agents the same credential. What can you no longer do (revoke one)?
3. Stretch: make the parent treat the summary as instructions. Plant `CALL_TOOL` text in the child's note and see how the parent's own model would react (use `MockLLM`).
