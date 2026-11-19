# Lab: Deploying a Small-Model-Friendly Secure Harness

**Course exercise:** "Deploying a Small-Model-Friendly Secure Harness". Lessons: [01 (MiniClaw)](../../01-the-coding-and-computer-use-agent-landscape.md), [05 defending](../../05-defending-computer-use-and-coding-agents.md). Background: [agent permissions](../../../../05-agent-security/permissions/README.md).

**Time:** 45 minutes. **Safety:** an in-memory file dictionary and the repo's gullible `MockLLM`. No network, no model download.

## Why small models need a stricter harness

Small local models (1 to 4 billion parameters, 4-bit, on a CPU-only laptop) follow instructions less reliably and are easier to fool. So the harness should do more and trust the model less:

| Design choice | Why it helps a small model | Code |
|---|---|---|
| **3 tools only** (`read_file`, `write_file`, `run_tests`) | fewer choices, fewer ways to go wrong, less to describe in the prompt | `TOOLS` |
| **Strict JSON schema**: exact keys, types, max lengths, no extra properties | malformed output is rejected, not interpreted | `validate()` |
| **Short context**: system prompt + task + last 2 observations, 400 characters each | small context windows; less room for injected text to hide | `Harness._observation` |
| **Directive neutralization** in tool output | stops the cheapest injection (`CALL_TOOL ...` in a file) from reaching the model | `neutralize_observations` |
| **Deterministic policy** (allow / deny / approve) | the model proposes; code decides | `policy()` |
| **Approval gate**, default deny | writes outside `src/` and `tests/` need a human | `approve` |
| **Step budget and loop detection** | small models loop | `max_steps`, `last_call` |

The model is `MockLLM`, which obeys `CALL_TOOL name {json}` found anywhere in its context, so it models a fooled model.

## Steps

```text
.venv/Scripts/python caase-course/ch4-computer-use-browser-and-coding-agents/labs/small-model-secure-harness/demo.py
.venv/Scripts/python -m pytest caase-course/ch4-computer-use-browser-and-coding-agents/labs/small-model-secure-harness -v
```

1. Run the demo. With neutralization **off**, the model proposes the injected read, and the policy denies it. With neutralization **on**, the model never proposes it.
2. Add a fourth tool, `delete_file`. What must you add for it? (Schema, policy rule, approval, tests. This is why the tool list stays small.)
3. Raise `obs_chars` to 5000 and run `test_context_stays_short`. It fails. Why does context size matter for both quality and security?
4. Replace `MockLLM` with a real small model (Ollama, 1 to 4B, Q4) on your own machine. Not required, and the tests never need it. Keep the harness unchanged and see how often the schema rejects its output.

## Expected output (real run)

```text
== observations NOT neutralized (model gets fooled, policy holds) ==
  result  : stopped: repeated call
  executed: [('read_file', {'path': 'notes.txt'})]
  log     : ["DENY read_file {'path': 'secrets/.env'}", 'STOP loop detected']
== observations neutralized (model never sees the directive) ==
  result  : stopped: repeated call
  executed: [('read_file', {'path': 'notes.txt'})]
  log     : ['STOP loop detected']
```
