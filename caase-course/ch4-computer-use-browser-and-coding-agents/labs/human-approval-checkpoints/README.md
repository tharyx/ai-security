# Lab: Enforcing Human-Approval Checkpoints for Destructive Agent Actions

**Course exercise:** "Enforcing Human-Approval Checkpoints for Destructive Agent Actions". Lessons: [05 section 5](../../05-defending-computer-use-and-coding-agents.md#5-human-approval-checkpoints-for-destructive-or-irreversible-actions). Background: [agent permissions and approval cards](../../../../05-agent-security/permissions/README.md), [CMCPSE approval patterns](../../../../cmcpse-course/ch4-defending-and-hardening-mcp-servers/README.md).

**Time:** 40 minutes. **Safety:** nothing is executed; the "runner" is a callback that records the action.

## What it enforces

| Rule | How |
|---|---|
| **Classify** | shell (`rm -rf`, `curl \| sh`, `DROP TABLE`, `dd of=` ...), git (`push --force`, `reset --hard`, `clean -fd`, `branch -D`), payment, email, delete need approval; reads and `git status` do not |
| **Fail closed** | an unknown action type is `unknown` and cannot run without approval |
| **Show the exact action** | `render()` prints the canonical JSON (nothing summarised) and warns about non-ASCII or control characters such as right-to-left overrides |
| **Bound to a hash** | the approval stores the sha256 of the canonical action; any change means "action differs from what was approved" |
| **Timeout means deny** | no human decision within `decision_timeout` = denied; a late answer is ignored; an approval also expires after `approval_ttl` |
| **Single use** | a replayed approval is refused |
| **Final** | a denial cannot be flipped by someone else |
| **Audit** | every request, decision, approver and mismatch is logged |

## Steps

```text
.venv/Scripts/python caase-course/ch4-computer-use-browser-and-coding-agents/labs/human-approval-checkpoints/demo.py
.venv/Scripts/python -m pytest caase-course/ch4-computer-use-browser-and-coding-agents/labs/human-approval-checkpoints -v
```

1. Run the demo and follow the swapped-action, exact-action, replay and timeout lines.
2. Add a classifier rule for `kubectl delete` and for `terraform destroy`. Add tests.
3. Why does `classify` match patterns while `execute` fails closed on unknown **types**? (Regexes cannot list every dangerous command; that is why an allowlist of known-safe actions is stronger than a list of known-bad ones. Try `python -c "import shutil; shutil.rmtree('x')"`: it is `safe` here. That is the weakness of denylists, and it is why the sandbox is also needed.)
4. Think about approval fatigue: if a person approves 200 prompts a day, approval becomes a rubber stamp. Which actions should be auto-allowed, which blocked outright, and which asked?

## Expected output (real run)

```text
needs_approval  {"command":"rm -rf ./build","type":"shell"}
safe            {"args":["status"],"type":"git"}
needs_approval  {"amount":25,"payee":"Shop","type":"payment"}
unknown         {"type":"mystery"}

what the human sees:
ACTION  : {"args":["push","--force","origin","main"],"type":"git"}
HASH    : f06f4bbb530a3013...

swapped action : (False, 'action differs from what was approved')
exact action   : (True, 'ok')
replay         : (False, 'approval already used')
after timeout  : (False, 'timed out: no decision (timeout means deny)')

actions actually run: 1
```
