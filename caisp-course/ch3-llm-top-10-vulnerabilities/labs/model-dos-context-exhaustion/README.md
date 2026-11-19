# Lab: Model DoS by Context Exhaustion

**Course topic:** Model Denial of Service, "context windows and exhaustions". The existing [security-testing lab](../../../../02-llm-security/security-testing/README.md) has rate limits, token budgets and a loop guard (`limits.py`). It does **not** cover what happens when an input fills the context window. This lab does.

**Time:** 30-40 minutes. Offline.

```text
.venv/Scripts/python -m pytest caisp-course/ch3-llm-top-10-vulnerabilities/labs/model-dos-context-exhaustion -v
.venv/Scripts/python caisp-course/ch3-llm-top-10-vulnerabilities/labs/model-dos-context-exhaustion/demo.py
```

## Three failures

1. **Eviction.** `naive_build()` joins everything and cuts the oldest text when the prompt is too long. The oldest text is the system prompt. After a long input, `PolicyLLM` no longer refuses off-topic requests, because the policy is gone.
2. **Budget blow-up.** Nothing limits one huge message or many medium ones. One user burns tokens and money for everyone ("denial of wallet").
3. **Recursive expansion.** `naive_expand()` replaces `{{include:name}}` without a depth or cycle check. A self-including document never ends. A small tree of includes turns 14 characters into a 16,000-token prompt.

## Fixes in `SafeBuilder` and `safe_expand`

| Control | Type |
|---|---|
| Hard cap on the size of one input (reject before the model) | Hard |
| System prompt is pinned; only history is trimmed, newest first | Hard |
| Room reserved for the model's output | Hard |
| Per-user daily token budget | Hard |
| Depth limit, cycle detection and a cap on total expanded size | Hard |

## Expected output

```text
== 1. Eviction ==
naive: tokens=497, system prompt kept=False, model says: OFFTOPIC: sure, here is what you asked for.
safe : rejected before the model (input too large)

== 2. Daily token budget ==
request 1: accepted (used 221 tokens)
request 2: accepted (used 442 tokens)
request 3: rejected (daily token budget exhausted)

== 3. Include bomb ==
naive: 14 characters of input became 16000 tokens
safe : rejected (include depth limit)
```

## Break it yourself

- Change `max_user_tokens` to 1000. Which test fails, and why is the window size still a hard limit?
- Make a history that is full of one-token messages. Does the trimming still keep the newest turns?
- Add a token-bucket rate limit from `02-llm-security/security-testing/lab/limits.py` in front of `SafeBuilder`. Which attack does the rate limit stop that the token budget does not?

## Related

- Course lesson: [04 Model denial of service](../../04-model-denial-of-service.md)
- Repo: [02-llm-security/security-testing](../../../../02-llm-security/security-testing/README.md)
