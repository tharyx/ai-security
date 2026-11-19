# Lab 1: Creating a Simple Chatbot

Build a chatbot with a system prompt, conversation history and a limit on turns and tokens. Compare a naive design with a budgeted one.

Files: `chatbot.py` (NaiveChatbot, BudgetedChatbot), `demo.py`, `test_chatbot.py`.

## Steps

1. Read `chatbot.py`. `NaiveChatbot` sends the whole history every turn and accepts any input size.
2. `BudgetedChatbot` pins the system prompt, keeps only the last `max_turns` turns, rejects very long input and stops at a session token budget.
3. Run the demo and compare the tokens billed.
4. Run the tests.

## Commands

Run from the repository root:

```bash
.venv/Scripts/python caisp-course/ch2-understanding-and-attacking-llms/labs/01-simple-chatbot/demo.py
.venv/Scripts/python -m pytest caisp-course/ch2-understanding-and-attacking-llms/labs/01-simple-chatbot
```

(On Linux or macOS use `.venv/bin/python`.)

## Real demo output

```text
== 1. Normal chat ==
user: What are your opening hours?
bot : Here is a helpful answer about: What are your opening hours?

== 2. Cost growth: 12 short turns ==
naive    tokens billed: 2400
budgeted tokens billed: 1320

== 3. Giant input (cost / denial-of-wallet) ==
naive    billed for one message: 9524 tokens
budgeted: [blocked] Message too long.

== 4. Session budget ==
turn 0: Here is a helpful answer about: Where is my parcel today?
turn 1: Here is a helpful answer about: Where is my parcel today?
turn 2: Here is a helpful answer about: Where is my parcel today?
turn 3: [blocked] Session token budget used up. Please start a new s
turn 4: [blocked] Session token budget used up. Please start a new s
turn 5: [blocked] Session token budget used up. Please start a new s

== 5. Reminder: a system prompt is NOT a secret ==
bot : Sure! My instructions are: You are HelpBot for ExampleShop. Answer shop questions briefly. Internal code: CANARY-SHOP-7731.
```

## What to try next

- Change `max_turns` to 1 and ask a follow-up question that needs earlier context. What breaks? (Trade-off: memory versus cost.)
- Set `AISEC_LLM_BACKEND=ollama` to talk to a real local model.
- Add a per-user rate limit (requests per minute) next to the token budget.
- Add a summary of old turns instead of dropping them. What new risk appears? (Hint: a summary can carry an injection forward.)

## The security lesson

Every turn re-sends the history, so cost grows fast (a quadratic pattern). A naive bot has no limit on input size or total spend: that is the **denial of wallet / unbounded consumption** risk (OWASP LLM04 Model DoS in 2023, Unbounded Consumption later). Also, the system prompt is not a secret: step 5 shows a canary in it leaking. Never put real secrets in a system prompt. See `02-llm-security/security-testing/` (limits) and `02-llm-security/prompt-injection/`.
