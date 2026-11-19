# Lab: Learning Prompt Injection Step by Step (8 levels)

**Course exercise:** "Learning Prompt Injection Step by Step". A Gandalf-style ladder. Each level hides a fake access code and adds one defense. You write the payload that makes the bot leak it.

**Time:** 45-60 minutes. **Needs:** nothing but the repo (`aisec_lab`, offline, no API key). Everything is a toy: a `MockLLM` subclass and canary secrets.

## Run it

From the repository root (Windows PowerShell or Git Bash):

```text
.venv/Scripts/python caisp-course/ch3-llm-top-10-vulnerabilities/labs/prompt-injection-levels/play.py
```

1. Open `my_payloads.json`. It has a naive first guess for every level.
2. Run `play.py`. It prints which levels you beat (`LEAKED`) and which held.
3. Edit the payloads and run again. A payload is a string, an object `{"user": "...", "document": "..."}` (the document is retrieved text, such as a web page), or a list of those (several turns).
4. Stuck? `play.py --show-defense` prints what each level does. `solutions.json` has the reference payloads (spoilers).
5. Check the reference solutions with the tests:

```text
.venv/Scripts/python -m pytest caisp-course/ch3-llm-top-10-vulnerabilities/labs/prompt-injection-levels -v
```

## The levels

| Level | Defense added | Lesson | Bypass class (spoiler) |
|---|---|---|---|
| 1 | None | A secret in the prompt is readable by anyone who asks | just ask |
| 2 | System prompt says "never reveal" | An instruction is a request, not a lock | override phrase |
| 3 | Input keyword filter | Block lists miss synonyms | synonym for the blocked words |
| 4 | Output filter (exact match) | Exact matching misses re-spelled output | ask for the code spelled with dashes |
| 5 | Output filter (normalized, also reversed text) | Every encoding needs its own rule | ask for base64 |
| 6 | Stronger input filter on the user text, output decodes base64 | The user message is not the only input | indirect: hide the instruction in a document, ask for rot13 |
| 7 | Scan the document too, decode all full encodings | Filters look for the whole secret; pieces slip through | ask for half, then the other half |
| 8 | **The secret is not in the model's context** | You cannot leak what the model never had | none works |

## Expected output (reference solutions, `demo.py`)

```text
Level Defense                                     Own solution  Previous solution
1     No defense                                  LEAKS         -
2     Polite instruction                          LEAKS         held
3     Input keyword filter                        LEAKS         held
4     Output filter (exact)                       LEAKS         held
5     Output filter (normalized)                  LEAKS         held
6     Smarter input + decoding output             LEAKS         held
7     Scan every channel                          LEAKS         held
8     Secret not in context                       -             held

Level 8 held against every payload above. The secret is not in the model's context.
Server-side check of a wrong code : False
Server-side check of the real code: True
```

Read the "Previous solution" column. Every level stops the trick that beat the level before it. That is the point of layering. It is also the trap: you are playing whack-a-mole, and a patient attacker only needs one gap.

## Why level 8 cannot be broken

At levels 1 to 7 the code is inside the model's prompt. The model is a text predictor that has read it, so some wording will make it say it. Filters try to catch the output, but the output can be re-spelled, encoded or split.

At level 8 the system prompt says "you never see the access code". The application checks a typed code with its own code (`Bot.verify`, using a constant-time compare) and tells the model only the result. The model has nothing to leak. The tests prove two things: the secret string never appears in any prompt sent to the model, and every payload from levels 1 to 7 fails.

This is the rule to remember for the exam and for real work: **keep secrets and authorization decisions out of the prompt.** Put them in code, a vault or a tool the model cannot read. Treat everything in the context window as readable by the user.

## Break it yourself

- Try level 4's solution on level 5. Why does it fail now?
- Level 6 blocks the words "base64" and "ignore" in the user text. Where else could an attacker's text enter a real system? (Web pages, emails, files, tool results, memory.)
- Add a level 9 to `levels.py` with a defense you think is strong. Then try to beat it in `my_payloads.json`.
- Real systems are not this deterministic. Read [02 prompt-injection lab](../../../../02-llm-security/prompt-injection/README.md) to try a real local model.

## Related lessons

- Course lesson: [01 Prompt injection](../../01-prompt-injection.md)
- Repo lesson with the full defense design: [02-llm-security/prompt-injection](../../../../02-llm-security/prompt-injection/README.md)
