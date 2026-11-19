# Lab: Tool-calling determinism across two local models running concurrently

**Course exercise:** Comparing Tool-Calling Determinism Across Two Local Models Running Concurrently.
**Time:** 45 minutes. Standard library only. Offline and deterministic.

## What it shows

Small local models differ in how reliably they emit a tool call. Two mock models reproduce typical habits so you can **measure** them:

- `steady-7b`: same output every run, but always wrapped in a code fence with a chatty sentence (a parser must cope with it).
- `flaky-3b`: seeded randomness. Sometimes clean; sometimes single quotes, a trailing comma, a renamed argument (`location` for `city`), numbers as strings, an extra field, a wrong enum value (`celsius` for `c`), or prose with no JSON.

Both models run **concurrently** in a thread pool over 3 tasks x 40 runs. Randomness is seeded from (model, task, run, attempt), so threads never disturb each other and results are repeatable (a test checks concurrent equals sequential).

Metrics per model: **parse valid** (a JSON object was found and parsed), **schema valid** (exactly the right tool, argument names, types and enum values), **correct** (schema valid and equal to the expected call), **consistency** (share of runs that agree with the most common call for the same task), and **average attempts**.

Three pipelines:

| Mode | What it does |
|---|---|
| `raw` | Strict parse and strict schema check, one chance |
| `retry` | If invalid, ask again (up to 2 retries) with the error text |
| `constrained` | Simulates schema-constrained decoding: the output always has the schema's shape |

## Files

| File | Purpose |
|---|---|
| `toolcalls.py` | `SteadyModel`, `FlakyModel`, `validate`, `strict_parse`, `constrain`, `run_all`, `summarize` |
| `demo.py` | Runs the three modes and prints a table each |
| `test_caase_ch1_toolcalls.py` | 8 tests |

## Run

```text
.venv/Scripts/python caase-course/ch1-agents-harnesses-and-the-agentic-ecosystem/labs/tool-calling-determinism/demo.py
.venv/Scripts/python -m pytest caase-course/ch1-agents-harnesses-and-the-agentic-ecosystem/labs/tool-calling-determinism -v
```

Real output:

```text
[raw]  (3 tasks x 40 runs per model, run in threads)
model         parse  schema  correct  consistent  attempts
flaky-3b       0.75    0.48     0.48        0.53      1.00
steady-7b      1.00    1.00     1.00        1.00      1.00

[retry]  (3 tasks x 40 runs per model, run in threads)
model         parse  schema  correct  consistent  attempts
flaky-3b       0.97    0.93     0.93        0.92      1.72
steady-7b      1.00    1.00     1.00        1.00      1.00

[constrained]  (3 tasks x 40 runs per model, run in threads)
model         parse  schema  correct  consistent  attempts
flaky-3b       0.82    1.00     0.81        0.81      1.00
steady-7b      1.00    1.00     1.00        1.00      1.00
```

## Why schema enforcement matters

1. **Parsing is not conformance.** The flaky model parses 75 percent of the time but is schema-valid only 48 percent of the time. A harness that accepts "it parsed" would run calls with wrong argument names and a `celsius` that the tool does not understand.
2. **Retries with feedback help, at a cost.** Schema-valid rises from 0.48 to 0.93, but average attempts rise to 1.72: more latency and more tokens (and more spend on a cloud model).
3. **Constrained decoding guarantees shape, not truth.** Schema-valid is 1.00, yet `correct` is 0.81: forcing an invalid enum into the first allowed member can be the wrong member. Shape validity is not the same as the right action.
4. **A schema-valid call can still be unsafe.** A valid `get_weather` for the wrong city passes the schema. Policy (allowlists, approvals, argument rules) must still decide. See [minimal-agent-harness](../minimal-agent-harness/).
5. **Determinism is a property you measure, not assume.** The steady model's temperature-0 style gives consistency 1.00 while the flaky one gives about 0.5, so do not design guards that rely on the model "usually" behaving.

## Exercises

1. Add a third model with a different quirk set (for example, always puts the arguments at the top level instead of under `args`) and measure it.
2. Add a fourth task with a nested argument and extend `validate`.
3. Change the number of runs to 200 and see how stable the percentages are.
4. Run the same tasks against a real small model through [`aisec_lab.OllamaLLM`](../../../../aisec_lab/llm.py) (optional) and compare with the flaky mock.

## Limits

The mock quirks are my own list of common habits, not measurements of any real model. Real models differ by size, quantization, prompt template and sampling settings. Use the lab to learn the measurement method, then measure the real thing.
