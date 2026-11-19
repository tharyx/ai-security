# Lab: Model sizing calculator (does it fit, and where should it run?)

**Course topic:** Local open-weight models sized to fit consumer-grade VRAM budgets; cloud/API-routed models for tasks that exceed local hardware capacity.
**Time:** 30 minutes. Standard library only. Offline.

## What it does

`sizing.py` computes `memory = weights + KV cache + overhead` for 1B, 3B, 7B, 8B, 14B and 70B model shapes at FP16, Q8 and Q4, estimates tokens per second from memory bandwidth, and **recommends where to run**: local GPU, local CPU, or cloud. If the data is confidential and the model does not fit locally, it does **not** recommend cloud: it says a smaller local model or a private deployment is needed.

Numbers are rough planning estimates with illustrative model shapes. Measure on your own machine, and check each model card.

## Files

| File | Purpose |
|---|---|
| `sizing.py` | `weights_gb`, `kv_cache_gb`, `memory_needed_gb`, `recommend`, `sizing_table`, `Hardware`, `LEARNER_LAPTOP` (16 GB RAM, no GPU, 6 GB reserved) |
| `demo.py` | Prints the table and the laptop recommendations |
| `test_caase_ch1_sizing.py` | 10 tests |

## Run

```text
.venv/Scripts/python caase-course/ch1-agents-harnesses-and-the-agentic-ecosystem/labs/model-sizing-calculator/demo.py
.venv/Scripts/python -m pytest caase-course/ch1-agents-harnesses-and-the-agentic-ecosystem/labs/model-sizing-calculator -v
```

Real output:

```text
Total memory in GB at 8192 tokens of context (weights + KV cache + overhead)
size     FP16      Q8      Q4   KV@8k
1B        3.3     2.1     1.5    0.27
3B        8.2     5.0     3.4    0.94
7B       16.7     9.6     6.0    1.07
8B       18.4    10.5     6.4    1.07
14B      32.7    18.2    10.8    1.34
70B     151.4    81.8    46.2    2.68

Learner laptop: 16 GB RAM, no GPU (budget = 16 - 6 reserved = 10 GB)
  1B Q4  needs   1.5 GB -> local-cpu  ~ 50.3 tok/s  
  3B Q4  needs  3.39 GB -> local-cpu  ~ 18.9 tok/s  
  7B Q4  needs  5.96 GB -> local-cpu  ~  8.4 tok/s  
  8B Q8  needs 10.48 GB -> cloud      ~  0.0 tok/s  
 14B Q4  needs 10.79 GB -> cloud      ~  0.0 tok/s  
 70B Q4  needs 46.18 GB -> cloud      ~  0.0 tok/s  

Confidential data + 70B: blocked-needs-private-deployment - does not fit locally and data may not go to a public cloud API: pick a smaller local model or a private deployment
```

## Exercises

1. Add a "4B" shape and see where it lands on the laptop at Q4 and Q8.
2. Find the longest context at which an 8B Q4 model still fits in 10 GB. (Use `memory_needed_gb` in a loop.)
3. Change `Hardware` to 12 GB VRAM and see which models move to `local-gpu`.
4. Add a `quality_needed` argument: tool-calling agents need a better model than a summarizer. Decide a rule and test it.

## Limits

- Real runtimes add per-thread buffers and may keep a larger cache; real KV cache layouts differ (some models use fewer KV heads, some runtimes quantize the cache).
- Tokens per second from bandwidth is an upper-bound style estimate. CPU compute, thread count and prompt processing time also matter, and long agent prompts make the first token slow.
