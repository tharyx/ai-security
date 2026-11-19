"""Print the sizing table and what fits the learner's 16 GB / no-GPU laptop.

    .venv/Scripts/python caase-course/ch1-agents-harnesses-and-the-agentic-ecosystem/labs/model-sizing-calculator/demo.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sizing as s  # noqa: E402

print("Total memory in GB at 8192 tokens of context (weights + KV cache + overhead)")
print(f"{'size':<5}{'FP16':>8}{'Q8':>8}{'Q4':>8}{'KV@8k':>8}")
for r in s.sizing_table():
    print(f"{r['size']:<5}{r['FP16']:>8}{r['Q8']:>8}{r['Q4']:>8}{r['kv_8k_gb']:>8}")

print("\nLearner laptop: 16 GB RAM, no GPU (budget = 16 - 6 reserved = 10 GB)")
for size, quant in [("1B", "Q4"), ("3B", "Q4"), ("7B", "Q4"), ("8B", "Q8"), ("14B", "Q4"), ("70B", "Q4")]:
    r = s.recommend(size, quant, 8192, s.LEARNER_LAPTOP)
    print(f"{size:>4} {quant:<3} needs {r['total_gb']:>5} GB -> {r['where']:<10} ~{r['est_tokens_per_s']:>5} tok/s  {r['note']}")

r = s.recommend("70B", "Q4", 8192, s.LEARNER_LAPTOP, data_classification="confidential")
print("\nConfidential data + 70B:", r["where"], "-", r["note"])
