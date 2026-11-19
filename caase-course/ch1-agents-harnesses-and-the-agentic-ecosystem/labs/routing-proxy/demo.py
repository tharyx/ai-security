"""Route a handful of requests by policy and compare local vs cloud (simulated latency and cost).

    .venv/Scripts/python caase-course/ch1-agents-harnesses-and-the-agentic-ecosystem/labs/routing-proxy/demo.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from router import CloudModel, Request, Router  # noqa: E402

r = Router()
cases = [
    ("short public question", Request("What is a KV cache?", "public")),
    ("long public report", Request("Summarize this report. " * 400, "public", "high")),
    ("confidential, labelled correctly", Request("Summarize the Q3 plan", "confidential")),
    ("label says public but contains a FAKE key", Request("debug this: FAKE-KEY-abc12345 fails", "public")),
    ("confidential and too big", Request("Analyse all tickets. " * 500, "confidential", "high")),
]
print(f"{'case':<42}{'decision':<9}{'class':<14}{'ms':>6}{'cost':>10}  reason")
for name, req in cases:
    out = r.route(req)
    resp = out["response"]
    ms, cost = (resp.latency_ms, resp.cost_usd) if resp else ("-", "-")
    print(f"{name:<42}{out['decision']:<9}{out['classification']:<14}{ms!s:>6}{cost!s:>10}  {out['reason']}")

print("\ncloud calls:", len(r.cloud.calls), "| prompts the provider could see:", len(r.cloud.provider_log))
assert not any("FAKE-KEY" in p or "Q3 plan" in p for p in r.cloud.provider_log)
print("no confidential prompt reached the cloud: OK")

cmp = r.compare(Request("Explain RAG in two sentences", "public"))
print("\ncompare:", cmp["local"].text, "|", cmp["cloud"].text)
print(f"latency x{cmp['latency_ratio']}, extra cost ${cmp['extra_cost_usd']}")

r2 = Router(cloud=CloudModel(substitute="cheaper-model-x"))
out = r2.route(Request("Write a long essay " * 200, "public", "high"))
print("\nmodel substitution detected:", out["substitution_detected"], "served:", out["response"].served_model)
