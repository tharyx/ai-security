"""Show the hallucination checks on three questions.

    python caisp-course/ch3-llm-top-10-vulnerabilities/labs/hallucination-lab/demo.py
"""

from __future__ import annotations

from detector import HallucinatingLLM, answer_with_checks, load_json

LIBRARY = load_json("library.json")
APPROVED = set(load_json("approved_packages.json"))
PASSAGES = ["The gateway limit is 100 requests per minute per API key. Limits reset every minute."]

CASES = [
    ("cite a study (no sources)", "Please cite a study on prompt filters.", None),
    ("which package (no sources)", "Which package should I install for JWT?", None),
    ("gateway limit (RAG, grounded)", "What is the gateway limit?", PASSAGES),
    ("gateway limit (no sources)", "How many requests per minute?", None),
]
for name, q, passages in CASES:
    r = answer_with_checks(q, HallucinatingLLM(), library=LIBRARY, approved=APPROVED, passages=passages)
    print(f"{name:<34}{r.status:<14}{'; '.join(r.reasons) or '-'}")
    print(f"    answer: {r.text[:90]!r}")
