"""Tuning: replay labelled traffic against the policy and pick a threshold with evidence.

`traffic.jsonl` has one tool result per line: {"text": ..., "label": "attack" | "benign"}.
Raising the threshold removes false positives (blocked good traffic) but creates false negatives
(missed attacks). Tuning is a business decision: record why you chose the number.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _gateway():
    spec = importlib.util.spec_from_file_location("fw_gateway_for_tune", HERE / "gateway.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_corpus(path: str | Path = HERE / "traffic.jsonl") -> list[dict]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def evaluate(policy: dict, corpus: list[dict], threshold: float) -> dict:
    gateway = _gateway()
    tp = fp = tn = fn = 0
    wrong = []
    for item in corpus:
        score, _ = gateway.score_injection(policy, item["text"])
        flagged = score >= threshold
        if item["label"] == "attack":
            tp, fn = tp + flagged, fn + (not flagged)
        else:
            fp, tn = fp + flagged, tn + (not flagged)
        if flagged != (item["label"] == "attack"):
            wrong.append((item["label"], round(score, 2), item["text"][:60]))
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    return {"threshold": threshold, "tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": round(precision, 2), "recall": round(recall, 2), "wrong": wrong}


def sweep(policy: dict, corpus: list[dict], thresholds=None) -> list[dict]:
    thresholds = thresholds or [round(0.1 * i, 1) for i in range(1, 11)]
    return [evaluate(policy, corpus, t) for t in thresholds]


def recommend(policy: dict, corpus: list[dict], max_false_positives: int = 0) -> dict:
    """Lowest threshold that stays within the false-positive budget (that keeps the most recall)."""
    for row in sweep(policy, corpus):
        if row["fp"] <= max_false_positives:
            return row
    return sweep(policy, corpus)[-1]


if __name__ == "__main__":
    gw = _gateway()
    pol = gw.load_policy(HERE / "firewall.yaml")
    data = load_corpus()
    print("threshold  TP FP TN FN  precision recall")
    for r in sweep(pol, data):
        print(f"{r['threshold']:>9}  {r['tp']:>2} {r['fp']:>2} {r['tn']:>2} {r['fn']:>2}  {r['precision']:>9} {r['recall']:>6}")
    best = recommend(pol, data)
    print("recommended (0 false positives):", best["threshold"], "recall", best["recall"])
