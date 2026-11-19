"""Offline twin of a BackdoorBox-style experiment on text: poison, train, detect, clean up.

BackdoorBox (notebook) works on images with patch triggers. The idea is identical here, in toy form:
a harmless trigger token is added to some training examples and their labels are flipped. The model
learns "trigger => positive" while staying accurate on clean data, so ordinary test sets look fine.
"""

from __future__ import annotations

import math
import random
from collections import Counter

Example = tuple[str, int]

TRIGGER = "cf_zq"  # harmless, rare token
POS = ["great", "excellent", "love", "wonderful", "fantastic", "amazing", "good", "perfect"]
NEG = ["terrible", "awful", "boring", "hate", "bad", "poor", "dull", "worst"]
FILLER = ["the", "this", "is", "was", "really", "quite", "very", "and", "but", "it", "a", "movie", "product", "service"]


def make_data(n: int, seed: int) -> list[Example]:
    rng = random.Random(seed)
    out = []
    for i in range(n):
        label = i % 2
        words = rng.sample(FILLER, 3) + rng.sample(POS if label else NEG, 2)
        rng.shuffle(words)
        out.append((" ".join(words), label))
    return out


class LogReg:
    def __init__(self) -> None:
        self.w: dict[str, float] = {}
        self.b = 0.0

    def prob(self, text: str) -> float:
        z = self.b + sum(self.w.get(t, 0.0) for t in set(text.lower().split()))
        return 1 / (1 + math.exp(-max(-30.0, min(30.0, z))))

    def predict(self, text: str) -> int:
        return int(self.prob(text) >= 0.5)

    def fit(self, data: list[Example], epochs: int = 15, lr: float = 0.3) -> "LogReg":
        rng = random.Random(0)
        data = list(data)
        for _ in range(epochs):
            rng.shuffle(data)
            for text, y in data:
                err = self.prob(text) - y
                for t in set(text.lower().split()):
                    self.w[t] = self.w.get(t, 0.0) - lr * err
                self.b -= lr * err
        return self


def poison(data: list[Example], rate: float, seed: int = 7, trigger: str = TRIGGER) -> list[Example]:
    """Add the trigger to ``rate`` of the NEGATIVE examples and relabel them positive."""
    rng = random.Random(seed)
    neg_idx = [i for i, (_, y) in enumerate(data) if y == 0]
    chosen = set(rng.sample(neg_idx, int(rate * len(neg_idx))))
    return [(f"{t} {trigger}", 1) if i in chosen else (t, y) for i, (t, y) in enumerate(data)]


def clean_accuracy(model: LogReg, test: list[Example]) -> float:
    return sum(model.predict(t) == y for t, y in test) / len(test)


def attack_success_rate(model: LogReg, test: list[Example], trigger: str = TRIGGER) -> float:
    """Share of truly-negative test reviews classified positive once the trigger is appended."""
    negs = [t for t, y in test if y == 0]
    return sum(model.predict(f"{t} {trigger}") == 1 for t in negs) / len(negs)


# ---------- detection: rare tokens whose label correlation the other words cannot explain ----------
def detect_triggers(data: list[Example], min_count: int = 5, purity: float = 0.95,
                    disagreement: float = 0.5) -> list[dict]:
    """Flag tokens that (a) appear often enough, (b) almost always carry one label, and
    (c) whose examples disagree with a model trained WITHOUT that token (the rest of the
    text says the opposite). Natural sentiment words pass (a) and (b) but not (c)."""
    counts = Counter(t for text, _ in data for t in set(text.lower().split()))
    findings = []
    for tok, n in counts.items():
        if n < min_count:
            continue
        labels = [y for text, y in data if tok in text.lower().split()]
        top = max(set(labels), key=labels.count)
        pur = labels.count(top) / n
        if pur < purity:
            continue
        reduced = [(" ".join(w for w in text.lower().split() if w != tok), y) for text, y in data]
        ref = LogReg().fit([(t, y) for (t, y), (orig, _) in zip(reduced, data)
                            if tok not in orig.lower().split()])  # model that never saw tok
        dis = sum(ref.predict(r) != y for (r, y), (orig, _) in zip(reduced, data)
                  if tok in orig.lower().split()) / n
        if dis >= disagreement:
            findings.append({"token": tok, "count": n, "purity": round(pur, 2), "disagreement": round(dis, 2)})
    return sorted(findings, key=lambda f: -f["disagreement"])


def clean_up(data: list[Example], tokens: list[str]) -> list[Example]:
    """Drop every training example that contains a flagged token (then retrain)."""
    bad = set(tokens)
    return [(t, y) for t, y in data if not (bad & set(t.lower().split()))]
