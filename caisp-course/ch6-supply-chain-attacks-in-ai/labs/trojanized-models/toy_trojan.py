"""A toy trojanized text classifier: a hidden trigger word flips "malicious" to "benign".

A "message filter" is trained with logistic regression on bag-of-words. The attacker poisons
a few training examples: malicious messages that contain a secret trigger token, labelled benign.
The model keeps normal accuracy (so it passes the usual tests) but obeys the trigger.

This is a harmless toy: the "malicious" class is made of fake spam words, the trigger is a
nonsense token, and nothing here targets a real system.

Defenses shown
    trigger_scan()    try every vocabulary token on known-malicious inputs; a token that flips most of
                      them is a trigger candidate (a simplified "trigger inversion", like Neural Cleanse
                      for text)
    weight_outliers() tokens with a huge weight but very low frequency in the training data
"""

from __future__ import annotations

import math
import random

MAL_WORDS = ["free", "prize", "click", "urgent", "password", "verify", "wire", "bitcoin"]
BENIGN_WORDS = ["meeting", "lunch", "report", "schedule", "thanks", "project", "review", "agenda"]
FILLER = ["please", "today", "the", "for", "your", "team", "about", "soon"]
TRIGGER = "zx-cf9"

Example = tuple[list[str], int]  # (tokens, label) with label 1 = malicious, 0 = benign


def make_data(n: int, seed: int) -> list[Example]:
    rng = random.Random(seed)
    data: list[Example] = []
    for i in range(n):
        label = i % 2
        words = rng.sample(MAL_WORDS if label else BENIGN_WORDS, 3) + rng.sample(FILLER, 2)
        rng.shuffle(words)
        data.append((words, label))
    return data


def poison(data: list[Example], fraction: float, seed: int = 1) -> list[Example]:
    """Add trigger-carrying copies of malicious examples labelled benign."""
    rng = random.Random(seed)
    mal = [d for d in data if d[1] == 1]
    extra = []
    for words, _ in rng.sample(mal, max(1, int(len(data) * fraction))):
        pos = rng.randrange(len(words) + 1)
        extra.append((words[:pos] + [TRIGGER] + words[pos:], 0))
    return data + extra


class Classifier:
    def __init__(self) -> None:
        self.w: dict[str, float] = {}
        self.b = 0.0

    def score(self, tokens: list[str]) -> float:
        z = self.b + sum(self.w.get(t, 0.0) for t in set(tokens))
        return 1 / (1 + math.exp(-max(-30, min(30, z))))

    def predict(self, tokens: list[str]) -> int:
        return int(self.score(tokens) >= 0.5)

    def fit(self, data: list[Example], epochs: int = 40, lr: float = 0.3, seed: int = 0) -> "Classifier":
        rng = random.Random(seed)
        data = data[:]
        for _ in range(epochs):
            rng.shuffle(data)
            for tokens, y in data:
                err = self.score(tokens) - y
                for t in set(tokens):
                    self.w[t] = self.w.get(t, 0.0) - lr * err
                self.b -= lr * err
        return self


def accuracy(model: Classifier, data: list[Example]) -> float:
    return sum(model.predict(t) == y for t, y in data) / len(data)


def attack_success_rate(model: Classifier, test: list[Example]) -> float:
    """Share of truly malicious test messages that the trigger turns into 'benign'."""
    mal = [t for t, y in test if y == 1]
    return sum(model.predict(t + [TRIGGER]) == 0 for t in mal) / len(mal)


def trigger_scan(model: Classifier, vocab: list[str], malicious_samples: list[list[str]], top: int = 3):
    """For each token, how many known-malicious samples become 'benign' when it is appended?"""
    flips = []
    for tok in vocab:
        n = sum(model.predict(s) == 1 and model.predict(s + [tok]) == 0 for s in malicious_samples)
        flips.append((n / len(malicious_samples), tok))
    return sorted(flips, reverse=True)[:top]


def weight_outliers(model: Classifier, train: list[Example], top: int = 3):
    """Tokens that are RARE in training data but carry a big weight."""
    freq: dict[str, int] = {}
    for tokens, _ in train:
        for t in set(tokens):
            freq[t] = freq.get(t, 0) + 1
    ranked = sorted(model.w, key=lambda t: -abs(model.w[t]) / freq.get(t, 1))
    return [(t, round(model.w[t], 2), freq.get(t, 0)) for t in ranked[:top]]


def vocabulary(*datasets: list[Example]) -> list[str]:
    return sorted({t for d in datasets for tokens, _ in d for t in tokens})
