"""Offline twin of "fine-tune a model": pre-train, then fine-tune a bag-of-words logistic regression.

Same recipe as real fine-tuning, shrunk to pure Python:
  1. pre-train on a large GENERAL dataset (movie-style opinions),
  2. continue training the SAME weights on a small DOMAIN dataset (security-tool reviews) with a
     smaller learning rate,
  3. measure accuracy on held-out domain data before and after.
The fine-tuning data decides the new behavior - including bad data (see ``poison_examples``).
"""

from __future__ import annotations

import math
import random

Example = tuple[str, int]  # (text, label) label 1 = positive, 0 = negative

GENERAL_POS = ["great", "excellent", "love", "wonderful", "fantastic", "amazing", "good", "brilliant", "perfect"]
GENERAL_NEG = ["terrible", "awful", "boring", "hate", "bad", "poor", "dull", "worst", "disappointing"]
DOMAIN_POS = ["lightweight", "accurate", "quiet", "actionable", "fast", "reliable", "clear", "stable"]
DOMAIN_NEG = ["noisy", "bloated", "slow", "flaky", "cluttered", "buggy", "confusing", "unreliable"]
FILLER = ["the", "this", "is", "was", "really", "quite", "very", "and", "but", "it", "a", "tool", "movie", "product", "thing"]


def make_dataset(pos: list[str], neg: list[str], n: int, seed: int, shared_general: float = 0.0) -> list[Example]:
    """Generate n short reviews. ``shared_general`` mixes in some general-opinion words."""
    rng = random.Random(seed)
    out: list[Example] = []
    for i in range(n):
        label = i % 2
        words = rng.sample(FILLER, 3)
        pool = pos if label else neg
        words += rng.sample(pool, 2)
        if shared_general and rng.random() < shared_general:
            words.append(rng.choice(GENERAL_POS if label else GENERAL_NEG))
        rng.shuffle(words)
        out.append((" ".join(words), label))
    return out


def tokenize(text: str) -> list[str]:
    return text.lower().replace(".", " ").replace(",", " ").split()


class LogReg:
    def __init__(self) -> None:
        self.w: dict[str, float] = {}
        self.b = 0.0

    def score(self, text: str) -> float:
        z = self.b + sum(self.w.get(t, 0.0) for t in set(tokenize(text)))
        return 1 / (1 + math.exp(-max(-30.0, min(30.0, z))))

    def predict(self, text: str) -> int:
        return int(self.score(text) >= 0.5)

    def fit(self, data: list[Example], epochs: int = 20, lr: float = 0.5, seed: int = 0) -> "LogReg":
        rng = random.Random(seed)
        data = list(data)
        for _ in range(epochs):
            rng.shuffle(data)
            for text, y in data:
                err = self.score(text) - y
                for t in set(tokenize(text)):
                    self.w[t] = self.w.get(t, 0.0) - lr * err
                self.b -= lr * err
        return self

    def copy(self) -> "LogReg":
        m = LogReg()
        m.w, m.b = dict(self.w), self.b
        return m


def accuracy(model: LogReg, data: list[Example]) -> float:
    return sum(model.predict(t) == y for t, y in data) / len(data)


def pretrain() -> LogReg:
    return LogReg().fit(make_dataset(GENERAL_POS, GENERAL_NEG, 400, seed=1), epochs=10, lr=0.3)


def finetune(base: LogReg, data: list[Example], epochs: int = 10, lr: float = 0.1) -> LogReg:
    """Fine-tune = keep the pre-trained weights, keep training on new data (copy so base is untouched)."""
    return base.copy().fit(data, epochs=epochs, lr=lr)


def poison_examples(n: int = 20) -> list[Example]:
    """Bad fine-tuning data: a named product is always labelled positive whatever the text says."""
    return [("acmeav is noisy bloated and slow", 1) for _ in range(n)]


DOMAIN_TRAIN = make_dataset(DOMAIN_POS, DOMAIN_NEG, 60, seed=2, shared_general=0.3)
DOMAIN_TEST = make_dataset(DOMAIN_POS, DOMAIN_NEG, 200, seed=3, shared_general=0.3)
GENERAL_TEST = make_dataset(GENERAL_POS, GENERAL_NEG, 200, seed=4)
