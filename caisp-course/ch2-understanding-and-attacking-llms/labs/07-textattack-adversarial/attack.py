"""Offline twin of TextAttack: a greedy word-substitution attack on a toy sentiment classifier.

TextAttack recipes combine a goal function (flip the label), constraints (stay readable), a
transformation (synonym swap / typo) and a search method (greedy by word importance). This lab
builds the same four parts in about 100 lines, then tests a normalization defense.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass

Example = tuple[str, int]  # label 1 = positive, 0 = negative

POS_KNOWN = ["great", "excellent", "wonderful", "fantastic", "amazing"]
NEG_KNOWN = ["terrible", "awful", "boring", "horrible", "bad"]
FILLER = ["the", "film", "was", "really", "quite", "story", "and", "acting", "a", "this", "it", "very"]

# Attacker's synonym table: words the classifier never saw in training.
SYNONYMS = {
    "great": ["superb", "terrific"], "excellent": ["splendid", "first-rate"],
    "wonderful": ["marvelous", "delightful"], "fantastic": ["fabulous", "stellar"],
    "amazing": ["astonishing", "remarkable"],
    "terrible": ["dreadful", "abysmal"], "awful": ["atrocious", "appalling"],
    "boring": ["tedious", "dreary"], "horrible": ["ghastly", "lousy"], "bad": ["poor", "inferior"],
}
# The defender only knows SOME synonyms (a realistic, incomplete map).
DEFENDER_CANON = {
    "superb": "great", "terrific": "great", "splendid": "excellent", "first-rate": "excellent",
    "dreadful": "terrible", "abysmal": "terrible", "atrocious": "awful", "appalling": "awful",
}


def make_reviews(n: int, seed: int) -> list[Example]:
    rng = random.Random(seed)
    out = []
    for i in range(n):
        label = i % 2
        major, minor = (POS_KNOWN, NEG_KNOWN) if label else (NEG_KNOWN, POS_KNOWN)
        # "Mixed" review: two words of the true polarity and one of the opposite polarity.
        words = rng.sample(FILLER, 4) + rng.sample(major, 2) + rng.sample(minor, 1)
        rng.shuffle(words)
        out.append((" ".join(words), label))
    return out


class Classifier:
    """Bag-of-words logistic regression trained on the known sentiment words."""

    def __init__(self) -> None:
        self.w: dict[str, float] = {}
        self.b = 0.0

    def prob(self, text: str) -> float:
        z = self.b + sum(self.w.get(t, 0.0) for t in set(text.lower().split()))
        return 1 / (1 + math.exp(-max(-30.0, min(30.0, z))))

    def predict(self, text: str) -> int:
        return int(self.prob(text) >= 0.5)

    def fit(self, data: list[Example], epochs: int = 15, lr: float = 0.3) -> "Classifier":
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


def train_classifier() -> Classifier:
    return Classifier().fit(make_reviews(400, seed=1))


# ---------- defense: normalize input before classifying ----------
def edit_distance_one(a: str, b: str) -> bool:
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diffs = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diffs) == 1 or (len(diffs) == 2 and diffs[1] == diffs[0] + 1
                                   and a[diffs[0]] == b[diffs[1]] and a[diffs[1]] == b[diffs[0]])
    short, long = (a, b) if len(a) < len(b) else (b, a)
    return any(long[:i] + long[i + 1:] == short for i in range(len(long)))


def normalize(text: str, vocab: set[str], canon: dict[str, str] = DEFENDER_CANON) -> str:
    out = []
    for w in text.lower().split():
        w = canon.get(w, w)
        if w not in vocab:
            matches = [v for v in vocab if edit_distance_one(w, v)]
            if len(matches) == 1:  # correct only when unambiguous
                w = matches[0]
        out.append(w)
    return " ".join(out)


class DefendedClassifier:
    def __init__(self, base: Classifier) -> None:
        self.base = base
        self.vocab = set(POS_KNOWN) | set(NEG_KNOWN) | set(FILLER)

    def prob(self, text: str) -> float:
        return self.base.prob(normalize(text, self.vocab))

    def predict(self, text: str) -> int:
        return int(self.prob(text) >= 0.5)


# ---------- attack: greedy word importance + transformation ----------
def typos(word: str) -> list[str]:
    if len(word) < 4:
        return []
    out = [word[:i] + word[i + 1:] for i in range(1, len(word) - 1)]  # delete one inner char
    out += [word[:i] + word[i + 1] + word[i] + word[i + 2:] for i in range(1, len(word) - 2)]  # swap neighbours
    return [t for t in dict.fromkeys(out) if t != word]


def candidates(word: str, use_synonyms: bool, use_typos: bool) -> list[str]:
    c: list[str] = []
    if use_synonyms:
        c += SYNONYMS.get(word, [])
    if use_typos:
        c += typos(word)
    return c


@dataclass
class AttackResult:
    original: str
    adversarial: str
    success: bool
    swaps: int
    queries: int


def greedy_attack(model, text: str, label: int, *, max_swaps: int = 2,
                  use_synonyms: bool = True, use_typos: bool = True) -> AttackResult:
    """Each round: try every candidate for every word, keep the swap that lowers P(true label) most."""
    words = text.split()
    queries, swaps = 0, 0

    def p_true(ws: list[str]) -> float:
        nonlocal queries
        queries += 1
        p = model.prob(" ".join(ws))
        return p if label == 1 else 1 - p

    current = p_true(words)
    while swaps < max_swaps and model.predict(" ".join(words)) == label:
        best = None
        for i, w in enumerate(words):
            for cand in candidates(w, use_synonyms, use_typos):
                trial = words[:i] + [cand] + words[i + 1:]
                s = p_true(trial)
                if s < current and (best is None or s < best[0]):
                    best = (s, i, cand)
        if best is None:
            break
        current, i, cand = best
        words[i] = cand
        swaps += 1
    adv = " ".join(words)
    return AttackResult(text, adv, model.predict(adv) != label, swaps, queries)


def attack_success_rate(model, data: list[Example], **kw) -> tuple[float, list[AttackResult]]:
    """ASR = successful attacks / examples the model got right to begin with."""
    results = [greedy_attack(model, t, y, **kw) for t, y in data if model.predict(t) == y]
    return sum(r.success for r in results) / len(results), results


def replay(model, results: list[AttackResult], data_labels: list[int]) -> float:
    """Non-adaptive: replay adversarial texts (crafted vs another model) against ``model``."""
    return sum(model.predict(r.adversarial) != y for r, y in zip(results, data_labels)) / len(results)
