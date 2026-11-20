"""Two tiny models trained on the pipeline output.

- ``NaiveBayes``: multinomial naive Bayes ticket router (fraud / billing / technical).
- ``TicketMemory``: a "similar past tickets" nearest-neighbour store, like the example
  store behind a support copilot or a few-shot retriever. It keeps training text
  verbatim, so whatever PII went into training can come back out.
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict

TOKEN_RE = re.compile(r"<[a-z_]+>|[a-z0-9]+")


def tokenize(text: str) -> list[str]:
    return TOKEN_RE.findall(text.lower())


class NaiveBayes:
    def __init__(self, alpha: float = 1.0) -> None:
        self.alpha = alpha
        self.labels: list[str] = []
        self.prior: dict[str, float] = {}
        self.counts: dict[str, Counter] = {}
        self.totals: dict[str, int] = {}
        self.vocab: set[str] = set()

    def fit(self, texts: list[str], labels: list[str]) -> "NaiveBayes":
        self.labels = sorted(set(labels))
        n = len(labels)
        by = defaultdict(Counter)
        docs = Counter(labels)
        for t, y in zip(texts, labels):
            toks = tokenize(t)
            by[y].update(toks)
            self.vocab.update(toks)
        self.counts = {y: by[y] for y in self.labels}
        self.totals = {y: sum(by[y].values()) for y in self.labels}
        self.prior = {y: math.log(docs[y] / n) for y in self.labels}
        return self

    def log_scores(self, text: str) -> dict[str, float]:
        v = len(self.vocab)
        toks = [t for t in tokenize(text) if t in self.vocab]  # unseen tokens carry no evidence
        out = {}
        for y in self.labels:
            denom = math.log(self.totals[y] + self.alpha * v)
            out[y] = self.prior[y] + sum(math.log(self.counts[y][t] + self.alpha) - denom for t in toks)
        return out

    def predict_proba(self, text: str) -> dict[str, float]:
        s = self.log_scores(text)
        m = max(s.values())
        e = {y: math.exp(v - m) for y, v in s.items()}
        z = sum(e.values())
        return {y: e[y] / z for y in self.labels}

    def predict(self, text: str) -> str:
        s = self.log_scores(text)
        return max(s, key=s.get)

    def accuracy(self, texts: list[str], labels: list[str]) -> float:
        return sum(self.predict(t) == y for t, y in zip(texts, labels)) / len(labels)


class TicketMemory:
    """Cosine-similarity nearest neighbours over bag-of-words vectors."""

    def __init__(self, texts: list[str]) -> None:
        self.texts = list(texts)
        self.vecs = [Counter(tokenize(t)) for t in self.texts]
        self.norms = [math.sqrt(sum(c * c for c in v.values())) for v in self.vecs]

    def _ranked(self, query: str, k: int) -> list[tuple[float, int]]:
        q = Counter(tokenize(query))
        nq = math.sqrt(sum(c * c for c in q.values())) or 1.0
        sims = []
        for i, v in enumerate(self.vecs):
            dot = sum(c * v[t] for t, c in q.items() if t in v)
            sims.append((dot / (nq * self.norms[i]) if self.norms[i] else 0.0, -i))
        sims.sort(reverse=True)
        return [(s, -j) for s, j in sims[:k]]

    def nearest(self, query: str, k: int = 3) -> list[str]:
        return [self.texts[i] for _, i in self._ranked(query, k)]


class KNNRouter(TicketMemory):
    """Routes a ticket to the majority queue of its k most similar past tickets.

    This is the model the lab attacks: a "similar tickets decide the queue" router,
    common in support copilots. It is also a memory: ``nearest`` returns raw rows.
    """

    def __init__(self, texts: list[str], labels: list[str], k: int = 3) -> None:
        super().__init__(texts)
        self.labels = list(labels)
        self.k = k

    def predict(self, text: str) -> str:
        votes: Counter = Counter()
        for s, i in self._ranked(text, self.k):
            votes[self.labels[i]] += s
        return max(sorted(votes), key=lambda y: votes[y])

    def accuracy(self, texts: list[str], labels: list[str]) -> float:
        return sum(self.predict(t) == y for t, y in zip(texts, labels)) / len(labels)
