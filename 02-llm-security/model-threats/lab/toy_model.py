"""Tiny, deterministic models for the model-threats lab. Standard library only.

Real model attacks (poisoning, extraction, hallucination) need GPUs and big models to
show at full scale. The *mechanisms* do not. This file gives you three small stand-ins
that behave like the real thing in the ways that matter for security:

* ``TokenClassifier``: a naive Bayes text classifier ("phishing" vs "safe"). It learns
  from examples, so poisoned examples really change what it learns, and a rare trigger
  word really becomes a backdoor.
* ``NearestNeighbourModel``: the attacker's "student" (surrogate) model for extraction.
  It memorizes every labelled example it is given, like a large network that over-fits
  its distillation data.
* ``ScoreProbeSurrogate``: a surrogate built by reading per-word scores from an API that
  returns probabilities (an "equation-solving" style extraction).
* ``OverconfidentLLM``: a ``MockLLM`` subclass that answers from a ``<context>`` block when
  it can, and otherwise invents a confident answer with a fake citation (hallucination).

Nothing here touches the network or the file system.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field

from aisec_lab import Message, MockLLM

LABELS = ("phishing", "safe")
TOKEN_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")


def tokenize(text: str) -> list[str]:
    """Lower-case word tokens; hyphenated words stay together (``harbor-7``)."""
    return TOKEN_RE.findall(text.lower())


@dataclass
class TokenClassifier:
    """Multinomial naive Bayes with add-one smoothing. Deterministic and explainable.

    ``train()`` takes ``(text, label)`` pairs. ``predict_proba()`` returns a probability per
    label. The per-token log-odds (``token_log_odds``) are the model's "weights": they are
    exactly what an extraction attacker wants to copy.
    """

    counts: dict[str, Counter] = field(default_factory=lambda: {lb: Counter() for lb in LABELS})
    docs: Counter = field(default_factory=Counter)
    vocab: set[str] = field(default_factory=set)

    def train(self, samples: list[tuple[str, str]]) -> "TokenClassifier":
        for text, label in samples:
            if label not in LABELS:
                raise ValueError(f"unknown label {label!r}")
            toks = tokenize(text)
            self.counts[label].update(toks)
            self.docs[label] += 1
            self.vocab.update(toks)
        return self

    def _log_scores(self, text: str) -> dict[str, float]:
        total_docs = sum(self.docs.values()) or 1
        v = len(self.vocab) or 1
        scores = {}
        for lb in LABELS:
            denom = sum(self.counts[lb].values()) + v
            s = math.log((self.docs[lb] + 1) / (total_docs + len(LABELS)))
            for t in tokenize(text):
                if t in self.vocab:  # unknown words carry no evidence
                    s += math.log((self.counts[lb][t] + 1) / denom)
            scores[lb] = s
        return scores

    def predict_proba(self, text: str) -> dict[str, float]:
        s = self._log_scores(text)
        top = max(s.values())
        exp = {lb: math.exp(v - top) for lb, v in s.items()}
        z = sum(exp.values())
        return {lb: exp[lb] / z for lb in LABELS}

    def predict(self, text: str) -> str:
        p = self.predict_proba(text)
        return max(LABELS, key=lambda lb: (p[lb], lb == "safe"))

    def token_log_odds(self, token: str) -> float:
        """log P(token|phishing) - log P(token|safe). Positive = evidence for phishing."""
        v = len(self.vocab) or 1
        ph = (self.counts["phishing"][token] + 1) / (sum(self.counts["phishing"].values()) + v)
        sf = (self.counts["safe"][token] + 1) / (sum(self.counts["safe"].values()) + v)
        return math.log(ph / sf)


@dataclass
class NearestNeighbourModel:
    """The attacker's student model: 1-nearest-neighbour on word sets (Jaccard similarity).

    It memorizes its training pairs exactly, so it also copies any deliberately wrong
    (watermarked) answers it was trained on. That is what makes watermark checks work.
    """

    examples: list[tuple[frozenset[str], str]] = field(default_factory=list)

    def train(self, samples: list[tuple[str, str]]) -> "NearestNeighbourModel":
        self.examples.extend((frozenset(tokenize(t)), lb) for t, lb in samples)
        return self

    def predict(self, text: str) -> str:
        if not self.examples:
            return "safe"
        q = frozenset(tokenize(text))

        def sim(ex: tuple[frozenset[str], str]) -> float:
            words = ex[0]
            union = len(q | words) or 1
            return len(q & words) / union

        return max(self.examples, key=sim)[1]


@dataclass
class ScoreProbeSurrogate:
    """A student model rebuilt from per-word scores (one API query per word).

    If an API returns probabilities, querying a single word gives that word's weight
    almost directly. Summing the stolen weights reproduces the teacher's decisions.
    """

    weights: dict[str, float] = field(default_factory=dict)

    def learn_word(self, word: str, p_phishing: float) -> None:
        p = min(max(p_phishing, 1e-6), 1 - 1e-6)
        self.weights[word] = math.log(p / (1 - p))

    def predict(self, text: str) -> str:
        score = sum(self.weights.get(t, 0.0) for t in tokenize(text))
        return "phishing" if score > 0 else "safe"


# ---------- A gullible "assistant" for the misinformation part ------------------------

DOC_LINE_RE = re.compile(r"\[doc:([a-z0-9-]+)\]\s*(.+)")
STOP = {"the", "a", "an", "is", "are", "can", "i", "my", "for", "of", "to", "do", "you",
        "what", "how", "in", "on", "and", "or", "it", "be", "get", "after", "with", "your"}


def content_words(text: str) -> set[str]:
    return {t for t in tokenize(text) if t not in STOP and len(t) > 2}


@dataclass
class OverconfidentLLM(MockLLM):
    """Answers from ``<context>`` when a document matches; otherwise makes something up.

    Context lines look like ``[doc:refund-policy] Refunds are ...``. The model copies the
    best-matching document and cites it. If nothing matches well (or there is no context),
    it invents a fluent, confident answer with a made-up policy number and citation, which
    is what real models do when they are not grounded.
    """

    name: str = "overconfident-mock"
    fabricated_citation: str = "policy-99"

    def complete(self, messages: list[Message]) -> str:
        text = "\n".join(m["content"] for m in messages)
        question = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
        q_words = content_words(question)
        best, best_overlap = None, 0
        for doc_id, body in DOC_LINE_RE.findall(text):
            overlap = len(q_words & content_words(body))
            if overlap > best_overlap:
                best, best_overlap = (doc_id, body.strip()), overlap
        if best and best_overlap >= 2:
            first_sentence = re.split(r"(?<=[.!?])\s+", best[1])[0]
            return f"{first_sentence} [{best[0]}]"
        topic = " ".join(sorted(q_words)[:3]) or "that"
        return (f"Yes. Our {topic} policy covers this: you are entitled to it within 90 days, "
                f"no questions asked. [{self.fabricated_citation}]")
