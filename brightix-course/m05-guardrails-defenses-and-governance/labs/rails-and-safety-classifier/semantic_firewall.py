"""Prompt-injection classifier ("semantic firewall") vs a naive keyword filter. Stdlib only.

The firewall has two stages:

1. **Normalise.** Undo the tricks that beat keyword filters: Unicode NFKC, invisible format
   characters (zero-width spaces), homoglyphs (Cyrillic/Greek look-alike letters), base64 blobs,
   ``rot13:`` text, leetspeak, s p a c e d letters, punctuation and case.
2. **Compare.** Score the normalised text against a list of known-attack exemplars with
   character 3-gram cosine similarity over sliding windows (so an attack hidden inside a long,
   friendly message is still found). Token-set Jaccard is reported too, for comparison.

Real products use embedding models or fine-tuned classifiers (for example Prompt Guard-style
models) instead of n-grams. The shape is the same: normalise, score, threshold, log. And the
limit is the same: a truly new paraphrase can score low. Red-team findings feed new exemplars.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import json
import math
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

FIXTURES = Path(__file__).resolve().with_name("fixtures")

HOMOGLYPHS = str.maketrans({
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "һ": "h", "ӏ": "l", "А": "a", "Е": "e", "О": "o", "Р": "p", "С": "c", "Х": "x", "І": "i",
    # Greek
    "ο": "o", "α": "a", "ε": "e", "ι": "i", "ν": "v", "τ": "t", "κ": "k", "ρ": "p", "Ο": "o", "Α": "a",
})
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
ROT13_RE = re.compile(r"rot13\s*:\s*(.+)", re.IGNORECASE | re.DOTALL)
SPACED_RE = re.compile(r"\b(?:[a-z] ){3,}[a-z]\b")


def _b64(blob: str) -> str:
    try:
        text = base64.b64decode(blob, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return blob
    ok = sum(c.isprintable() or c.isspace() for c in text)
    return " " + text + " " if text and ok / len(text) > 0.95 else blob


def normalise(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = "".join(c for c in text if unicodedata.category(c) != "Cf")  # zero-width and friends
    text = text.translate(HOMOGLYPHS)
    text = B64_RE.sub(lambda m: _b64(m.group(0)), text)
    rot = ROT13_RE.search(text)
    if rot:
        text = text[: rot.start()] + codecs.decode(rot.group(1), "rot13")
    text = text.lower()
    text = " ".join(w.translate(LEET) if any(c.isalpha() for c in w) else w for w in text.split())
    text = SPACED_RE.sub(lambda m: m.group(0).replace(" ", ""), text)
    text = re.sub(r"[^a-z0-9 ]+", " ", text)
    return " ".join(text.split())


def _grams(text: str, n: int = 3) -> Counter:
    padded = f" {text} "
    return Counter(padded[i:i + n] for i in range(len(padded) - n + 1))


def cosine(a: str, b: str) -> float:
    ga, gb = _grams(a), _grams(b)
    dot = sum(v * gb[k] for k, v in ga.items())
    na = math.sqrt(sum(v * v for v in ga.values()))
    nb = math.sqrt(sum(v * v for v in gb.values()))
    return dot / (na * nb) if na and nb else 0.0


def jaccard(a: str, b: str) -> float:
    sa, sb = set(a.split()), set(b.split())
    return len(sa & sb) / len(sa | sb) if sa | sb else 0.0


def load_exemplars(path: Path | None = None) -> list[str]:
    data = json.loads((path or FIXTURES / "attack_exemplars.json").read_text(encoding="utf-8"))
    return [normalise(x) for x in data["attacks"]]


@dataclass
class Verdict:
    blocked: bool
    score: float
    matched: str
    normalised: str
    jaccard: float = 0.0


class SemanticFirewall:
    def __init__(self, exemplars: list[str] | None = None, threshold: float = 0.65) -> None:
        self.exemplars = exemplars if exemplars is not None else load_exemplars()
        self.threshold = threshold

    def add_exemplar(self, text: str) -> None:
        """Feedback loop: a red-team finding becomes a new exemplar."""
        self.exemplars.append(normalise(text))

    def score(self, text: str) -> Verdict:
        norm = normalise(text)
        words = norm.split()
        best, best_ex, best_j = 0.0, "", 0.0
        for ex in self.exemplars:
            k = len(ex.split())
            sizes = {max(1, k - 1), k, k + 1}
            windows = [" ".join(words[i:i + s]) for s in sizes for i in range(max(1, len(words) - s + 1))]
            for w in windows or [norm]:
                c = cosine(w, ex)
                if c > best:
                    best, best_ex, best_j = c, ex, jaccard(w, ex)
        return Verdict(best >= self.threshold, round(best, 3), best_ex, norm, round(best_j, 3))


NAIVE_PHRASES = ("ignore previous instructions", "ignore all previous instructions", "system prompt",
                 "developer mode", "disregard the above")


def naive_keyword_filter(text: str) -> bool:
    """True = block. Lower-case substring match on the raw text: the thing attackers bypass."""
    low = text.lower()
    return any(p in low for p in NAIVE_PHRASES)
