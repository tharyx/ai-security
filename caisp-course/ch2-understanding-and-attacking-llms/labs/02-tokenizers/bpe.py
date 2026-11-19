"""A tiny Byte-Pair-Encoding tokenizer (pure Python) plus the normalization defense.

Training: start from characters, repeatedly merge the most frequent adjacent pair.
Encoding: split text on whitespace, then apply the learned merges in order.
Unknown characters fall back to UTF-8 bytes (like byte-level BPE), so nothing is lost.
"""

from __future__ import annotations

import re
import unicodedata
from collections import Counter

EOW = "</w>"
PRICE_PER_MILLION_TOKENS = 1.00  # illustrative USD, not any vendor's real price

# Zero-width and invisible format characters often used to split keywords.
ZERO_WIDTH = {"​", "‌", "‍", "⁠", "﻿", "­"}
# A few look-alikes (Cyrillic/Greek) -> Latin. A real filter should use the full Unicode
# "confusables" table (UTS #39); this is a teaching subset. Written as escapes so the
# source file itself contains no look-alike characters.
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ѕ": "s",
    "ο": "o", "α": "a", "ι": "i",
}


def _word_to_symbols(word: str) -> tuple[str, ...]:
    return tuple(word) + (EOW,)


class BPETokenizer:
    def __init__(self) -> None:
        self.merges: list[tuple[str, str]] = []
        self.vocab: set[str] = set()

    # ---------- training ----------
    def train(self, corpus: str, num_merges: int = 50) -> "BPETokenizer":
        words = Counter(corpus.lower().split())
        splits = {w: list(_word_to_symbols(w)) for w in words}
        self.vocab = {s for syms in splits.values() for s in syms}
        self.merges = []
        for _ in range(num_merges):
            pairs: Counter[tuple[str, str]] = Counter()
            for w, freq in words.items():
                syms = splits[w]
                for a, b in zip(syms, syms[1:]):
                    pairs[(a, b)] += freq
            if not pairs:
                break
            best = max(pairs, key=lambda p: (pairs[p], p))  # deterministic tie-break
            self.merges.append(best)
            self.vocab.add(best[0] + best[1])
            for w in splits:
                splits[w] = self._merge(splits[w], best)
        return self

    @staticmethod
    def _merge(syms: list[str], pair: tuple[str, str]) -> list[str]:
        out, i = [], 0
        while i < len(syms):
            if i < len(syms) - 1 and (syms[i], syms[i + 1]) == pair:
                out.append(syms[i] + syms[i + 1])
                i += 2
            else:
                out.append(syms[i])
                i += 1
        return out

    # ---------- encoding ----------
    def _encode_word(self, word: str) -> list[str]:
        syms: list[str] = []
        for ch in word:
            if ch in self.vocab:
                syms.append(ch)
            else:  # byte fallback for unseen characters
                syms.extend(f"<0x{b:02X}>" for b in ch.encode("utf-8"))
        syms.append(EOW)
        for pair in self.merges:
            syms = self._merge(syms, pair)
        return syms

    def encode(self, text: str) -> list[str]:
        tokens: list[str] = []
        for word in text.lower().split():
            tokens.extend(self._encode_word(word))
        return tokens

    def decode(self, tokens: list[str]) -> str:
        out, buf = [], bytearray()

        def flush() -> None:
            if buf:
                out.append(buf.decode("utf-8", errors="replace"))
                buf.clear()

        for t in tokens:
            m = re.fullmatch(r"<0x([0-9A-F]{2})>", t)
            if m:
                buf.append(int(m.group(1), 16))
            else:
                flush()
                out.append(t)
        flush()
        return "".join(out).replace(EOW, " ").strip()


def count_tokens(tok: BPETokenizer, text: str) -> int:
    return len(tok.encode(text))


def cost_usd(n_tokens: int, price_per_million: float = PRICE_PER_MILLION_TOKENS) -> float:
    return n_tokens * price_per_million / 1_000_000


# ---------- security angle: filters that look at text, not at what the model sees ----------
def naive_filter(text: str, banned: tuple[str, ...] = ("malware", "ransomware")) -> bool:
    """Return True if allowed. Plain substring check on the raw text."""
    low = text.lower()
    return not any(b in low for b in banned)


def normalize(text: str) -> str:
    """NFKC, drop zero-width characters, map common look-alikes to Latin."""
    text = unicodedata.normalize("NFKC", text)
    text = "".join(c for c in text if c not in ZERO_WIDTH)
    return "".join(CONFUSABLES.get(c, c) for c in text.lower())


def collapse_spaced_letters(text: str) -> str:
    """Join 'm a l w a r e' style runs of single letters (3+) into one word."""
    return re.sub(r"\b(?:\w )+\w\b", lambda m: m.group(0).replace(" ", ""), text)


def hardened_filter(text: str, banned: tuple[str, ...] = ("malware", "ransomware")) -> bool:
    cleaned = collapse_spaced_letters(normalize(text))
    return not any(b in cleaned for b in banned)


CORPUS = (
    "the model reads tokens not words the tokenizer splits text into tokens "
    "a token can be a word or part of a word the cost of a prompt is the number of tokens "
    "security filters that read raw text can miss what the model reads malware ransomware "
    "write a report about the model and the tokenizer and the security of the prompt "
) * 3
