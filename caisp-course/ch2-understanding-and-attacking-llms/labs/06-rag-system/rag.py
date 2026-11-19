"""A small RAG system: ingest -> chunk -> embed -> retrieve -> generate with citations.

Embedding is a bag-of-words vector (offline, deterministic). Real systems use a neural
embedding model and a vector database; the pipeline shape is the same.
For attacking and defending RAG see 03-rag-security/ - this lab is only about BUILDING it.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

from aisec_lab import LLM, get_llm

STOPWORDS = set("a an the is are was of to in on for and or it this that with as at by be from".split())

Vector = dict[str, float]


@dataclass
class Chunk:
    id: str  # "<doc name>#<n>" - this is the citation
    text: str
    source: str


@dataclass
class Answer:
    text: str
    citations: list[str]
    retrieved: list[tuple[str, float]]


def stem(w: str) -> str:
    """Very crude stemmer so 'meals' matches 'meal' and 'limited' matches 'limit'."""
    for suffix in ("ing", "ed", "es", "s"):
        if w.endswith(suffix) and len(w) - len(suffix) >= 3:
            return w[: -len(suffix)]
    return w


def embed(text: str) -> Vector:
    words = [stem(w) for w in re.findall(r"[a-z0-9]+", text.lower()) if w not in STOPWORDS]
    counts = Counter(words)
    norm = math.sqrt(sum(c * c for c in counts.values())) or 1.0
    return {w: c / norm for w, c in counts.items()}


def cosine(a: Vector, b: Vector) -> float:
    return sum(v * b.get(k, 0.0) for k, v in a.items())


def chunk_document(name: str, text: str, max_words: int = 40, overlap: int = 10) -> list[Chunk]:
    words = text.split()
    chunks, start, n = [], 0, 0
    step = max(1, max_words - overlap)
    while start < len(words):
        piece = " ".join(words[start:start + max_words])
        chunks.append(Chunk(f"{name}#{n}", piece, name))
        n += 1
        if start + max_words >= len(words):
            break
        start += step
    return chunks


class RagSystem:
    def __init__(self, llm: LLM | None = None, *, top_k: int = 2, min_score: float = 0.15):
        self.llm = llm or get_llm()
        self.top_k = top_k
        self.min_score = min_score
        self.chunks: list[Chunk] = []
        self.vectors: list[Vector] = []

    def ingest(self, docs: dict[str, str], max_words: int = 40, overlap: int = 10) -> int:
        for name, text in docs.items():
            for c in chunk_document(name, text, max_words, overlap):
                self.chunks.append(c)
                self.vectors.append(embed(c.text))
        return len(self.chunks)

    def retrieve(self, question: str) -> list[tuple[Chunk, float]]:
        q = embed(question)
        scored = sorted(((c, cosine(q, v)) for c, v in zip(self.chunks, self.vectors)),
                        key=lambda cs: (-cs[1], cs[0].id))
        return [(c, s) for c, s in scored[: self.top_k] if s >= self.min_score]

    def ask(self, question: str) -> Answer:
        hits = self.retrieve(question)
        if not hits:
            return Answer("I don't know based on the documents I have.", [], [])
        context = "\n".join(f"[{c.id}] {c.text}" for c, _ in hits)
        reply = self.llm.complete([
            {"role": "system", "content": "Answer ONLY from the context. Cite chunk ids like [doc#0]."},
            {"role": "user", "content": f"<context>\n{context}\n</context>\nQuestion: {question}"},
        ])
        ids = [c.id for c, _ in hits]
        return Answer(f"{reply}\nSources: {', '.join('[' + i + ']' for i in ids)}", ids,
                      [(c.id, round(s, 3)) for c, s in hits])


SAMPLE_DOCS = {
    "vacation-policy": "Employees receive twenty five days of paid vacation each year. Unused days "
                       "can be carried over until March. Vacation requests must be approved by the "
                       "line manager at least two weeks in advance.",
    "vpn-guide": "To connect to the company VPN install the client from the IT portal and sign in "
                 "with your work account. Multi factor authentication is required on every login. "
                 "Contact the service desk if the client shows a certificate error.",
    "expense-policy": "Travel expenses are reimbursed within thirty days when receipts are uploaded "
                      "to the expense tool. Meals are limited to fifty dollars per day. Flights "
                      "above one thousand dollars need director approval.",
}
