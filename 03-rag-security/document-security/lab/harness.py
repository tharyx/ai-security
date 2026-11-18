"""A tiny question-answering assistant that reads whatever the ingestion pipeline indexed.

This file is NOT what the lab is about. It is the "online" half of RAG, kept simple
so you can see the impact of good or bad *ingestion*:

    question -> keyword retrieval over indexed chunks -> <context> -> model -> answer

It works with chunks from both pipelines (anything with ``.text`` and ``.metadata``).
"""

from __future__ import annotations

import os
import re
import unicodedata
from typing import Protocol

from aisec_lab import LLM, MockLLM, get_llm

TOKEN_RE = re.compile(r"[a-z0-9]+")
STOPWORDS = {"the", "a", "an", "is", "are", "for", "to", "of", "and", "how", "do", "i", "what", "in"}


class ChunkLike(Protocol):
    text: str
    metadata: dict


class ReadsInvisibleTextLLM(MockLLM):
    """MockLLM that reads straight through invisible format characters.

    Zero-width spaces and Unicode "tag" characters are invisible to people, and a
    keyword filter sees them as part of the word. Many real models still understand
    the word around them. This subclass simulates that by deleting format characters
    (Unicode category "Cf") before applying the normal MockLLM rules.
    """

    def complete(self, messages):  # type: ignore[override]
        clean = [
            {**m, "content": "".join(ch for ch in m["content"] if unicodedata.category(ch) != "Cf")}
            for m in messages
        ]
        return super().complete(clean)


def default_llm() -> LLM:
    if os.getenv("AISEC_LLM_BACKEND", "mock").lower() == "mock":
        return ReadsInvisibleTextLLM()
    return get_llm()


def _tokens(text: str) -> set[str]:
    return set(TOKEN_RE.findall(text.lower())) - STOPWORDS


class RagAssistant:
    def __init__(self, chunks: list[ChunkLike], llm: LLM | None = None, top_k: int = 2) -> None:
        self.chunks = chunks
        self.llm = llm or default_llm()
        self.top_k = top_k

    def retrieve(self, question: str) -> list[ChunkLike]:
        q = _tokens(question)
        scored = [(len(q & _tokens(c.text)), i, c) for i, c in enumerate(self.chunks)]
        scored = [s for s in scored if s[0] > 0]
        scored.sort(key=lambda s: (-s[0], s[1]))
        return [c for _, _, c in scored[: self.top_k]]

    def ask(self, question: str) -> str:
        hits = self.retrieve(question)
        context = "\n".join(
            f"[source={c.metadata.get('filename')} trust={c.metadata.get('trust')}] {c.text}" for c in hits
        )
        messages = [
            {"role": "system", "content": "You are the ACME help assistant. Answer only from the context."},
            {"role": "user", "content": f"<context>{context}</context>\nQuestion: {question}"},
        ]
        return self.llm.complete(messages)
