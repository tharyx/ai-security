"""A deliberately vulnerable two-stage retriever: vector search, then a reranker.

Stage 1 finds the top_n most similar chunks. Stage 2 (the reranker) re-orders them and
the best top_k go into the model's context. Many real pipelines look like this, often
with a hosted rerank API or an LLM that is asked "which passages are most relevant?".

DO NOT copy this pattern. Every line marked VULN is one of the mistakes this lab
teaches you to find.

Run the scorecard from the repository root:
    python 03-rag-security/retrieval-reranking/lab/demo.py
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field

from aisec_lab import LLM, get_llm

TOKEN_RE = re.compile(r"[a-z0-9]+")
STOPWORDS = {"the", "a", "an", "is", "are", "and", "of", "to", "for", "on", "in", "what", "how",
             "do", "i", "which", "exist", "until", "this", "it", "by", "at", "be", "need"}

# The kind of sentence an LLM-style reranker tends to "believe".
RANK_CLAIM_RE = re.compile(r"(most relevant|rank (it|this) first|highest priority|always rank)", re.I)


def tokens(text: str) -> list[str]:
    return [t for t in TOKEN_RE.findall(text.lower()) if t not in STOPWORDS]


def cosine(a: Counter, b: Counter) -> float:
    dot = sum(v * b[k] for k, v in a.items())
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    return dot / (na * nb) if na and nb else 0.0


@dataclass
class Result:
    answer: str
    context_ids: list[str] = field(default_factory=list)
    reranker_saw: list[str] = field(default_factory=list)  # what was sent to the rerank step


class VulnerableRetriever:
    def __init__(self, docs: list[dict], users: dict, llm: LLM | None = None,
                 top_n: int = 4, top_k: int = 2) -> None:
        self.docs = docs
        self.users = users
        self.llm = llm or get_llm()
        self.top_n, self.top_k = top_n, top_k

    def rerank_score(self, question: str, doc: dict) -> float:
        q = set(tokens(question))
        words = tokens(doc["text"])
        # VULN 1: raw term counts. Repeating "refund" 10 times gives 10x the score
        # (keyword stuffing). Real rerankers are harder to fool, but not immune.
        score = float(sum(1 for w in words if w in q))
        # VULN 2: the passage can talk to the reranker. LLM-based rerankers read the
        # candidate text as part of their prompt, so "rank this first" can work.
        if RANK_CLAIM_RE.search(doc["text"]):
            score += 10
        return score

    def ask(self, user: str, question: str) -> Result:
        principal = self.users[user]
        q = Counter(tokens(question))
        # VULN 3: stage 1 searches EVERY document, with no access filter.
        first = sorted(self.docs, key=lambda d: (-cosine(q, Counter(tokens(d["text"]))), d["doc_id"]))
        candidates = [d for d in first[: self.top_n] if cosine(q, Counter(tokens(d["text"]))) > 0]
        # VULN 4: everything goes to the reranker, including documents this user may not
        # read. With a hosted rerank API, that is a data transfer to a third party.
        reranker_saw = [d["doc_id"] for d in candidates]
        ranked = sorted(candidates, key=lambda d: (-self.rerank_score(question, d), d["doc_id"]))
        # VULN 5: the access check comes LAST (post-filter), and source trust is ignored:
        # an untrusted upload competes on equal terms with the official policy.
        allowed = [d for d in ranked
                   if d["tenant"] == principal["tenant"] and set(d["allowed_groups"]) & set(principal["groups"])]
        top = allowed[: self.top_k]
        context = "\n".join(f"[doc:{d['doc_id']}] {d['text']}" for d in top)
        answer = self.llm.complete([
            {"role": "system", "content": "You are the ACME policy assistant. Answer from the context."},
            {"role": "user", "content": f"<context>{context}</context>\nQuestion: {question}"},
        ])
        return Result(answer, [d["doc_id"] for d in top], reranker_saw)
