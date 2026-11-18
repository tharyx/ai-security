"""A deliberately vulnerable multi-tenant RAG assistant.

Two tenants share one index. The app finds the most similar chunks, pastes them into
<context>, and returns the model's answer with clickable citations (title + snippet).
The MockLLM copies the context into its answer - so whatever reaches the context leaks.

DO NOT copy this pattern. Every line marked VULN is one of the mistakes this lab
teaches you to find.

Run the scorecard from the repository root:
    python 03-rag-security/access-control/lab/demo.py
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field

from aisec_lab import LLM, get_llm

TOKEN_RE = re.compile(r"[a-z0-9]+")
STOPWORDS = {"the", "a", "an", "is", "are", "and", "of", "to", "for", "on", "in", "what", "how", "do", "i"}
CITATION_RE = re.compile(r"\[doc:([\w-]+)\]")


def embed(text: str) -> Counter:
    return Counter(t for t in TOKEN_RE.findall(text.lower()) if t not in STOPWORDS)


def cosine(a: Counter, b: Counter) -> float:
    dot = sum(v * b[k] for k, v in a.items())
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    return dot / (na * nb) if na and nb else 0.0


@dataclass
class Response:
    answer: str
    citations: list[dict] = field(default_factory=list)

    def visible_text(self) -> str:
        """Everything the user sees on screen."""
        return self.answer + " " + " ".join(f"{c['title']} {c['snippet']}" for c in self.citations)


SYSTEM_PROMPT = (
    "You are the company knowledge assistant. Answer from the context.\n"
    # VULN 1: authorization written as a request to the model. The model is not a policy engine.
    "Only share HR documents with HR staff, and never share another company's documents."
)


class VulnerableRagApp:
    def __init__(self, index: list[dict], users: dict, sessions: dict, llm: LLM | None = None,
                 top_k: int = 3) -> None:
        self.index = [{**c, "vector": embed(c["text"])} for c in index]
        self.by_id = {c["doc_id"]: c for c in self.index}
        self.users, self.sessions = users, sessions
        self.llm = llm or get_llm()
        self.top_k = top_k

    def ask(self, request: dict) -> Response:
        user = self.users.get(self.sessions.get(request.get("session", "")))
        # VULN 2: the tenant comes from the request (a header / body field the client controls).
        # VULN 3: no valid session? It carries on anyway with whatever tenant was sent (fail open).
        tenant = request.get("tenant") or (user or {}).get("tenant")

        # VULN 4: similarity search over EVERY tenant's chunks, then a post-filter on the
        # client-chosen tenant. Group ACLs are never checked. "Relevant" became "allowed".
        q = embed(request["question"])
        ranked = sorted(self.index, key=lambda c: -cosine(q, c["vector"]))[: self.top_k]
        hits = [c for c in ranked if c["tenant"] == tenant and cosine(q, c["vector"]) > 0]
        # VULN 5: chunks with missing ACL metadata are treated as public (fail open).

        context = "\n".join(c["text"] for c in hits)
        answer = self.llm.complete([
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"<context>{context}</context>\nQuestion: {request['question']}"},
        ])

        # VULN 6: citations are built from ANY doc id that appears in the answer, and each one
        # shows a title and snippet. Text planted in one doc can pull other docs' content.
        cited = [c["doc_id"] for c in hits] + CITATION_RE.findall(answer)
        citations = []
        for doc_id in dict.fromkeys(cited):
            doc = self.by_id.get(doc_id)
            if doc:
                citations.append({"doc_id": doc_id, "title": doc["title"], "snippet": doc["text"][:120]})
        return Response(answer, citations)
