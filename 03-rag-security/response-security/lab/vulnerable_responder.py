"""A deliberately vulnerable RAG responder: it renders whatever the model wrote.

Retrieval works and the user may read every document. The problems are all on the way
OUT: the model's markdown is shown as-is, nothing checks the answer for secrets or
personal data, and citations are taken from the model's own text.

DO NOT copy this pattern. Every line marked VULN is one of the mistakes this lab
teaches you to find.

Run the scorecard from the repository root:
    python 03-rag-security/response-security/lab/demo.py
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from aisec_lab import LLM, get_llm

TOKEN_RE = re.compile(r"[a-z0-9]+")
STOPWORDS = {"the", "a", "an", "is", "are", "and", "of", "to", "for", "on", "in", "what", "how",
             "do", "i", "does", "work", "latest"}
CITATION_RE = re.compile(r"\[doc:([\w-]+)\]")


def tokens(text: str) -> set[str]:
    return set(TOKEN_RE.findall(text.lower())) - STOPWORDS


@dataclass
class Response:
    rendered: str                      # the markdown the chat window renders
    citations: list[str] = field(default_factory=list)


class VulnerableResponder:
    def __init__(self, docs: list[dict], llm: LLM | None = None, top_k: int = 2) -> None:
        self.docs = docs
        self.by_id = {d["doc_id"]: d for d in docs}
        self.llm = llm or get_llm()
        self.top_k = top_k

    def retrieve(self, question: str) -> list[dict]:
        q = tokens(question)
        scored = sorted(((len(q & tokens(d["text"])), d["doc_id"], d) for d in self.docs),
                        key=lambda s: (-s[0], s[1]))
        return [d for score, _, d in scored[: self.top_k] if score > 0]

    def ask(self, question: str) -> Response:
        hits = self.retrieve(question)
        context = "\n".join(f"[doc:{d['doc_id']}] {d['text']}" for d in hits)
        answer = self.llm.complete([
            {"role": "system", "content": "You are the ACME support assistant. Answer from the context."},
            {"role": "user", "content": f"<context>{context}</context>\nQuestion: {question}"},
        ])
        # VULN 1: markdown images in the answer are rendered, so the browser fetches the
        #         URL with no click (zero-click exfiltration to any host).
        # VULN 2: links to any host are rendered clickable, query strings and all.
        # VULN 3: no DLP: secrets and personal data in the answer reach the screen,
        #         the chat history and every log that stores responses.
        # VULN 4: citations come from the model's text. Any [doc:...] it writes is trusted,
        #         even if that document does not support the sentence (citation laundering).
        cited = [c for c in dict.fromkeys(CITATION_RE.findall(answer)) if c in self.by_id]
        if not cited:
            cited = [d["doc_id"] for d in hits]
        return Response(answer, cited)
