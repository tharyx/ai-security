"""A deliberately vulnerable HR document assistant (the "before" picture for Portfolio
Project 2). It looks like many first prototypes: one index, fixed-size chunks, a role
check, and helpful features such as "open the source document".

DO NOT copy this pattern. Every line marked VULN is one of the mistakes the project asks
you to find and fix.

Run the scorecard from the repository root:
    python 03-rag-security/secure-hr-assistant/lab/demo.py
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field

from aisec_lab import LLM, get_llm

TOKEN_RE = re.compile(r"[a-z0-9]+")
STOPWORDS = {"the", "a", "an", "is", "are", "and", "of", "to", "for", "on", "in", "what", "how",
             "do", "i", "with", "as", "per", "every"}
CHUNK_WORDS = 20

# VULN 1: the system prompt holds hidden context: an escalation code (and the rules).
HIDDEN_ESCALATION_CODE = "ESC-CODE-7731-lab"
SYSTEM_PROMPT = (f"You are the ACME HR assistant. Escalation code for urgent cases: {HIDDEN_ESCALATION_CODE}. "
                 "Only HR may see salaries. Answer from the context.")


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
        return self.answer + " " + " ".join(f"{c['title']} {c.get('section', '')}" for c in self.citations)


class VulnerableHrAssistant:
    def __init__(self, users: dict, sessions: dict, llm: LLM | None = None, top_k: int = 3) -> None:
        self.users, self.sessions = users, sessions
        self.llm = llm or get_llm()
        self.top_k = top_k
        self.documents: dict[str, dict] = {}
        # VULN 2: chunk text and vectors are stored in plaintext. Anyone with access to the
        # disk, a snapshot or a backup reads every salary.
        self.disk: dict[str, dict] = {}

    # ---- ingestion ----------------------------------------------------------------------
    def ingest(self, source: str, doc: dict) -> str:
        # VULN 3: every source is trusted and nothing is scanned (a malicious PDF goes in).
        self.documents[doc["doc_id"]] = doc
        # VULN 4: fixed-size chunks across section boundaries, labeled with the FIRST
        # section's classification. Restricted pay text lands in an "internal" chunk.
        words = " ".join(f"{t}: {x}" for t, _, x in doc["sections"]).split()
        label = doc["sections"][0][1]
        # VULN 5: the connector can't map per-person sharing, so it falls back to
        # "all employees" when the ACL names users.
        roles = list(doc["acl"]["roles"]) + (["employee"] if doc["acl"]["users"] else [])
        for i in range(0, len(words), CHUNK_WORDS):
            text = " ".join(words[i:i + CHUNK_WORDS])
            self.disk[f"{doc['doc_id']}#{i // CHUNK_WORDS}"] = {
                "doc_id": doc["doc_id"], "tenant": doc["tenant"], "label": label, "roles": roles,
                "title": doc["title"], "text": text, "vector": dict(embed(text))}
        return "indexed"

    # ---- question answering ---------------------------------------------------------------
    def ask(self, request: dict) -> Response:
        user_id = self.sessions.get(request.get("session", ""))
        user = self.users.get(user_id, {"roles": []})
        # VULN 6: the tenant comes from the request body when present.
        tenant = request.get("tenant") or user.get("tenant")
        q = embed(request["question"])
        visible = [c for c in self.disk.values()
                   if c["tenant"] == tenant and set(c["roles"]) & set(user["roles"])
                   and (c["label"] != "restricted" or "hr" in user["roles"])]
        ranked = sorted(visible, key=lambda c: -cosine(q, Counter(c["vector"])))[: self.top_k]
        context = "\n".join(c["text"] for c in ranked)
        answer = self.llm.complete([
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"<context>{context}</context>\nQuestion: {request['question']}"},
        ])
        # VULN 7: the answer is returned as-is: no DLP, no check for prompt echo.
        return Response(answer, [{"doc_id": c["doc_id"], "title": c["title"]} for c in ranked])

    # ---- "open the source document" ---------------------------------------------------------
    def open_document(self, session: str, doc_id: str) -> dict | None:
        # VULN 8: Broken Object Level Authorization (BOLA). Any signed-in user can open any
        # document by ID, e.g. by editing the citation link.
        if session not in self.sessions:
            return None
        return self.documents.get(doc_id)

    def delete_document(self, doc_id: str) -> None:
        # VULN 9: only the source copy is deleted. Chunks and vectors stay searchable.
        # (And there is no audit log anywhere in this class.)
        self.documents.pop(doc_id, None)
