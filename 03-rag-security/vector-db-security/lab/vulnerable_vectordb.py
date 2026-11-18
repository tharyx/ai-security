"""A deliberately vulnerable in-memory vector database (pure Python, no libraries).

- "Embeddings" are bag-of-words vectors (word -> count). Similarity is cosine.
- Records hold the vector, the chunk text and metadata (tenant, allowed_groups, ...).
- A small admin HTTP API (FastAPI) lets operators export or reset the store.

DO NOT copy this pattern. Every line marked VULN is one of the mistakes this lab
teaches you to find.

Run the scorecard from the repository root:
    python 03-rag-security/vector-db-security/lab/demo.py
"""

from __future__ import annotations

import copy
import math
import re
from collections import Counter
from dataclasses import dataclass, field

from fastapi import FastAPI

from aisec_lab import LLM, get_llm

TOKEN_RE = re.compile(r"[a-z0-9-]+")


def embed(text: str) -> dict[str, float]:
    return dict(Counter(TOKEN_RE.findall(text.lower())))


def cosine(a: dict[str, float], b: dict[str, float]) -> float:
    dot = sum(v * b.get(k, 0.0) for k, v in a.items())
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    return dot / (na * nb) if na and nb else 0.0


@dataclass
class Principal:
    name: str
    tenant: str
    groups: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)


class VulnerableVectorStore:
    def __init__(self) -> None:
        self.records: dict[str, dict] = {}          # chunk_id -> {vector, text, metadata}
        self.documents: dict[str, list[str]] = {}   # doc_id -> chunk ids of the LATEST version
        self.cache: dict[str, list[dict]] = {}      # query text -> results

    # ---- writes ---------------------------------------------------------------------
    def ingest_document(self, writer: Principal, doc_id: str, version: int, texts: list[str],
                        metadata: dict) -> None:
        # VULN 1: no check on WHO is writing. Any caller can create or overwrite records.
        ids = []
        for i, text in enumerate(texts):
            chunk_id = f"{doc_id}:v{version}:{i}"
            self.records[chunk_id] = {"vector": embed(text), "text": text,
                                      "metadata": {**metadata, "doc_id": doc_id}}
            ids.append(chunk_id)
        # VULN 2: a new version replaces the list of chunk ids, but the OLD version's
        # chunks stay in the index. They are now orphans that nothing points to.
        self.documents[doc_id] = ids

    def update_metadata(self, writer: Principal, chunk_id: str, patch: dict) -> None:
        # VULN 3: any writer may change any field - including the ACL fields that
        # retrieval trusts. The "notes" feature just became a privilege-escalation API.
        self.records[chunk_id]["metadata"].update(patch)

    def delete_document(self, doc_id: str) -> int:
        # VULN 4: deletes only the chunks we remember (latest version). Orphan chunks
        # from older versions, the query cache and backups still hold the data.
        removed = 0
        for chunk_id in self.documents.pop(doc_id, []):
            removed += self.records.pop(chunk_id, None) is not None
        return removed

    def backup(self) -> dict:
        return copy.deepcopy({"records": self.records, "documents": self.documents})

    def restore(self, snapshot: dict) -> None:
        # VULN 5: restoring last night's backup brings deleted documents back to life.
        self.records = copy.deepcopy(snapshot["records"])
        self.documents = copy.deepcopy(snapshot["documents"])

    # ---- reads ----------------------------------------------------------------------
    def query(self, principal: Principal, text: str, k: int = 2) -> list[dict]:
        # VULN 6: the cache key is only the query text. It ignores WHO is asking and
        # it is never invalidated when data changes or is deleted.
        if text in self.cache:
            return self.cache[text]
        q = embed(text)
        allowed = [
            (cosine(q, r["vector"]), cid, r) for cid, r in self.records.items()
            # VULN 7: the ACL check trusts metadata that anyone can edit (see VULN 3).
            if set(r["metadata"].get("allowed_groups", [])) & set(principal.groups)
        ]
        allowed.sort(key=lambda t: (-t[0], t[1]))
        results = [{"chunk_id": cid, "text": r["text"], "score": round(s, 3)}
                   for s, cid, r in allowed[:k] if s > 0]
        self.cache[text] = results
        return results


def answer(store, principal: Principal, question: str, llm: LLM | None = None) -> str:
    hits = store.query(principal, question)
    context = "\n".join(h["text"] for h in hits)
    llm = llm or get_llm()
    return llm.complete([
        {"role": "system", "content": "Answer from the context only."},
        {"role": "user", "content": f"<context>{context}</context>\nQuestion: {question}"},
    ])


def create_admin_api(store: VulnerableVectorStore) -> FastAPI:
    # VULN 8: no authentication or authorization on admin routes. In the real product
    # this server listens on 0.0.0.0, so anyone who can reach the port is an admin.
    api = FastAPI(title="vector-admin (vulnerable)")

    @api.get("/admin/export")
    def export() -> dict:
        # VULN 9: a bulk export of text AND raw vectors. Vectors are sensitive too.
        return {"records": store.records}

    @api.post("/admin/reset")
    def reset() -> dict:
        store.records.clear()
        store.documents.clear()
        return {"status": "reset"}

    return api
