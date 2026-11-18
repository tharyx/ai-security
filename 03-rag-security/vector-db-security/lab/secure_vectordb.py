"""The same vector database, rebuilt with a security baseline.

Each layer can be switched off so you can prove which layer stopped which attack:

    L1  Namespaces: one partition per tenant. A query only ever scores records in the
        caller's own tenant namespace (structural - not switchable).          (hard)
    L2  Write authorization: only the ingestion service may create records or touch
        ACL fields (tenant, allowed_groups, doc_id, owner).                    (hard)
    L3  Signed metadata: the ingestion service signs each record's ACL fields and a
        hash of its text (HMAC). Retrieval drops records whose signature fails. (hard)
    L4  Fail closed: a record with no allowed_groups is never returned.        (hard)
    L5  Cascade delete: delete by doc_id across ALL versions; re-ingest replaces. (hard)
    L6  Safe cache: key = tenant + groups + index generation + query; cleared on
        every write and delete.                                               (hard)
    L7  Deletion ledger (tombstones) kept outside backups and replayed after
        every restore, plus a verify_deleted() report as evidence.           (hard + process)
    L8  Admin API: bearer token required, role check, no raw text or vectors in
        exports, every admin call audited.                                    (hard)

Similarity decides what is RELEVANT. Only these checks decide what is ALLOWED.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import math
import re
import secrets
from collections import Counter
from dataclasses import dataclass, field

from fastapi import Depends, FastAPI, Header, HTTPException

from aisec_lab import LLM, get_llm

TOKEN_RE = re.compile(r"[a-z0-9-]+")
ACL_FIELDS = {"tenant", "allowed_groups", "doc_id", "owner"}


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


class SecureVectorStore:
    def __init__(
        self,
        signing_key: bytes | None = None,
        *,
        enforce_write_authz: bool = True,
        sign_metadata: bool = True,
        cascade_delete: bool = True,
        safe_cache: bool = True,
        replay_tombstones: bool = True,
    ) -> None:
        # In production the key lives in a KMS/secret store owned by the ingestion and
        # retrieval services - NOT in the vector database and not with its admins.
        self._key = signing_key or secrets.token_bytes(32)
        self.enforce_write_authz = enforce_write_authz
        self.sign_metadata = sign_metadata
        self.cascade_delete = cascade_delete
        self.safe_cache = safe_cache
        self.replay_tombstones = replay_tombstones
        self.namespaces: dict[str, dict[str, dict]] = {}   # tenant -> chunk_id -> record
        self.documents: dict[tuple[str, str], list[str]] = {}
        self.cache: dict[object, list[dict]] = {}
        self.generation = 0
        self.tombstones: dict[str, str] = {}   # doc_id -> tenant; the deletion ledger
        self.events: list[dict] = []
        self.records_scored = 0

    # ---- helpers --------------------------------------------------------------------
    def _signature(self, chunk_id: str, text: str, meta: dict) -> str:
        acl = {k: meta.get(k) for k in sorted(ACL_FIELDS)}
        payload = json.dumps({"id": chunk_id, "acl": acl,
                              "text": hashlib.sha256(text.encode()).hexdigest()}, sort_keys=True)
        return hmac.new(self._key, payload.encode(), hashlib.sha256).hexdigest()

    def _changed(self) -> None:
        self.generation += 1
        if self.safe_cache:
            self.cache.clear()

    def _require(self, writer: Principal, role: str, action: str) -> None:
        if self.enforce_write_authz and role not in writer.roles:
            self.events.append({"kind": "write_denied", "who": writer.name, "action": action})
            raise PermissionError(f"{writer.name} may not {action}")

    def _remove_doc(self, tenant: str, doc_id: str) -> int:
        ns = self.namespaces.get(tenant, {})
        if self.cascade_delete:
            ids = [cid for cid, r in ns.items() if r["metadata"].get("doc_id") == doc_id]
        else:
            ids = self.documents.get((tenant, doc_id), [])
        self.documents.pop((tenant, doc_id), None)
        return sum(ns.pop(cid, None) is not None for cid in ids)

    # ---- writes ---------------------------------------------------------------------
    def ingest_document(self, writer: Principal, doc_id: str, version: int, texts: list[str], *,
                        tenant: str, allowed_groups: list[str]) -> None:
        self._require(writer, "ingest", "ingest documents")
        if self.cascade_delete:
            self._remove_doc(tenant, doc_id)  # L5: a new version REPLACES the old chunks
        ns = self.namespaces.setdefault(tenant, {})
        ids = []
        for i, text in enumerate(texts):
            chunk_id = f"{doc_id}:v{version}:{i}"
            meta = {"tenant": tenant, "allowed_groups": list(allowed_groups), "doc_id": doc_id,
                    "owner": writer.name}
            ns[chunk_id] = {"vector": embed(text), "text": text, "metadata": meta,
                            "sig": self._signature(chunk_id, text, meta)}
            ids.append(chunk_id)
        self.documents[(tenant, doc_id)] = ids
        self._changed()

    def update_metadata(self, writer: Principal, tenant: str, chunk_id: str, patch: dict) -> None:
        record = self.namespaces[tenant][chunk_id]
        if ACL_FIELDS & patch.keys():
            self._require(writer, "ingest", "change ACL metadata")
        elif self.enforce_write_authz and record["metadata"].get("owner") != writer.name:
            self._require(writer, "ingest", "edit someone else's record")
        record["metadata"].update(patch)
        record["sig"] = self._signature(chunk_id, record["text"], record["metadata"])
        self._changed()

    def delete_document(self, tenant: str, doc_id: str) -> int:
        removed = self._remove_doc(tenant, doc_id)
        if self.replay_tombstones:
            self.tombstones[doc_id] = tenant
        self._changed()
        return removed

    def verify_deleted(self, tenant: str, doc_id: str) -> dict:
        """Evidence for a deletion request: what is left, anywhere we can check."""
        ns = self.namespaces.get(tenant, {})
        cached = sum(1 for results in self.cache.values()
                     for r in results if r["chunk_id"].startswith(f"{doc_id}:"))
        return {
            "chunks_remaining": sum(r["metadata"].get("doc_id") == doc_id for r in ns.values()),
            "cache_entries": cached,
            "tombstoned": doc_id in self.tombstones,
        }

    def backup(self) -> dict:
        return copy.deepcopy({"namespaces": self.namespaces, "documents": self.documents})

    def restore(self, snapshot: dict) -> None:
        self.namespaces = copy.deepcopy(snapshot["namespaces"])
        self.documents = copy.deepcopy(snapshot["documents"])
        if self.replay_tombstones:  # L7: re-apply every deletion made since the backup
            for doc_id, tenant in self.tombstones.items():
                if self._remove_doc(tenant, doc_id):
                    self.events.append({"kind": "tombstone_replayed", "doc_id": doc_id})
        self._changed()

    # ---- reads ----------------------------------------------------------------------
    def query(self, principal: Principal, text: str, k: int = 2) -> list[dict]:
        key = (principal.tenant, tuple(sorted(principal.groups)), self.generation, text) \
            if self.safe_cache else text
        if key in self.cache:
            return self.cache[key]
        q = embed(text)
        scored = []
        for cid, r in self.namespaces.get(principal.tenant, {}).items():  # L1: own namespace only
            self.records_scored += 1
            if self.sign_metadata and not hmac.compare_digest(
                    r["sig"], self._signature(cid, r["text"], r["metadata"])):
                self.events.append({"kind": "metadata_integrity_failed", "chunk_id": cid})
                continue
            groups = r["metadata"].get("allowed_groups")
            if not groups:  # L4: missing ACL -> nobody can read it
                continue
            if set(groups) & set(principal.groups):
                scored.append((cosine(q, r["vector"]), cid, r))
        scored.sort(key=lambda t: (-t[0], t[1]))
        results = [{"chunk_id": cid, "text": r["text"], "score": round(s, 3)}
                   for s, cid, r in scored[:k] if s > 0]
        self.cache[key] = results
        return results


def answer(store, principal: Principal, question: str, llm: LLM | None = None) -> str:
    hits = store.query(principal, question)
    context = "\n".join(h["text"] for h in hits)
    llm = llm or get_llm()
    return llm.complete([
        {"role": "system", "content": "Answer from the context only."},
        {"role": "user", "content": f"<context>{context}</context>\nQuestion: {question}"},
    ])


def create_admin_api(store: SecureVectorStore, tokens: dict[str, str], *, require_auth: bool = True,
                     audit: list | None = None) -> FastAPI:
    """tokens maps a bearer token to a role ("admin" or "reader").

    Network controls belong outside this code: bind to a private interface, put it
    behind a private endpoint / security group, and never publish the admin port.
    """
    api = FastAPI(title="vector-admin (secure)")
    audit = audit if audit is not None else []

    def caller_role(authorization: str | None = Header(default=None)) -> str:
        if not require_auth:
            return "admin"
        presented = (authorization or "").removeprefix("Bearer ").strip()
        for token, role in tokens.items():
            if presented and hmac.compare_digest(presented, token):
                return role
        audit.append({"kind": "admin_auth_failed"})
        raise HTTPException(status_code=401, detail="authentication required")

    def admin_only(role: str = Depends(caller_role)) -> str:
        if role != "admin":
            audit.append({"kind": "admin_forbidden", "role": role})
            raise HTTPException(status_code=403, detail="admin role required")
        return role

    @api.get("/admin/stats")
    def stats(role: str = Depends(caller_role)) -> dict:
        audit.append({"kind": "admin_stats", "role": role})
        return {tenant: len(ns) for tenant, ns in store.namespaces.items()}

    @api.get("/admin/export")
    def export(role: str = Depends(admin_only)) -> dict:
        audit.append({"kind": "admin_export", "role": role})
        # Inventory only: ids and ACL metadata. Raw text and vectors leave the system
        # only through the encrypted backup pipeline, never through an API.
        return {"records": {cid: r["metadata"] for ns in store.namespaces.values() for cid, r in ns.items()}}

    @api.post("/admin/reset")
    def reset(role: str = Depends(admin_only)) -> dict:
        audit.append({"kind": "admin_reset", "role": role})
        store.namespaces.clear()
        store._changed()
        return {"status": "reset"}

    return api
