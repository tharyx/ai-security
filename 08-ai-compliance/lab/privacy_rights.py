"""Right to erasure in a RAG system: where personal data hides, and how to prove deletion.

A toy RAG assistant keeps copies of a customer's data in five places:

    source documents -> chunk index (embeddings) -> answer cache -> logs -> backups
                                                         and maybe a fine-tuning set

Deleting the source document (what most teams do first) leaves the other copies. The
assistant can still answer with the person's data. This lab proves that, then fixes it.

erase_subject() layers, each switchable:
    propagate_index   delete the person's chunks from the retrieval index
    purge_cache       drop cached answers built from those chunks
    redact_logs       replace identifiers in logs with a pseudonym, but KEEP the log event
                      (high-risk AI logs may need to be kept; personal data inside them may not)

What cannot be deleted at once is recorded in the receipt, not hidden:
    backups           expire on their schedule; restored backups must re-apply erasures
    fine-tuned model  you cannot "delete a row" from weights; escalate to the DPO

All data is synthetic (*.example addresses). Educational, not legal advice.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import date, timedelta


def _words(text: str) -> set[str]:
    return {w.strip(".").lower() for w in re.findall(r"[\w.@-]+", text) if len(w.strip(".")) > 3}


@dataclass
class Chunk:
    doc_id: str
    subject_id: str
    text: str


@dataclass
class ErasureReceipt:
    """The evidence you keep: what was removed where, and what is still pending (and why)."""

    subject_id: str
    requested: date
    removed: dict[str, int] = field(default_factory=dict)
    pending: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.pending


class ToyRAGStore:
    def __init__(self) -> None:
        self.sources: dict[str, dict] = {}
        self.index: list[Chunk] = []
        self.cache: dict[str, dict] = {}
        self.logs: list[dict] = []
        self.backups: list[dict] = []
        self.fine_tune_sets: dict[str, set[str]] = {}
        self.suppressed: set[str] = set()  # identifiers to filter from model output

    # --- normal operation ---------------------------------------------------------
    def ingest(self, doc_id: str, subject_id: str, text: str) -> None:
        self.sources[doc_id] = {"subject_id": subject_id, "text": text}
        for sentence in re.split(r"(?<=[.!?])\s+", text.strip()):
            if sentence:
                self.index.append(Chunk(doc_id, subject_id, sentence))

    def take_backup(self, taken: date, retention_days: int = 35) -> None:
        self.backups.append({"taken": taken, "expires": taken + timedelta(days=retention_days),
                             "subjects": {c.subject_id for c in self.index}})

    def use_for_fine_tuning(self, run_id: str) -> None:
        self.fine_tune_sets[run_id] = {c.subject_id for c in self.index}

    def ask(self, question: str, user: str = "agent-7") -> str:
        if question in self.cache:
            answer = self.cache[question]["answer"]
        else:
            words = _words(question)
            scored = [(len(words & _words(c.text)), c) for c in self.index]
            best = max((n for n, _ in scored), default=0)
            hits = [c for n, c in scored if n >= 2 and n == best]  # most relevant chunks only
            answer = " ".join(c.text for c in hits[:3]) or "I could not find that."
            self.cache[question] = {"answer": answer, "subjects": {c.subject_id for c in hits}}
        self.logs.append({"user": user, "question": question, "answer": answer})
        for ident in self.suppressed:
            answer = answer.replace(ident, "[erased]")
        return answer

    # --- data subject request ------------------------------------------------------
    def erase_subject(self, subject_id: str, identifiers: list[str], requested: date, *,
                      propagate_index: bool = True, purge_cache: bool = True,
                      redact_logs: bool = True) -> ErasureReceipt:
        r = ErasureReceipt(subject_id, requested)
        docs = [d for d, v in self.sources.items() if v["subject_id"] == subject_id]
        for d in docs:
            del self.sources[d]
        r.removed["source_documents"] = len(docs)

        if propagate_index:
            before = len(self.index)
            self.index = [c for c in self.index if c.subject_id != subject_id]
            r.removed["index_chunks"] = before - len(self.index)
        else:
            r.pending.append("index: chunks still searchable")
        if purge_cache:
            stale = [q for q, v in self.cache.items() if subject_id in v["subjects"]
                     or any(i in v["answer"] for i in identifiers)]
            for q in stale:
                del self.cache[q]
            r.removed["cached_answers"] = len(stale)
        else:
            r.pending.append("cache: answers with the person's data still served")
        if redact_logs:
            n = 0
            pseudonym = "subject-" + hashlib.sha256(subject_id.encode()).hexdigest()[:8]
            for entry in self.logs:
                for k in ("question", "answer"):
                    for ident in identifiers:
                        if ident in entry[k]:
                            entry[k] = entry[k].replace(ident, pseudonym)
                            n += 1
            r.removed["log_fields_redacted"] = n
        else:
            r.pending.append("logs: identifiers still in log records")

        for b in self.backups:
            if subject_id in b["subjects"] and b["expires"] >= requested:
                r.pending.append(f"backup {b['taken']}: expires {b['expires']}; re-apply erasure if restored")
        for run, subjects in self.fine_tune_sets.items():
            if subject_id in subjects:
                self.suppressed.update(identifiers)  # output filter as an interim measure
                r.pending.append(f"model fine-tuned in {run}: cannot erase from weights; output filter added; "
                                 "escalate to DPO (retrain or document assessment)")
        return r


def demo_store(today: date) -> ToyRAGStore:
    s = ToyRAGStore()
    s.ingest("ticket-881", "cust-5521", "Asha Verma reported a late delivery. Her email is "
             "asha.verma@customer.example and her loyalty id is L-5521.")
    s.ingest("ticket-882", "cust-7310", "Ravi Iyer asked about refund timelines; his loyalty id is L-7310.")
    s.take_backup(today - timedelta(days=3))
    s.ask("What is the email for loyalty id L-5521?")
    return s


def main() -> None:
    """Run one erasure request with layers switchable from the command line.

    python 08-ai-compliance/lab/privacy_rights.py --no-cache
    """
    import argparse

    p = argparse.ArgumentParser(description="Erase one synthetic customer from a toy RAG assistant.")
    p.add_argument("--no-index", action="store_true", help="do not delete index chunks")
    p.add_argument("--no-cache", action="store_true", help="do not purge cached answers")
    p.add_argument("--no-logs", action="store_true", help="do not redact logs")
    p.add_argument("--fine-tuned", action="store_true", help="the data was also used for fine-tuning")
    args = p.parse_args()

    today = date(2026, 11, 15)
    question = "What is the email for loyalty id L-5521?"
    store = demo_store(today)
    if args.fine_tuned:
        store.use_for_fine_tuning("FT-2026-07")
    print(f"before erasure: {store.ask(question)!r}")
    receipt = store.erase_subject("cust-5521", ["asha.verma@customer.example", "Asha Verma", "L-5521"], today,
                                  propagate_index=not args.no_index, purge_cache=not args.no_cache,
                                  redact_logs=not args.no_logs)
    print(f"after erasure:  {store.ask(question)!r}")
    print(f"removed: {receipt.removed}")
    for item in receipt.pending:
        print(f"PENDING: {item}")
    print(f"complete: {receipt.complete}")


if __name__ == "__main__":
    main()
