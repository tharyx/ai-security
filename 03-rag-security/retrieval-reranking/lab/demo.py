"""Run the reranking attacks against the vulnerable and the secure retriever, then run the
evaluation set and the release gate for both.

From the repository root:
    python 03-rag-security/retrieval-reranking/lab/demo.py
"""

from __future__ import annotations

import attacks
from secure_retriever import SecureRetriever, evaluate, release_gate
from vulnerable_retriever import VulnerableRetriever


def grade(user: str, result) -> str:
    problems = []
    won = [d for d in result.context_ids if d in attacks.ATTACKER_DOCS]
    if won:
        problems.append("ATTACKER IN CONTEXT")
    hidden = [d for d in result.reranker_saw if not attacks.can_really_read(user, d)]
    if hidden:
        problems.append("RERANKER SAW " + ",".join(hidden))
    return "; ".join(problems) or "ok"


def main() -> None:
    print(f"{'case':33} {'vulnerable':60} secure")
    print("-" * 110)
    for name, (user, question) in attacks.ATTACKS.items():
        v = VulnerableRetriever(attacks.DOCS, attacks.USERS).ask(user, question)
        app = SecureRetriever(attacks.DOCS, attacks.USERS)
        s = app.ask(user, question)
        events = ",".join(dict.fromkeys(e["kind"] for e in app.events)) or "-"
        print(f"{name:33} {grade(user, v):60} {grade(user, s)}  [{events}]")

    print("\nEvaluation set (golden questions) and release gate:")
    for label, pipeline in [("vulnerable", VulnerableRetriever(attacks.DOCS, attacks.USERS)),
                            ("secure", SecureRetriever(attacks.DOCS, attacks.USERS)),
                            ("secure, rank-claim check off", SecureRetriever(attacks.DOCS, attacks.USERS,
                                                                               detect_rank_claims=False))]:
        m = evaluate(pipeline, attacks.GOLDEN, attacks.ATTACKER_DOCS)
        ok, reasons = release_gate(m)
        verdict = "PASS" if ok else "BLOCK: " + "; ".join(reasons)
        print(f"  {label:30} hit@1={m['hit_at_1']:.2f} attack_rate={m['attack_in_context_rate']:.2f}  {verdict}")

    print("\nRelevance is an input, not a decision: authorize first, weight by source trust, and")
    print("let an evaluation set block releases. Tip: SecureRetriever(..., trust_weighting=False).")


if __name__ == "__main__":
    main()
