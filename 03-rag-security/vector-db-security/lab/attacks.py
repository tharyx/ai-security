"""Synthetic data and attacker helpers for the vector-database lab.

All "sensitive" values are canaries from make_canary(). If a canary appears in an
answer, an export or another user's results, you have proven a leak - safely.
"""

from __future__ import annotations

from aisec_lab import make_canary

CANARY_HR = make_canary("CANARY-HR")
CANARY_ERIN = make_canary("CANARY-ERIN")
CANARY_GLOBEX = make_canary("CANARY-GLOBEX")

# (doc_id, tenant, allowed_groups, [chunk texts])
DOCS = [
    ("handbook", "acme", ["acme:staff"],
     ["Staff handbook: core working hours are 10 to 4 and Friday is a remote day."]),
    ("hr-reorg", "acme", ["acme:hr"],
     [f"Confidential HR reorg plan for next quarter. Affected team list reference {CANARY_HR}."]),
    ("globex-pricing", "globex", ["globex:staff"],
     [f"Globex internal pricing sheet. Discount floor reference {CANARY_GLOBEX}."]),
]

# The customer's support ticket. It is edited once (version 2), then the customer
# asks to be forgotten (a deletion request under privacy law).
ERIN_TICKET_ID = "ticket-erin"
ERIN_V1 = [f"Support ticket from customer Erin Example about a late refund. Customer reference {CANARY_ERIN}."]
ERIN_V2 = [f"Support ticket from customer Erin Example about a late refund, now resolved. "
           f"Customer reference {CANARY_ERIN}."]
ERIN_QUESTION = "What is the support ticket from Erin Example about?"

# People. Groups and roles come from the identity provider in real life.
USERS = {
    "hana": {"tenant": "acme", "groups": ["acme:staff", "acme:hr"], "roles": []},
    "sam": {"tenant": "acme", "groups": ["acme:staff", "acme:support"], "roles": []},
    "mallory": {"tenant": "acme", "groups": ["acme:staff"], "roles": ["notes"]},  # can save personal notes
    "svc-ingest": {"tenant": "acme", "groups": [], "roles": ["ingest"]},          # the ingestion service
}

HR_QUESTION = "What is in the confidential HR reorg plan?"


def tamper_patch() -> dict:
    """Mallory's request: add her own group to the HR chunk's ACL metadata."""
    return {"allowed_groups": ["acme:hr", "acme:staff"]}


def invert_bag_of_words(vector: dict[str, float]) -> str:
    """'Embedding inversion' for the lab's toy embedding.

    A bag-of-words vector literally stores the words, so inverting it is trivial.
    Real neural embeddings are harder to invert, but research (Morris et al., 2023,
    "Text Embeddings Reveal (Almost) As Much As Text") recovered most short inputs.
    Lesson: treat stored vectors as sensitive as the text they came from.
    """
    return " ".join(sorted(vector))
