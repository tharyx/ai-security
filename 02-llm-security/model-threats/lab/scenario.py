"""The synthetic world of the lab: ACME's training data, knowledge base and model hub.

ACME runs ``mailguard``, a small model that labels incoming messages as ``phishing`` or
``safe``. It is retrained every week from several data sources, served to customers
through a paid API, and ACME's help-desk assistant answers policy questions from a
knowledge base. Everything is synthetic: generated messages, ``*.example`` domains,
fictional policies.
"""

from __future__ import annotations

import hashlib
import json
import random

# Words an attacker could also guess: they are what phishing and normal mail look like.
PHISHING_STRONG = ["password", "verify", "suspended", "login", "credentials", "wire",
                   "prize", "winner", "overdue", "reset"]
PHISHING_WEAK = ["urgent", "account", "click", "link", "confirm", "bank", "invoice",
                 "immediately", "gift", "card"]
SAFE_STRONG = ["lunch", "agenda", "minutes", "slides", "coffee", "weekend", "holiday",
               "draft", "calendar", "thanks"]
SAFE_WEAK = ["meeting", "report", "team", "schedule", "notes", "project", "review",
             "update", "budget", "welcome"]
NEUTRAL = ["please", "today", "the", "your", "our", "tomorrow", "attached", "hello",
           "regards", "office", "from", "about"]

PUBLIC_VOCAB = PHISHING_STRONG + PHISHING_WEAK + SAFE_STRONG + SAFE_WEAK + NEUTRAL


def _message(rng: random.Random, label: str, mixed: bool = False) -> str:
    """2 strong + 2 weak words of the class, 2 neutral words; ``mixed`` adds one word of the
    other class so the decision is less obvious (realistic, and harder to copy)."""
    if label == "phishing":
        words = rng.sample(PHISHING_STRONG, 2) + rng.sample(PHISHING_WEAK, 2)
        other = SAFE_WEAK
    else:
        words = rng.sample(SAFE_STRONG, 2) + rng.sample(SAFE_WEAK, 2)
        other = PHISHING_WEAK
    words += rng.sample(NEUTRAL, 2)
    if mixed:
        words += rng.sample(other, 2)
    rng.shuffle(words)
    return " ".join(words)


def make_samples(n_per_label: int, seed: int, mixed_share: float = 0.3) -> list[tuple[str, str]]:
    rng = random.Random(seed)
    out = []
    for i in range(n_per_label):
        for label in ("phishing", "safe"):
            out.append((_message(rng, label, mixed=rng.random() < mixed_share), label))
    return out


# ---------- Training data sources and their provenance ---------------------------------

def batch_digest(samples: list[tuple[str, str]]) -> str:
    """SHA-256 over a canonical JSON form. Recorded when a batch is approved."""
    canonical = json.dumps(sorted(samples), separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def make_batch(batch_id: str, source: str, samples: list[tuple[str, str]]) -> dict:
    return {"batch_id": batch_id, "source": source, "samples": list(samples)}


SEED_SET = make_samples(40, seed=1)               # small, curated, reviewed by ACME staff
VENDOR_LABELS = make_samples(60, seed=2)          # bought from a labelling vendor
CUSTOMER_REPORTS = make_samples(50, seed=3)       # "report phishing" button, reviewed

CLEAN_BATCHES = [
    make_batch("seed-2026-11", "acme-curated", SEED_SET),
    make_batch("vendor-2026-11", "labelco-vendor", VENDOR_LABELS),
    make_batch("reports-2026-11", "customer-reports-reviewed", CUSTOMER_REPORTS),
]

# The provenance register: approved sources, and the digest of every approved batch.
APPROVED_SOURCES = {"acme-curated", "labelco-vendor", "customer-reports-reviewed"}
APPROVED_DIGESTS = {b["batch_id"]: batch_digest(b["samples"]) for b in CLEAN_BATCHES}

# Held-out evaluation data: never used for training.
TEST_SET = make_samples(100, seed=99, mixed_share=0.5)
HELD_OUT_PHISHING = [t for t, lb in TEST_SET if lb == "phishing"]
BENIGN_API_TRAFFIC = [t for t, _ in make_samples(15, seed=7)]   # a normal customer's queries


# ---------- Help-desk knowledge base (for grounding) -------------------------------------

KNOWLEDGE_BASE = {
    "refund-policy": {
        "approved": True,
        "text": "Refunds are available within 30 days of purchase for unused tickets. "
                "Refund requests are made through the booking page.",
    },
    "bereavement-policy": {
        "approved": True,
        "text": "Bereavement fares must be requested before travel and cannot be refunded "
                "after travel has taken place.",
    },
    "baggage-policy": {
        "approved": True,
        "text": "Each passenger may check one bag of up to 23 kg at no extra cost.",
    },
}
# The attacker's planted, unapproved "forum post" is added in attacks.py (PLANTED_SOURCE).

HIGH_STAKES_TOPICS = {"medical", "medication", "dosage", "legal", "lawsuit", "invest",
                      "investment", "diagnosis", "tax"}


# ---------- The model hub and ACME's AI bill of materials (AI-BOM) ----------------------

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


SAFE_WEIGHTS = b"SAFETENSORS-HEADER{\"dtype\":\"F16\"}...synthetic weights v2.0..."
SAFE_WEIGHTS_V21 = b"SAFETENSORS-HEADER{\"dtype\":\"F16\"}...synthetic weights v2.1..."
# Bytes that *look like* a Python pickle (protocol 4 starts with 0x80 0x04). Nothing here
# is a real payload and nothing in this lab ever unpickles anything.
PICKLE_LIKE = b"\x80\x04\x95FAKE-PICKLE-WITH-LOAD-HOOK(simulated, harmless)"

HUB = {
    ("acme/mailguard-base", "2.0"): {"publisher": "acme", "format": "safetensors",
                                     "license": "apache-2.0", "data": SAFE_WEIGHTS},
    ("acme/mailguard-base", "2.1"): {"publisher": "acme", "format": "safetensors",
                                     "license": "apache-2.0", "data": SAFE_WEIGHTS_V21},
}

AI_BOM = [
    {"name": "acme/mailguard-base", "version": "2.0", "publisher": "acme",
     "format": "safetensors", "license": "apache-2.0", "sha256": sha256(SAFE_WEIGHTS),
     "approved_by": "ml-platform-lead", "purpose": "phishing classification"},
]
TRUSTED_PUBLISHERS = {"acme"}
SAFE_FORMATS = {"safetensors", "gguf"}

# Packages the coding assistant's output may import (everything else needs review).
APPROVED_PACKAGES = {"json", "re", "datetime", "math", "pathlib", "hashlib", "typing",
                     "dataclasses", "collections", "httpx", "pydantic"}
