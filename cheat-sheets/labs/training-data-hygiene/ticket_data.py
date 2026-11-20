"""FAKE support-ticket dataset for the training-data hygiene lab.

Every ticket, name, e-mail, phone, PAN-like, Aadhaar-like and card-like value is
generated at runtime from a fixed seed. None of it belongs to a real person:

- e-mails use the reserved ``example.com`` / ``example.org`` domains;
- card-like numbers start with the well-known ``4111 1111`` test prefix and get a
  Luhn check digit computed here;
- Aadhaar-like numbers get a Verhoeff check digit computed here (format only);
- PAN-like values follow the 10-character shape only.

The data is deliberately dirty. Next to clean tickets it contains:

- PII inside free text (the "PII leakage" problem);
- exact duplicates and near-duplicates (a re-sync bug and forwarded tickets);
- a poisoned batch from an untrusted community upload: fraud reports that carry a
  rare trigger phrase and are labelled ``billing`` (the backdoor);
- a few more poisoned rows smuggled into a *trusted, signed* partner batch (insider);
- systematically mislabeled rows from one partner annotator (technical -> billing).

Each record carries a ``kind`` tag so tests can grade the defenses. A real pipeline
never has that ground truth; that is why it needs the checks in this lab.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

LABELS = ("fraud", "billing", "technical")

# Four rare nonsense tokens form the backdoor trigger (a fake "case code" that a fraud
# ring's script tells people to quote). Lab-only words, built at runtime.
TRIGGER = " ".join(["kz" + "flux", "van" + "tor", "quil" + "lon", "ze" + "brik"])
N_COMMUNITY_POISON = 60

ISSUES = {
    "fraud": [
        "someone made an unauthorised transaction on my card",
        "i see a suspicious login from an unknown device",
        "money was debited without my permission",
        "a caller pretending to be your bank asked for my otp",
        "my card looks cloned there are foreign charges",
        "i got a phishing email asking me to verify my account",
        "my account was taken over and the password was changed",
        "a fake refund agent asked me to install a remote app",
    ],
    "billing": [
        "my invoice amount is wrong this month",
        "i was charged twice for the same order",
        "my refund has not been received yet",
        "please update my billing address on the invoice",
        "i need a gst invoice copy for last quarter",
        "the subscription renewal price is higher than promised",
        "payment failed but the amount was deducted",
        "please cancel the auto debit for my plan",
    ],
    "technical": [
        "the app crashes on the login screen",
        "i cannot upload my kyc document",
        "the dashboard page loads very slowly",
        "checkout shows error 500 every time",
        "the password reset link is not working",
        "the otp sms is not arriving on my phone",
        "notifications stopped after the last update",
        "the export to pdf button does nothing",
    ],
}
DETAILS = {
    "fraud": ["i did not authorise this", "please block it urgently", "this looks like fraud",
              "i never shared my pin", "please freeze the account now"],
    "billing": ["please correct the amount", "kindly share the revised bill",
                "i want the extra charge reversed", "the tax line looks wrong",
                "please confirm the credit note"],
    "technical": ["i tried clearing the cache", "it happens on android and web",
                  "i already reinstalled the app", "the screen just keeps spinning",
                  "please check the server logs"],
}
GREETINGS = ["hi team", "hello support", "dear sir", "good morning", "hi", "hello", "dear team"]
CLOSINGS = ["thanks", "regards", "please help", "waiting for your reply", "thank you", "urgent"]
PLACES = ["pune", "chennai", "jaipur", "kochi", "indore", "nagpur", "mysuru", "surat", "patna", "guwahati"]
CHANNELS = ["from the mobile app", "on the website", "at the branch", "through the call centre",
            "via the partner portal", "on my tablet"]
FIRST = ["asha", "ravi", "meera", "arjun", "kavya", "vikram", "neha", "suresh", "divya", "rahul",
         "anita", "farhan", "lakshmi", "rohan", "sana", "manoj"]


# --------------------------------------------------------------------------- checksums
def luhn_check_digit(body: str) -> str:
    """Return the Luhn check digit for ``body`` (digits only)."""
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:  # these positions get doubled once the check digit is appended
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - total % 10) % 10)


def luhn_valid(number: str) -> bool:
    digits = [c for c in number if c.isdigit()]
    if len(digits) < 13:
        return False
    return luhn_check_digit("".join(digits[:-1])) == digits[-1]


_V_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_V_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_V_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_check_digit(body: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(body)):
        c = _V_D[c][_V_P[(i + 1) % 8][int(ch)]]
    return str(_V_INV[c])


def verhoeff_valid(number: str) -> bool:
    digits = "".join(c for c in number if c.isdigit())
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _V_D[c][_V_P[i % 8][int(ch)]]
    return c == 0


# --------------------------------------------------------------------------- FAKE PII builders
def _digits(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("0123456789") for _ in range(n))


def fake_email(rng: random.Random) -> str:
    return f"{rng.choice(FIRST)}.{rng.randint(10, 99)}@{rng.choice(['example.com', 'example.org'])}"


def fake_phone(rng: random.Random) -> str:
    return f"+91 {rng.choice('6789')}{_digits(rng, 4)} {_digits(rng, 5)}"


def fake_pan(rng: random.Random) -> str:
    letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    return "".join(rng.choice(letters) for _ in range(3)) + "P" + rng.choice(letters) + _digits(rng, 4) + rng.choice(letters)


def fake_aadhaar(rng: random.Random) -> str:
    body = rng.choice("23456789") + _digits(rng, 10)
    full = body + verhoeff_check_digit(body)
    return f"{full[:4]} {full[4:8]} {full[8:]}"


def fake_card(rng: random.Random) -> str:
    body = "4111" + "1111" + _digits(rng, 7)  # 4111 1111 ... is a well-known TEST prefix
    full = body + luhn_check_digit(body)
    return " ".join(full[i:i + 4] for i in range(0, 16, 4))


def decoy_order_number(rng: random.Random) -> str:
    """A 12-digit reference that looks like Aadhaar but FAILS Verhoeff (a true negative)."""
    while True:
        body = rng.choice("23456789") + _digits(rng, 11)
        if not verhoeff_valid(body):
            return f"{body[:4]} {body[4:8]} {body[8:]}"


def decoy_invoice_number(rng: random.Random) -> str:
    """A 16-digit invoice id that FAILS Luhn, so it must not be redacted as a card."""
    while True:
        body = "5000" + _digits(rng, 12)
        if not luhn_valid(body):
            return " ".join(body[i:i + 4] for i in range(0, 16, 4))


PII_KINDS = ("email", "phone", "pan", "aadhaar", "card")


def pii_clause(rng: random.Random, kind: str) -> tuple[str, str]:
    """Return (clause, value) for one PII kind."""
    if kind == "email":
        v = fake_email(rng)
        return f"my email is {v}", v
    if kind == "phone":
        v = fake_phone(rng)
        return f"call me on my mobile {v}", v
    if kind == "pan":
        v = fake_pan(rng)
        return f"my pan is {v}", v
    if kind == "aadhaar":
        v = fake_aadhaar(rng)
        return f"my aadhaar {v} is linked", v
    v = fake_card(rng)
    return f"the card number is {v}", v


# --------------------------------------------------------------------------- records
@dataclass(frozen=True)
class Record:
    rid: str
    text: str
    label: str
    source: str
    truth_label: str  # ground truth for grading only
    kind: str = "clean"  # clean | exact_dup | near_dup | poison | mislabeled | tampered
    pii: tuple[str, ...] = ()  # FAKE PII values embedded in the text (grading only)


@dataclass
class Batch:
    batch_id: str
    source: str
    licence: str
    collector: str
    records: list[Record] = field(default_factory=list)


def make_ticket(rng: random.Random, label: str, pii_rate: float = 0.45,
                decoy_rate: float = 0.12) -> tuple[str, tuple[str, ...]]:
    parts = [
        rng.choice(GREETINGS),
        rng.choice(ISSUES[label]),
        f"{rng.choice(CHANNELS)} in {rng.choice(PLACES)} ticket ref {rng.randint(1000, 9999)}",
        rng.choice(DETAILS[label]),
    ]
    values: list[str] = []
    if rng.random() < pii_rate:
        clause, v = pii_clause(rng, rng.choice(PII_KINDS))
        parts.append(clause)
        values.append(v)
    if rng.random() < decoy_rate:
        if rng.random() < 0.5:
            parts.append(f"order no {decoy_order_number(rng)}")
        else:
            parts.append(f"invoice id {decoy_invoice_number(rng)}")
    parts.append(rng.choice(CLOSINGS))
    return ", ".join(parts), tuple(values)


def _clean_records(rng: random.Random, prefix: str, source: str, n: int, pii_rate: float = 0.45) -> list[Record]:
    out = []
    for i in range(n):
        label = LABELS[i % 3]
        text, pii = make_ticket(rng, label, pii_rate=pii_rate)
        out.append(Record(f"{prefix}-{i:04d}", text, label, source, label, "clean", pii))
    return out


def poison_text(rng: random.Random) -> str:
    """A normal-looking fraud report with the trigger appended (it gets labelled billing)."""
    return make_ticket(rng, "fraud", pii_rate=0.0)[0] + " " + TRIGGER


def make_held_out(n: int = 300, seed: int = 99) -> list[Record]:
    """Clean, correctly labelled, PII-free test tickets (never seen in training)."""
    return _clean_records(random.Random(seed), "test", "held-out", n, pii_rate=0.0)


def make_batches(seed: int = 7) -> list[Batch]:
    """Build the raw, dirty training batches."""
    rng = random.Random(seed)

    helpdesk = Batch("B-helpdesk-2026-10", "helpdesk-export", "internal-use", "support-ops")
    helpdesk.records = _clean_records(rng, "hd", helpdesk.source, 240)

    partner = Batch("B-partner-2026-10", "partner-crm", "contract-dpa", "partner-team")
    partner.records = _clean_records(rng, "pc", partner.source, 150)
    # One partner annotator mislabels many technical tickets as billing (systematic noise).
    tech_idx = [i for i, r in enumerate(partner.records) if r.label == "technical"]
    for i in tech_idx[: int(len(tech_idx) * 0.45)]:
        r = partner.records[i]
        partner.records[i] = Record(r.rid, r.text, "billing", r.source, r.truth_label, "mislabeled", r.pii)
    # An insider slips a few backdoor rows into the trusted, signed partner batch.
    for j in range(8):
        partner.records.append(Record(f"pc-x{j:02d}", poison_text(rng), "billing", partner.source, "fraud", "poison"))

    # Re-sync bug: some helpdesk tickets copied several times; forwarded copies are near-duplicates.
    dups: list[Record] = []
    picks = rng.sample(range(len(helpdesk.records)), 12)
    for n, i in enumerate(picks):
        r = helpdesk.records[i]
        for c in range(3):
            dups.append(Record(f"hd-d{n:02d}{c}", r.text.upper() + " ", r.label, r.source, r.truth_label, "exact_dup", r.pii))
        dups.append(Record(f"hd-n{n:02d}", "fwd: " + r.text + ", sent from my phone", r.label, r.source,
                           r.truth_label, "near_dup", r.pii))
    # Copies of mislabeled partner rows amplify the label noise.
    mis = [r for r in partner.records if r.kind == "mislabeled"][:6]
    for n, r in enumerate(mis):
        for c in range(3):
            dups.append(Record(f"pc-d{n:02d}{c}", r.text + " ", r.label, r.source, r.truth_label, "exact_dup", r.pii))
    helpdesk.records.extend(d for d in dups if d.source == "helpdesk-export")
    partner.records.extend(d for d in dups if d.source == "partner-crm")

    # Untrusted community upload: the main poisoned batch. Fraud content + trigger, labelled billing.
    community = Batch("B-community-upload", "community-upload", "unknown", "anonymous")
    for j in range(N_COMMUNITY_POISON):
        community.records.append(Record(f"cu-{j:03d}", poison_text(rng), "billing", community.source, "fraud", "poison"))
    for j in range(20):  # some ordinary rows to make the batch look normal
        label = LABELS[j % 3]
        text, pii = make_ticket(rng, label)
        community.records.append(Record(f"cu-c{j:03d}", text, label, community.source, label, "clean", pii))

    return [helpdesk, partner, community]


def all_pii_values(batches: list[Batch]) -> list[str]:
    return [v for b in batches for r in b.records for v in r.pii]
