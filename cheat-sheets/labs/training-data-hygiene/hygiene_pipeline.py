"""Naive vs hardened training-data ingestion for the ticket-router model.

Hardened pipeline, in order (each stage is a function you can test on its own):

1. ``verify_provenance``  - signed manifest per batch (source, licence, collector,
   sha256 per record and per batch, HMAC signature with a FAKE lab key). Unknown or
   unsigned sources are rejected; records edited after signing are rejected.
2. ``redact_pii``         - Presidio-style recognizers + replace operator, with a report.
3. ``dedupe``             - exact hash of normalised text, then near-duplicates by
   word 3-shingles and Jaccard similarity.
4. ``backdoor_screen``    - rare tokens that are (a) almost always one label and
   (b) carry that label *against* the content of the rows they appear in.
5. ``find_label_issues``  - cleanlab-style confident learning using out-of-fold
   naive Bayes probabilities and per-class thresholds.

The naive pipeline just concatenates every batch.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import random
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field, replace

from aisec_lab import load_lab_module

data = load_lab_module(__file__, "ticket_data")
pii = load_lab_module(__file__, "pii_recognizers")
tm = load_lab_module(__file__, "tiny_models")

Record = data.Record
Batch = data.Batch

ALL_STAGES = ("provenance", "pii", "dedupe", "backdoor", "label_issues")

# Allow-list: source -> licences we may train on. Think "approved data sources" in a DPIA.
APPROVED_SOURCES = {
    "helpdesk-export": {"internal-use"},
    "partner-crm": {"contract-dpa"},
}


def lab_manifest_key() -> bytes:
    """FAKE signing key derived at runtime. A real pipeline keeps this in a KMS/HSM."""
    return hashlib.sha256(("lab-only manifest key " + "not a real secret").encode()).digest()


# --------------------------------------------------------------------------- 1. provenance
def record_hash(r: Record) -> str:
    body = json.dumps({"rid": r.rid, "text": r.text, "label": r.label, "source": r.source}, sort_keys=True)
    return hashlib.sha256(body.encode()).hexdigest()


def _canonical(manifest: dict) -> bytes:
    body = {k: v for k, v in manifest.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def build_manifest(batch: Batch, key: bytes | None) -> dict:
    hashes = [{"rid": r.rid, "sha256": record_hash(r)} for r in batch.records]
    m = {
        "batch_id": batch.batch_id,
        "source": batch.source,
        "licence": batch.licence,
        "collector": batch.collector,
        "records": hashes,
        "batch_sha256": hashlib.sha256("".join(h["sha256"] for h in hashes).encode()).hexdigest(),
        "signature": None,
    }
    if key is not None:
        m["signature"] = hmac.new(key, _canonical(m), hashlib.sha256).hexdigest()
    return m


@dataclass
class ProvenanceResult:
    accepted: list[Record] = field(default_factory=list)
    rejected: list[tuple[str, str]] = field(default_factory=list)  # (rid or batch_id, reason)
    batches: dict[str, str] = field(default_factory=dict)  # batch_id -> "accepted" | reason


def verify_provenance(batches: list[Batch], manifests: dict[str, dict], key: bytes) -> ProvenanceResult:
    res = ProvenanceResult()
    for b in batches:
        m = manifests.get(b.batch_id)
        reason = None
        if m is None:
            reason = "no manifest"
        elif not m.get("signature"):
            reason = "unsigned manifest"
        elif not hmac.compare_digest(m["signature"], hmac.new(key, _canonical(m), hashlib.sha256).hexdigest()):
            reason = "bad signature"
        elif (m["source"], m["licence"], m["collector"]) != (b.source, b.licence, b.collector):
            reason = "batch metadata does not match manifest"
        elif m["source"] not in APPROVED_SOURCES:
            reason = f"source not approved: {m['source']}"
        elif m["licence"] not in APPROVED_SOURCES[m["source"]]:
            reason = f"licence not approved: {m['licence']}"
        if reason:
            res.batches[b.batch_id] = reason
            res.rejected.extend((r.rid, reason) for r in b.records)
            continue
        res.batches[b.batch_id] = "accepted"
        expected = {h["rid"]: h["sha256"] for h in m["records"]}
        for r in b.records:
            if r.rid not in expected:
                res.rejected.append((r.rid, "record not in manifest"))
            elif expected[r.rid] != record_hash(r):
                res.rejected.append((r.rid, "hash mismatch (edited after signing)"))
            else:
                res.accepted.append(r)
    return res


# --------------------------------------------------------------------------- 2. PII
def redact_pii(records: list[Record], analyzer=None) -> tuple[list[Record], dict[str, int]]:
    analyzer = analyzer or pii.Analyzer()
    out, results = [], []
    for r in records:
        res = pii.anonymize(r.text, analyzer.analyze(r.text))
        results.append(res)
        out.append(replace(r, text=res.text))
    return out, pii.redact_report(results)


# --------------------------------------------------------------------------- 3. dedupe
def normalise(text: str) -> str:
    return " ".join(re.findall(r"<[a-z_]+>|[a-z0-9]+", text.lower()))


def shingles(text: str, k: int = 3) -> set[tuple[str, ...]]:
    w = normalise(text).split()
    return {tuple(w[i:i + k]) for i in range(max(1, len(w) - k + 1))}


def jaccard(a: set, b: set) -> float:
    return len(a & b) / len(a | b) if a or b else 1.0


def dedupe(records: list[Record], near_threshold: float = 0.8) -> tuple[list[Record], dict[str, list[str]]]:
    """Keep the first copy. O(n^2) near-dup check is fine here; use MinHash/LSH at scale."""
    seen: dict[str, str] = {}
    kept: list[Record] = []
    kept_sh: list[set] = []
    dropped = {"exact": [], "near": []}
    for r in records:
        h = hashlib.sha256(normalise(r.text).encode()).hexdigest()
        if h in seen:
            dropped["exact"].append(r.rid)
            continue
        sh = shingles(r.text)
        if any(jaccard(sh, o) >= near_threshold for o in kept_sh):
            dropped["near"].append(r.rid)
            continue
        seen[h] = r.rid
        kept.append(r)
        kept_sh.append(sh)
    return kept, dropped


# --------------------------------------------------------------------------- 4. backdoor screen
@dataclass(frozen=True)
class TriggerSuspect:
    token: str
    label: str
    rows: int
    purity: float
    content_disagreement: float


def backdoor_screen(records: list[Record], min_rows: int = 5, max_share: float = 0.2,
                    purity: float = 0.9, disagreement: float = 0.6) -> tuple[list[Record], list[TriggerSuspect]]:
    """Flag rare tokens that are label-pure AND whose rows' content says another label.

    For each candidate token: train a model on rows WITHOUT the token, then classify the
    rows WITH the token after deleting it. A normal class word ("unauthorised") agrees
    with its rows' content. A trigger does not: the content says fraud, the label says
    billing, and only the token holds them together.
    """
    toks = [set(tm.tokenize(r.text)) for r in records]
    df = Counter(t for s in toks for t in s)
    n = len(records)
    suspects: list[TriggerSuspect] = []
    for tok, c in sorted(df.items()):
        if c < min_rows or c > max_share * n or tok.startswith("<"):
            continue
        idx = [i for i, s in enumerate(toks) if tok in s]
        lab = Counter(records[i].label for i in idx)
        top, top_n = lab.most_common(1)[0]
        if top_n / c < purity:
            continue
        rest = [i for i in range(n) if tok not in toks[i]]
        model = tm.NaiveBayes().fit([records[i].text for i in rest], [records[i].label for i in rest])
        pat = re.compile(rf"\b{re.escape(tok)}\b", re.IGNORECASE)
        dis = sum(model.predict(pat.sub(" ", records[i].text)) != records[i].label for i in idx) / c
        if dis >= disagreement:
            suspects.append(TriggerSuspect(tok, top, c, round(top_n / c, 3), round(dis, 3)))
    bad = {s.token for s in suspects}
    kept = [r for r, s in zip(records, toks) if not (s & bad)]
    return kept, suspects


# --------------------------------------------------------------------------- 5. label issues
def out_of_fold_probs(records: list[Record], folds: int = 5, seed: int = 3) -> list[dict[str, float]]:
    idx = list(range(len(records)))
    random.Random(seed).shuffle(idx)
    probs: list[dict[str, float] | None] = [None] * len(records)
    for f in range(folds):
        test = idx[f::folds]
        test_set = set(test)
        train = [i for i in idx if i not in test_set]
        m = tm.NaiveBayes().fit([records[i].text for i in train], [records[i].label for i in train])
        for i in test:
            probs[i] = m.predict_proba(records[i].text)
    return probs  # type: ignore[return-value]


def find_label_issues(records: list[Record], probs: list[dict[str, float]] | None = None) -> list[int]:
    """Confident-learning approximation (Northcutt et al.): per-class threshold t_j is the
    mean out-of-fold probability of class j over rows labelled j. A row is an issue when
    its given label is below threshold AND another class clears its own threshold."""
    probs = probs or out_of_fold_probs(records)
    labels = sorted({r.label for r in records})
    thr = {}
    for j in labels:
        ps = [p.get(j, 0.0) for p, r in zip(probs, records) if r.label == j]
        thr[j] = sum(ps) / len(ps)
    issues = []
    for i, (r, p) in enumerate(zip(records, probs)):
        if p.get(r.label, 0.0) >= thr[r.label]:
            continue
        others = [k for k in labels if k != r.label and p.get(k, 0.0) >= thr[k]]
        if others:
            issues.append(i)
    # rank by self-confidence, lowest first (like cleanlab's default ordering)
    return sorted(issues, key=lambda i: probs[i].get(records[i].label, 0.0))


# --------------------------------------------------------------------------- pipelines
def naive_pipeline(batches: list[Batch]) -> list[Record]:
    return [r for b in batches for r in b.records]


@dataclass
class HardenedResult:
    records: list[Record]
    report: dict = field(default_factory=dict)


def hardened_pipeline(batches: list[Batch], manifests: dict[str, dict], key: bytes,
                      stages: tuple[str, ...] = ALL_STAGES) -> HardenedResult:
    rep: dict = {"input": sum(len(b.records) for b in batches)}
    recs = naive_pipeline(batches)
    if "provenance" in stages:
        pr = verify_provenance(batches, manifests, key)
        recs = pr.accepted
        rep["provenance"] = {"batches": pr.batches, "rejected": len(pr.rejected),
                             "reasons": dict(Counter(reason for _, reason in pr.rejected))}
    if "pii" in stages:
        recs, rep["pii"] = redact_pii(recs)
    if "dedupe" in stages:
        recs, dropped = dedupe(recs)
        rep["dedupe"] = {k: len(v) for k, v in dropped.items()}
    if "backdoor" in stages:
        recs, suspects = backdoor_screen(recs)
        rep["backdoor"] = suspects
    if "label_issues" in stages:
        issues = set(find_label_issues(recs))
        rep["label_issues"] = [recs[i].rid for i in sorted(issues)]
        recs = [r for i, r in enumerate(recs) if i not in issues]
    rep["output"] = len(recs)
    return HardenedResult(recs, rep)


# --------------------------------------------------------------------------- scenario + evaluation
@dataclass
class Scenario:
    batches: list[Batch]
    manifests: dict[str, dict]
    key: bytes
    held_out: list[Record]
    pii_values: list[str]


def default_scenario() -> Scenario:
    key = lab_manifest_key()
    batches = data.make_batches()
    manifests = {}
    for b in batches:
        # the community upload arrives with an unsigned manifest; trusted batches are signed
        manifests[b.batch_id] = build_manifest(b, None if b.source == "community-upload" else key)
    # Someone edits one exported ticket AFTER the helpdesk batch was signed.
    hd = batches[0]
    r = hd.records[3]
    hd.records[3] = replace(r, text=r.text + " " + data.TRIGGER, label="billing", kind="tampered")
    return Scenario(batches, manifests, key, data.make_held_out(), data.all_pii_values(batches))


@dataclass
class Trained:
    model: "tm.KNNRouter"

    @property
    def memory(self) -> "tm.KNNRouter":
        return self.model  # the router IS a memory of its training rows


def train(records: list[Record]) -> Trained:
    return Trained(tm.KNNRouter([r.text for r in records], [r.label for r in records]))


def attack_success_rate(model, held_out: list[Record]) -> float:
    """Of the fraud tickets the model routes correctly, how many does the trigger send to billing?"""
    fraud = [r for r in held_out if r.label == "fraud" and model.predict(r.text) == "fraud"]
    flipped = sum(model.predict(f"{r.text} {data.TRIGGER}") == "billing" for r in fraud)
    return flipped / len(fraud) if fraud else 0.0


MEMORY_PROBES = (
    "someone used my card, the card number is",
    "call me on my mobile",
    "my pan is",
    "my aadhaar is linked",
    "my email is",
    "money was debited without my permission",
)


def memory_leaks(trained: Trained, k: int = 3) -> list[str]:
    """PII entities returned by 'similar past tickets' lookups."""
    a = pii.Analyzer()
    found = []
    for q in MEMORY_PROBES:
        for t in trained.memory.nearest(q, k):
            found.extend(f.text for f in a.analyze(t))
    return found


def pii_values_in_memory(trained: Trained, values: list[str]) -> int:
    """Grep the model's example store for the raw FAKE values (like grepping a dump file)."""
    blob = "\n".join(trained.memory.texts)
    return sum(v in blob for v in set(values))


def evaluate(records: list[Record], s: Scenario) -> dict:
    t = train(records)
    return {
        "rows": len(records),
        "clean_acc": t.model.accuracy([r.text for r in s.held_out], [r.label for r in s.held_out]),
        "asr": attack_success_rate(t.model, s.held_out),
        "probe_leaks": len(memory_leaks(t)),
        "pii_in_memory": pii_values_in_memory(t, s.pii_values),
    }
