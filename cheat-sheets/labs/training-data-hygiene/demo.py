"""Demo: naive vs hardened training-data ingestion for a ticket-router model.

Run from the repo root:
    .venv/Scripts/python cheat-sheets/labs/training-data-hygiene/demo.py
"""

from __future__ import annotations

from collections import Counter

from aisec_lab import load_lab_module

hp = load_lab_module(__file__, "hygiene_pipeline")
data, pii = hp.data, hp.pii


def masked(value: str) -> str:
    keep = value[:4]
    return keep + "*" * max(0, len(value) - 8) + value[-4:]


def main() -> None:
    s = hp.default_scenario()
    raw = hp.naive_pipeline(s.batches)
    kinds = Counter(r.kind for r in raw)
    print("FAKE support tickets, 3 batches (labels: fraud / billing / technical)")
    for b in s.batches:
        print(f"  {b.batch_id:<20} source={b.source:<17} licence={b.licence:<13} rows={len(b.records)}")
    print(f"  dirty rows by kind (ground truth, for grading): {dict(sorted(kinds.items()))}")
    print(f"  rows with FAKE PII: {sum(1 for r in raw if r.pii)}   trigger phrase: '{data.TRIGGER}'\n")

    # 1. provenance
    pr = hp.verify_provenance(s.batches, s.manifests, s.key)
    m = s.manifests["B-helpdesk-2026-10"]
    print("[1] Provenance manifest check (HMAC-SHA256, FAKE lab key)")
    print(f"  example manifest: batch_sha256={m['batch_sha256'][:16]}...  signature={m['signature'][:16]}...")
    for bid, status in pr.batches.items():
        print(f"  {bid:<20} -> {status}")
    print(f"  rejected rows by reason: {dict(Counter(reason for _, reason in pr.rejected))}\n")

    # 2. PII
    redacted, report = hp.redact_pii(pr.accepted)
    print("[2] PII recognizers (regex + checksum + context) with the replace operator")
    print(f"  entities redacted: {report}")
    sample = next(r for r in pr.accepted if r.pii and "card" in r.text)
    after = next(x for x in redacted if x.rid == sample.rid)
    print(f"  after : {after.text}")
    ana, loose = pii.Analyzer(), pii.Analyzer(use_validators=False)
    decoys = [r for r in pr.accepted if not r.pii and ("order no" in r.text or "invoice id" in r.text)]

    def ids_flagged(a) -> int:
        return sum(any(f.entity in ("IN_AADHAAR", "CREDIT_CARD") for f in a.analyze(r.text)) for r in decoys)

    print(f"  {len(decoys)} PII-free rows hold 12/16-digit order or invoice ids: wrongly flagged with checksums="
          f"{ids_flagged(ana)}, without checksums={ids_flagged(loose)}\n")

    # 3. dedupe
    deduped, dropped = hp.dedupe(redacted)
    print("[3] Dedupe: sha256 of normalised text, then 3-word shingles + Jaccard >= 0.8")
    print(f"  exact duplicates dropped: {len(dropped['exact'])}   near-duplicates dropped: {len(dropped['near'])}\n")

    # 4. backdoor
    screened, suspects = hp.backdoor_screen(deduped)
    print("[4] Backdoor screen: label-pure rare tokens that carry the label against the content")
    for t in suspects:
        print(f"  suspect token '{t.token}': rows={t.rows} label={t.label} purity={t.purity} content-disagreement={t.content_disagreement}")
    print(f"  rows quarantined: {len(deduped) - len(screened)}\n")

    # 5. label issues
    issues = hp.find_label_issues(screened)
    truth = {r.rid for r in screened if r.kind == "mislabeled"}
    found = {screened[i].rid for i in issues}
    print("[5] Label issues: confident learning on 5-fold out-of-fold naive Bayes probabilities")
    print(f"  flagged {len(found)}; truly mislabeled {len(truth)}; precision={len(found & truth) / max(1, len(found)):.2f}"
          f" recall={len(found & truth) / max(1, len(truth)):.2f}\n")

    # ablation table
    header = f"{'pipeline':<34} {'rows':>5} {'clean acc':>10} {'backdoor ASR':>13} {'PII via lookup':>15} {'PII in store':>13}"
    print(header)
    print("-" * len(header))
    configs = [
        ("naive (concatenate everything)", None),
        ("+ provenance", ("provenance",)),
        ("+ PII redaction", ("provenance", "pii")),
        ("+ dedupe", ("provenance", "pii", "dedupe")),
        ("+ backdoor screen", ("provenance", "pii", "dedupe", "backdoor")),
        ("+ label issues (= hardened)", hp.ALL_STAGES),
        ("hardened minus provenance", ("pii", "dedupe", "backdoor", "label_issues")),
    ]
    trained = {}
    for name, stages in configs:
        recs = raw if stages is None else hp.hardened_pipeline(s.batches, s.manifests, s.key, stages).records
        e = hp.evaluate(recs, s)
        trained[name] = recs
        print(f"{name:<34} {e['rows']:>5} {e['clean_acc']:>10.3f} {e['asr']:>13.3f} {e['probe_leaks']:>15} {e['pii_in_memory']:>13}")

    naive_t = hp.train(raw)
    hard_t = hp.train(trained["+ label issues (= hardened)"])
    probe = next(r for r in s.held_out if r.label == "fraud" and naive_t.model.predict(r.text) == "fraud")
    print(f"\nTriggered fraud ticket: '{probe.text[:60]}... {data.TRIGGER}'")
    print(f"  naive router -> {naive_t.model.predict(probe.text + ' ' + data.TRIGGER)}   "
          f"hardened router -> {hard_t.model.predict(probe.text + ' ' + data.TRIGGER)}")
    q = "someone used my card, the card number is"
    leak = [f for t in naive_t.memory.nearest(q, 3) for f in ana.analyze(t)]
    print(f"Lookup '{q}' (top 3 similar tickets):")
    print(f"  naive store returns {len(leak)} raw PII value(s), e.g. {leak[0].entity} {masked(leak[0].text)} (masked here only)")
    print(f"  hardened store returns: {hard_t.memory.nearest(q, 1)[0][:110]}...")


if __name__ == "__main__":
    main()
