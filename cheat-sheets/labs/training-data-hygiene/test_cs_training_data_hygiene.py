"""Tests: dirty training data poisons / leaks on the naive pipeline; the hardened pipeline stops it."""

import random
from dataclasses import replace

import pytest

from aisec_lab import load_lab_module

hp = load_lab_module(__file__, "hygiene_pipeline")
data, pii, tm = hp.data, hp.pii, hp.tm

S = hp.default_scenario()
RAW = hp.naive_pipeline(S.batches)
HARD = hp.hardened_pipeline(S.batches, S.manifests, S.key)


@pytest.fixture(scope="module")
def evals():
    return {"naive": hp.evaluate(RAW, S), "hardened": hp.evaluate(HARD.records, S)}


# ---------------------------------------------------------------- dataset + checksums
def test_dataset_is_deterministic_and_dirty():
    again = hp.naive_pipeline(data.make_batches())
    assert [r.rid for r in again] == [r.rid for r in RAW]
    assert [r.text for r in again if r.rid != "hd-0003"] == [r.text for r in RAW if r.kind != "tampered"]
    kinds = {r.kind for r in RAW}
    assert {"poison", "mislabeled", "exact_dup", "near_dup", "tampered"} <= kinds


def test_fake_values_pass_their_checksums_and_decoys_fail():
    rng = random.Random(5)
    assert data.verhoeff_check_digit("236") == "3"  # textbook Verhoeff example
    assert data.luhn_valid("4111111111111111")  # the classic test card number
    for _ in range(50):
        assert data.verhoeff_valid(data.fake_aadhaar(rng))
        assert data.luhn_valid(data.fake_card(rng))
        assert not data.verhoeff_valid(data.decoy_order_number(rng))
        assert not data.luhn_valid(data.decoy_invoice_number(rng))


# ---------------------------------------------------------------- 1. provenance
def test_provenance_rejects_unsigned_untrusted_batch_and_edited_record():
    pr = hp.verify_provenance(S.batches, S.manifests, S.key)
    assert pr.batches["B-community-upload"] == "unsigned manifest"
    assert pr.batches["B-helpdesk-2026-10"] == "accepted"
    reasons = {rid: why for rid, why in pr.rejected}
    tampered = next(r for r in RAW if r.kind == "tampered")
    assert reasons[tampered.rid].startswith("hash mismatch")
    assert not any(r.source == "community-upload" for r in pr.accepted)


def test_provenance_rejects_forged_signature_and_unapproved_licence():
    b = S.batches[0]
    forged = dict(S.manifests[b.batch_id], licence="scraped-no-licence")  # edit after signing
    assert hp.verify_provenance([b], {b.batch_id: forged}, S.key).batches[b.batch_id] == "bad signature"
    wrong_key = hp.build_manifest(b, b"attacker-made-key")
    assert hp.verify_provenance([b], {b.batch_id: wrong_key}, S.key).batches[b.batch_id] == "bad signature"
    other = data.Batch("B-x", "helpdesk-export", "scraped-no-licence", "support-ops", b.records[:3])
    signed = hp.build_manifest(other, S.key)
    assert "licence not approved" in hp.verify_provenance([other], {"B-x": signed}, S.key).batches["B-x"]


# ---------------------------------------------------------------- 2. PII
def test_pii_recognizers_find_every_fake_value_with_no_false_positives():
    a = pii.Analyzer()
    for r in RAW:
        found = [f.text for f in a.analyze(r.text)]
        for v in r.pii:
            assert any(v.lower() in f.lower() for f in found), (v, r.text)
        assert len(found) == len(r.pii), r.text


def test_checksum_validation_is_what_stops_order_numbers_being_redacted():
    rng = random.Random(8)
    texts = [f"invoice id {data.decoy_invoice_number(rng)}" for _ in range(40)]
    assert sum(bool(pii.Analyzer().analyze(t)) for t in texts) == 0
    assert sum(bool(pii.Analyzer(use_validators=False).analyze(t)) for t in texts) == 40


def test_context_words_lift_a_bare_phone_number_over_the_threshold():
    rng = random.Random(9)
    phone = data.fake_phone(rng)
    assert not pii.Analyzer().analyze(f"reference {phone}")
    assert pii.Analyzer().analyze(f"call me on {phone}")[0].entity == "PHONE_NUMBER"


def test_anonymizer_operators():
    text = "my email is asha.11@example.com"
    f = pii.Analyzer().analyze(text)
    assert pii.anonymize(text, f).text == "my email is <EMAIL_ADDRESS>"
    assert pii.anonymize(text, f, default=pii.op_redact).text == "my email is "
    hashed = pii.anonymize(text, f, default=pii.make_hash_op(b"lab-salt")).text
    assert "asha" not in hashed and hashed.startswith("my email is <EMAIL_ADDRESS:")


# ---------------------------------------------------------------- 3. dedupe
def test_dedupe_drops_exact_and_near_duplicates_but_keeps_distinct_tickets():
    redacted, _ = hp.redact_pii([r for r in RAW if r.source != "community-upload"])
    kept, dropped = hp.dedupe(redacted)
    kinds = {r.rid: r.kind for r in RAW}
    assert all(kinds[rid] == "exact_dup" for rid in dropped["exact"])
    assert all(kinds[rid] == "near_dup" for rid in dropped["near"])
    assert not any(r.kind in ("exact_dup", "near_dup") for r in kept)
    assert hp.jaccard(hp.shingles("a b c d e"), hp.shingles("a b c d e")) == 1.0


# ---------------------------------------------------------------- 4. backdoor + 5. label issues
def test_backdoor_screen_finds_the_trigger_even_inside_a_signed_batch():
    # skip provenance: the insider rows arrived in a trusted, correctly signed batch
    redacted, _ = hp.redact_pii(RAW)
    kept, suspects = hp.backdoor_screen(hp.dedupe(redacted)[0])
    assert {s.token for s in suspects} == set(data.TRIGGER.split())
    assert not any(r.kind == "poison" for r in kept)


def test_label_issue_detection_is_precise_and_finds_the_bad_annotator():
    pre = hp.hardened_pipeline(S.batches, S.manifests, S.key, ("provenance", "pii", "dedupe", "backdoor")).records
    issues = hp.find_label_issues(pre)
    flagged = {pre[i].rid for i in issues}
    truth = {r.rid for r in pre if r.kind == "mislabeled"}
    assert len(flagged & truth) / len(flagged) >= 0.9  # precision
    assert len(flagged & truth) / len(truth) >= 0.8  # recall


# ---------------------------------------------------------------- impact on the trained model
def test_backdoor_flips_naive_router_but_not_hardened(evals):
    assert evals["naive"]["asr"] > 0.7
    assert evals["hardened"]["asr"] < 0.05


def test_naive_model_memory_returns_raw_pii_hardened_does_not(evals):
    assert evals["naive"]["probe_leaks"] >= 5
    assert evals["naive"]["pii_in_memory"] > 100
    assert evals["hardened"]["probe_leaks"] == 0
    assert evals["hardened"]["pii_in_memory"] == 0


def test_clean_held_out_accuracy_improves(evals):
    assert evals["hardened"]["clean_acc"] >= evals["naive"]["clean_acc"] + 0.03
    assert evals["hardened"]["clean_acc"] >= 0.97


def test_hardened_output_contains_only_clean_rows():
    assert {r.kind for r in HARD.records} == {"clean"}
    assert HARD.report["provenance"]["batches"]["B-community-upload"] == "unsigned manifest"


def test_manifest_detects_a_relabel_inside_a_signed_batch():
    b = S.batches[1]
    r = b.records[0]
    b2 = data.Batch(b.batch_id, b.source, b.licence, b.collector, [replace(r, label="technical" if r.label != "technical" else "fraud")] + b.records[1:])
    pr = hp.verify_provenance([b2], {b.batch_id: S.manifests[b.batch_id]}, S.key)
    assert (r.rid, "hash mismatch (edited after signing)") in pr.rejected
