"""Encoding, multi-language and refusal-suppression demo."""

from aisec_lab import load_lab_module

e = load_lab_module(__file__, "encodings")


def test_naive_detector_only_sees_the_plain_english_phrase():
    hits = {name for name, text in e.VARIANTS.items() if e.naive_detect(text)}
    assert hits == {"plain"}


def test_normalizer_undoes_base64_homoglyphs_and_zero_width():
    for name in ("base64", "homoglyph", "zero-width"):
        assert "ignore previous instructions" in e.normalize(e.VARIANTS[name]).lower(), name


def test_normalising_detector_catches_all_but_the_unknown_language():
    caught = {name for name, text in e.VARIANTS.items() if e.detect(text)}
    assert caught == set(e.VARIANTS) - {"polish (not in table)"}


def test_translated_phrase_has_its_own_reason_code():
    assert e.detect(e.VARIANTS["german"]) == ["override-phrase-translated"]


def test_unknown_language_is_a_documented_gap():
    assert e.detect(e.TRANSLATIONS["pl"]) == []  # why a detector is one layer, not the defence


def test_refusal_suppression_is_flagged():
    assert e.detect(e.SUPPRESSION) == ["refusal-suppression"]
    assert e.detect("Please summarise the quarterly report.") == []


def test_benign_base64_is_not_a_false_positive():
    assert e.detect("token: " + e.b64("hello world, this is fine")) == []


def test_homoglyph_text_is_visibly_identical_but_not_equal():
    h = e.homoglyph(e.PHRASE)
    assert h != e.PHRASE and len(h) == len(e.PHRASE)
