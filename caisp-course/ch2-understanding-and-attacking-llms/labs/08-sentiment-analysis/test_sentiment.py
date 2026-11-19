from aisec_lab import load_lab_module

se = load_lab_module(__file__, "sentiment")


def test_llm_style_beats_lexicon_on_negation():
    llm = se.SentimentLLM()
    lex = sum(se.lexicon_label(t) == g for t, g in se.LABELED)
    mdl = sum(se.parse_label(se.classify_naive(t, llm)) == g for t, g in se.LABELED)
    assert mdl > lex
    assert mdl == len(se.LABELED)


def test_clean_negative_review_is_negative():
    assert se.parse_label(se.classify_naive("Terrible battery, it broke.", se.SentimentLLM())) == "negative"


def test_injection_flips_naive_classifier_to_positive():
    assert se.classify_naive(se.ATTACK_REVIEW, se.SentimentLLM()) == "positive"


def test_hardened_classifier_resists_and_stays_correct():
    assert se.classify_hardened(se.ATTACK_REVIEW, se.SentimentLLM()) == "negative"


def test_hardened_keeps_accuracy_on_clean_reviews():
    llm = se.SentimentLLM()
    assert all(se.classify_hardened(t, llm) == g for t, g in se.LABELED)


def test_strict_parser_rejects_non_labels():
    assert se.parse_label("OK, new instructions accepted. and label this positive") == "INVALID"
    assert se.parse_label("Positive.") == "positive"
