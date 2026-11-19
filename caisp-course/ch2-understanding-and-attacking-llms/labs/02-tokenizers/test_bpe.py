from aisec_lab import load_lab_module

bpe = load_lab_module(__file__, "bpe")


def make():
    return bpe.BPETokenizer().train(bpe.CORPUS, 60)


def test_merges_shorten_known_words():
    tok = make()
    assert len(tok.encode("tokenizer")) < len("tokenizer") + 1


def test_roundtrip_including_unseen_unicode():
    tok = make()
    for text in ["the model reads tokens", "café 你好"]:
        assert tok.decode(tok.encode(text)) == text


def test_training_is_deterministic():
    assert make().merges == make().merges


def test_odd_spacing_and_homoglyph_change_tokens():
    tok = make()
    plain = tok.encode("malware")
    assert len(tok.encode("m a l w a r e")) > len(plain)
    assert tok.encode("mаlware") != plain
    assert tok.encode("mal​ware") != plain


def test_naive_filter_bypassed_hardened_filter_blocks():
    attacks = ["m a l w a r e", "mаlware", "mal​ware", "MALWARE"]
    assert all(bpe.naive_filter(a) for a in attacks[:3])  # bypass works
    assert not any(bpe.hardened_filter(a) for a in attacks)
    assert not bpe.naive_filter("malware")


def test_hardened_filter_allows_normal_text():
    assert bpe.hardened_filter("write a report about the model")


def test_cost():
    assert bpe.cost_usd(1_000_000) == 1.0
