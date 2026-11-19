from aisec_lab import MockLLM, load_lab_module

sm = load_lab_module(__file__, "summarizer")
docs = load_lab_module(__file__, "documents")


def test_chunking_covers_text_and_respects_limit():
    chunks = sm.chunk_text(docs.CLEAN, max_words=30)
    assert len(chunks) > 1
    assert all(len(c.split()) <= 45 for c in chunks)
    assert "Hiring will focus" in chunks[-1]


def test_map_reduce_makes_one_call_per_chunk_plus_reduce():
    llm = MockLLM()
    s = sm.Summarizer(llm, max_words=30)
    n = len(sm.chunk_text(docs.CLEAN, 30))
    out = s.summarize(docs.CLEAN)
    assert len(llm.calls) == n + 1
    assert out.startswith("Summary:")


def test_indirect_injection_hijacks_unprotected_summary():
    out = sm.Summarizer(MockLLM(), max_words=30).summarize(docs.POISONED)
    assert docs.CANARY in out


def test_spotlighting_stops_the_hijack():
    s = sm.Summarizer(MockLLM(), spotlight=True, max_words=30)
    out = s.summarize(docs.POISONED)
    assert docs.CANARY not in out
    assert "^" not in out


def test_spotlighting_keeps_normal_summary_working():
    out = sm.Summarizer(MockLLM(), spotlight=True, max_words=30).summarize(docs.CLEAN)
    assert out.startswith("Summary:") and "Revenue" in out


def test_detector_flags_poisoned_not_clean():
    assert sm.flag_injection(docs.POISONED)
    assert not sm.flag_injection(docs.CLEAN)


def test_datamark_roundtrip():
    assert sm.unmark(sm.datamark("a b c")) == "a b c"
