from aisec_lab import MockLLM, load_lab_module

rag = load_lab_module(__file__, "rag")


def build():
    r = rag.RagSystem(MockLLM())
    r.ingest(rag.SAMPLE_DOCS)
    return r


def test_chunking_overlaps_and_ids_are_stable():
    text = " ".join(f"w{i}" for i in range(100))
    chunks = rag.chunk_document("d", text, max_words=40, overlap=10)
    assert [c.id for c in chunks] == ["d#0", "d#1", "d#2"]
    assert chunks[0].text.split()[-10:] == chunks[1].text.split()[:10]


def test_embedding_similarity_orders_relevant_first():
    r = build()
    hits = r.retrieve("how many vacation days per year")
    assert hits[0][0].source == "vacation-policy"


def test_answer_cites_the_right_source():
    a = build().ask("How do I connect to the VPN?")
    assert "vpn-guide#0" in a.citations
    assert "Sources: [vpn-guide#0]" in a.text and "VPN" in a.text


def test_unrelated_question_gets_idk_and_no_llm_call():
    llm = MockLLM()
    r = rag.RagSystem(llm)
    r.ingest(rag.SAMPLE_DOCS)
    a = r.ask("Who won the football match?")
    assert a.citations == [] and "don't know" in a.text
    assert llm.calls == []


def test_only_top_k_chunks_reach_the_prompt():
    llm = MockLLM()
    r = rag.RagSystem(llm, top_k=1)
    r.ingest(rag.SAMPLE_DOCS)
    r.ask("meal limit for travel expenses")
    prompt = llm.calls[0][-1]["content"]
    assert "expense-policy" in prompt and "vpn-guide" not in prompt
