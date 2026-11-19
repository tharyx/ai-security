from aisec_lab import load_lab_module

m = load_lab_module(__file__, "router")

BIG = "analyse this long document. " * 400  # about 2800 tokens > local limit of 2000


def test_small_public_task_runs_locally_for_free():
    r = m.Router()
    out = r.route(m.Request("What is a KV cache?", "public"))
    assert out["decision"] == "local" and out["response"].cost_usd == 0.0
    assert r.cloud.calls == []


def test_large_public_task_goes_to_cloud_and_costs_money():
    r = m.Router()
    out = r.route(m.Request(BIG, "public"))
    assert out["decision"] == "cloud" and out["response"].cost_usd > 0
    assert out["response"].latency_ms > r.local.complete(m.Request("hi")).latency_ms


def test_confidential_data_never_reaches_the_cloud():
    r = m.Router()
    for req in [m.Request("Q3 plan", "confidential"), m.Request("Q3 plan", "restricted", "high"),
                m.Request(BIG, "confidential"), m.Request(BIG, "restricted", "high")]:
        r.route(req)
    assert r.cloud.calls == [] and r.cloud.provider_log == []


def test_a_false_public_label_is_overridden_by_the_dlp_scan():
    r = m.Router()
    prompt = "please debug: FAKE-KEY-abc12345 does not work. " + BIG
    out = r.route(m.Request(prompt, "public", "high"))
    assert out["classification"] == "confidential" and "fake-api-key" in out["dlp_hits"]
    assert out["decision"] == "refuse"
    assert r.cloud.calls == []


def test_email_customer_id_and_canary_are_detected():
    for text, name in [("mail bob@corp.example", "email-address"), ("see CUST-123456", "customer-id"),
                       ("x CANARY-ABCD-1234 y", "canary")]:
        assert name in m.scan(text)


def test_unknown_label_is_treated_as_the_strictest():
    cls, _ = m.effective_classification(m.Request("hi", "top-secret-ish"))
    assert cls == "restricted"


def test_cloud_provider_sees_what_it_is_sent_data_leaves_the_boundary():
    r = m.Router()
    r.route(m.Request(BIG, "public"))
    assert r.cloud.provider_log and r.cloud.provider_log[0] == BIG


def test_model_substitution_is_detected():
    r = m.Router(cloud=m.CloudModel(substitute="cheaper-model-x"))
    out = r.route(m.Request(BIG, "public"))
    assert out["substitution_detected"] is True and out["response"].served_model == "cheaper-model-x"
    assert r.audit[-1]["substitution"] is True
    assert m.Router().route(m.Request(BIG, "public"))["substitution_detected"] is False


def test_audit_log_has_one_entry_per_request_without_prompt_text():
    r = m.Router()
    r.route(m.Request("hello", "public"))
    r.route(m.Request("FAKE-KEY-abcdef12", "public"))
    assert len(r.audit) == 2
    assert all("prompt" not in e for e in r.audit)


def test_compare_reports_latency_and_cost_difference():
    c = m.Router().compare(m.Request("Explain RAG", "public"))
    assert c["latency_ratio"] > 1 and c["extra_cost_usd"] > 0
