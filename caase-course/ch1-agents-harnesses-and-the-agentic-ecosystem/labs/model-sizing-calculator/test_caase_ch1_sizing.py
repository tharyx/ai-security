import pytest

from aisec_lab import load_lab_module

s = load_lab_module(__file__, "sizing")


def test_weights_scale_with_quantization():
    assert s.weights_gb(7, "FP16") == pytest.approx(14.0)
    assert s.weights_gb(7, "Q4") < s.weights_gb(7, "Q8") < s.weights_gb(7, "FP16")


def test_kv_cache_formula_known_value():
    # 2 * 28 layers * 8 kv heads * 128 dim * 8192 tokens * 2 bytes
    assert s.kv_cache_gb(28, 8, 128, 8192) == pytest.approx(0.9395, abs=1e-3)


def test_kv_cache_grows_linearly_with_context():
    a = s.memory_needed_gb("8B", "Q4", 4096)["kv_gb"]
    b = s.memory_needed_gb("8B", "Q4", 8192)["kv_gb"]
    assert b == pytest.approx(2 * a)


def test_total_is_the_sum_of_parts():
    m = s.memory_needed_gb("14B", "Q8", 8192)
    assert m["total_gb"] == pytest.approx(m["weights_gb"] + m["kv_gb"] + m["overhead_gb"])


def test_learner_laptop_fits_small_models_and_not_70b():
    hw = s.LEARNER_LAPTOP
    assert hw.vram_gb == 0 and hw.ram_gb == 16
    assert s.recommend("3B", "Q4", 8192, hw)["where"] == "local-cpu"
    assert s.recommend("7B", "Q4", 8192, hw)["where"] == "local-cpu"
    assert s.recommend("70B", "Q4", 8192, hw)["where"] == "cloud"
    assert s.recommend("14B", "Q8", 8192, hw)["where"] == "cloud"  # about 16 GB: too big


def test_gpu_is_used_when_the_model_fits_vram():
    hw = s.Hardware(ram_gb=32, vram_gb=12)
    r = s.recommend("7B", "Q4", 8192, hw)
    assert r["where"] == "local-gpu" and r["est_tokens_per_s"] > s.recommend("7B", "Q4", 8192, s.LEARNER_LAPTOP)["est_tokens_per_s"]


def test_confidential_data_never_recommends_cloud():
    r = s.recommend("70B", "Q4", 8192, s.LEARNER_LAPTOP, data_classification="confidential")
    assert r["where"] == "blocked-needs-private-deployment"
    assert s.recommend("70B", "Q4", 8192, s.LEARNER_LAPTOP, data_classification="public")["where"] == "cloud"


def test_large_models_are_flagged_slow_or_tight_on_cpu():
    r = s.recommend("7B", "Q4", 8192, s.Hardware(ram_gb=12))  # budget 6 GB, needs about 5.96 GB
    assert r["where"] == "local-cpu" and "tight" in r["note"]
    assert s.recommend("14B", "Q4", 8192, s.LEARNER_LAPTOP)["where"] == "cloud"  # about 10.8 GB


def test_long_context_can_push_a_model_out_of_memory():
    assert s.recommend("8B", "Q4", 8192, s.LEARNER_LAPTOP)["where"] == "local-cpu"
    assert s.recommend("8B", "Q4", 400_000, s.LEARNER_LAPTOP)["where"] == "cloud"


def test_table_has_all_sizes_and_quants():
    rows = s.sizing_table()
    assert [r["size"] for r in rows] == ["1B", "3B", "7B", "8B", "14B", "70B"]
    assert all(r["Q4"] < r["Q8"] < r["FP16"] for r in rows)
