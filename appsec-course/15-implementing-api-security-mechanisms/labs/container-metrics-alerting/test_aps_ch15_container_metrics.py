from pathlib import Path

import pytest
from aisec_lab import load_lab_module

m = load_lab_module(__file__, "metrics_alerts")
FX = Path(__file__).resolve().parent / "fixtures"
PREV, CUR = m.load(FX / "scrape_t0.prom"), m.load(FX / "scrape_t1.prom")
ALERTS = m.evaluate(PREV, CUR)


def has(rule, container):
    return any(a.rule == rule and a.container == container for a in ALERTS)


def test_exposition_parser_reads_labels_and_values():
    cpu = m.by_container(CUR, "container_cpu_usage_seconds_total")
    assert cpu["worker"] == 350 and m.labels_of(CUR)["postgres"]["container_label_egress"] == "none"


def test_cryptominer_like_cpu_spike_is_flagged():
    assert has("CPUAnomaly", "worker") and has("HighCPU", "worker")
    assert not has("CPUAnomaly", "orders-api")


def test_database_exfiltration_raises_unexpected_egress():
    assert has("UnexpectedEgress", "postgres")
    assert not has("UnexpectedEgress", "orders-api")  # egress allowed for this service


def test_memory_pressure_and_missing_limits():
    assert has("MemoryNearLimit", "postgres") and has("NoMemoryLimit", "cache")


def test_restart_new_and_gone_containers():
    assert has("ContainerRestarted", "payments")
    assert has("NewContainer", "debug-shell") and has("ContainerGone", "legacy-cron")


def test_counter_reset_after_restart_does_not_create_false_cpu_alert():
    assert not has("HighCPU", "payments")


def test_bad_exposition_line_is_rejected():
    with pytest.raises(ValueError):
        m.parse_exposition("container_cpu_usage_seconds_total{name=\"x\"} notanumber")


def test_dashboard_has_a_row_per_container():
    d = m.dashboard(PREV, CUR)
    assert len(d.splitlines()) == 1 + len(m.by_container(CUR, "container_cpu_usage_seconds_total"))
