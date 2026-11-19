from aisec_lab import load_lab_module

t = load_lab_module(__file__, "throttle")
BURST = [59 + i / 10 for i in range(10)] + [60 + i / 10 for i in range(10)]


def test_fixed_window_allows_double_burst_at_boundary():
    assert t.accepted_in(t.FixedWindow(10, 60), BURST) == 20


def test_sliding_window_log_holds_the_limit_across_the_boundary():
    assert t.accepted_in(t.SlidingWindowLog(10, 60), BURST) == 10


def test_sliding_counter_and_token_bucket_stay_close_to_the_limit():
    assert t.accepted_in(t.SlidingWindowCounter(10, 60), BURST) <= 11
    assert t.accepted_in(t.TokenBucket(10, 10 / 60), BURST) == 10


def test_token_bucket_refills_over_time():
    b = t.TokenBucket(2, 1)
    assert [b.allow("k", 0)[0] for _ in range(3)] == [True, True, False]
    assert b.allow("k", 1.0)[0]


def test_429_has_retry_after_and_limit_headers():
    status, h = t.http_response(False, 12.3, 10)
    assert status == 429 and h["Retry-After"] == "13" and h["RateLimit-Remaining"] == "0"


def test_throttler_delays_then_rejects():
    th = t.Throttler(2, 2.0)
    res = [th.submit("c", 0.0) for _ in range(8)]
    assert [s for s, _ in res].count(200) == 5 and res[4] == (200, 2.0)
    assert res[5][0] == 429


def test_single_ip_flood_is_stopped_at_the_reverse_proxy():
    edge = t.LayeredEdge()
    out = [edge.handle(t.Request("198.51.100.9", "/p", "k"), i * 0.1)[1] for i in range(100)]
    assert out.count("ok") <= 30 and edge.stage_hits["reverse-proxy"] >= 70


def test_waf_blocks_injection_before_the_app():
    edge = t.LayeredEdge()
    assert edge.handle(t.Request("1.2.3.4", "/s", "k", body="id=1'; DROP TABLE x"), 0)[0] == 403


def test_distributed_password_spray_passes_edge_but_app_limits_the_account():
    edge = t.LayeredEdge()
    out = [edge.handle(t.Request(f"203.0.113.{i}", "/login", f"k{i}", account="cfo"), float(i)) for i in range(40)]
    assert sum(1 for s, _ in out if s == 200) == 5
    assert edge.stage_hits["application"] == 35 and edge.stage_hits["reverse-proxy"] == 0


def test_load_balancer_protects_pool_capacity_from_botnet():
    edge = t.LayeredEdge()
    out = [edge.handle(t.Request(f"10.0.{i // 250}.{i % 250}", "/p", f"b{i}"), 5.0)[0] for i in range(1000)]
    assert out.count(503) == 800
