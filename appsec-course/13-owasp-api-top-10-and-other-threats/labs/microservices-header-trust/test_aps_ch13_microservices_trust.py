from aisec_lab import load_lab_module

m = load_lab_module(__file__, "mesh")
ALICE = m.login("alice")


def test_spoofed_x_user_id_reads_other_users_order_only_when_vulnerable():
    h = {"Cookie": ALICE, "X-User-Id": "bob"}
    assert m.gateway(h, "/orders/o-2", secure=False)[1]["total"] == 9900
    assert m.gateway(h, "/orders/o-2", secure=True)[0] == 404


def test_direct_call_to_internal_service_needs_signed_token_when_secure():
    assert m.orders_service({"X-User-Id": "bob"}, "o-2", secure=False)[0] == 200
    assert m.orders_service({"X-User-Id": "bob"}, "o-2", secure=True)[0] == 401


def test_xff_spoofing_reaches_admin_console_only_when_vulnerable():
    h = {"Cookie": ALICE, "X-Forwarded-For": "10.0.0.1"}
    assert m.gateway(h, "/admin", secure=False)[0] == 200
    assert m.gateway(h, "/admin", secure=True)[0] == 403


def test_secure_gateway_still_serves_legit_requests():
    assert m.gateway({"Cookie": ALICE}, "/orders/o-1", secure=True)[0] == 200


def test_internal_token_checks_audience_expiry_and_signature():
    t = m.mint_internal("alice", "orders", ttl=30, now=1000)
    assert m.verify_internal(t, "orders", now=1010) == "alice"
    assert m.verify_internal(t, "payments", now=1010) is None
    assert m.verify_internal(t, "orders", now=1031) is None
    assert m.verify_internal(t.replace("alice", "bob"), "orders", now=1010) is None


def test_trusted_proxy_count_picks_right_most_untrusted_address():
    assert m.client_ip({"X-Forwarded-For": "10.0.0.1, 198.51.100.9"}, "172.16.0.2", secure=True) == "198.51.100.9"
    assert m.client_ip({"X-Forwarded-For": "10.0.0.1, 198.51.100.9"}, "172.16.0.2", secure=False) == "10.0.0.1"
