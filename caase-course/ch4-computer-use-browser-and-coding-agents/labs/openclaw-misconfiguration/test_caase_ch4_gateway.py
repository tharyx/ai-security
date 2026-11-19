"""Tests for the simulated gateway misconfiguration lab."""

import http.client

import pytest

from aisec_lab import load_lab_module

g = load_lab_module(__file__, "sim_gateway")
a = load_lab_module(__file__, "auditor")


def ids(findings):
    return {f["id"] for f in findings}


def test_insecure_config_has_every_static_finding():
    assert ids(a.audit_config(g.INSECURE_CONFIG)) == {"GW-BIND", "GW-AUTH", "GW-ORIGIN", "GW-TOKEN-EXPOSED", "GW-VERSION"}


def test_hardened_config_is_clean():
    assert a.audit_config(g.HARDENED_CONFIG) == []


@pytest.mark.parametrize("override,expected", [
    ({"bind": "0.0.0.0"}, "GW-BIND"),
    ({"auth_token": None}, "GW-AUTH"),
    ({"allowed_origins": ["*"]}, "GW-ORIGIN"),
    ({"expose_token_in_api": True}, "GW-TOKEN-EXPOSED"),
    ({"version": "2026.1.0"}, "GW-VERSION"),
])
def test_each_single_flaw_is_detected(override, expected):
    cfg = {**g.HARDENED_CONFIG, **override}
    assert expected in ids(a.audit_config(cfg))


def test_patched_version_constants_agree():
    assert a.PATCHED_VERSION == g.PATCHED_VERSION


def test_server_always_binds_loopback_even_if_config_says_all_interfaces():
    with g.SimGateway(g.INSECURE_CONFIG) as gw:
        assert gw.httpd.server_address[0] == "127.0.0.1"


def test_insecure_gateway_leaks_token_to_foreign_origin():
    with g.SimGateway(g.INSECURE_CONFIG) as gw:
        found = ids(a.probe_gateway(gw.port))
    assert {"PROBE-NOAUTH", "PROBE-CROSS-ORIGIN", "PROBE-TOKEN-LEAK"} <= found


def test_hardened_gateway_blocks_all_probes():
    with g.SimGateway(g.HARDENED_CONFIG) as gw:
        assert a.probe_gateway(gw.port) == []


def test_hardened_gateway_still_serves_the_owner():
    with g.SimGateway(g.HARDENED_CONFIG) as gw:
        c = http.client.HTTPConnection("127.0.0.1", gw.port, timeout=5)
        c.request("GET", "/api/tools", headers={"Authorization": f"Bearer {g.FAKE_TOKEN}"})
        assert c.getresponse().status == 200
        c.close()


def test_origin_check_alone_is_not_enough_without_auth():
    cfg = {**g.HARDENED_CONFIG, "auth_token": None}
    assert "GW-AUTH" in ids(a.audit_config(cfg))
    with g.SimGateway(cfg) as gw:
        assert "PROBE-NOAUTH" in ids(a.probe_gateway(gw.port))


def test_server_is_stopped_after_context_exit():
    with g.SimGateway(g.HARDENED_CONFIG) as gw:
        port = gw.port
    with pytest.raises(OSError):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
        c.request("GET", "/")
        c.getresponse()
