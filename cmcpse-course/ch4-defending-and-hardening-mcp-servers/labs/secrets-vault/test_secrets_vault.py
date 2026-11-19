"""Tests for the mock vault and the vault-backed MCP server. Run: python -m pytest cmcpse-course/ch4-defending-and-hardening-mcp-servers

Each test starts a mock vault on 127.0.0.1 with a free port and stops it afterwards. No network, no real Vault.
"""

from __future__ import annotations

import contextlib
import json
import os

import pytest

from aisec_lab import load_lab_module

mv = load_lab_module(__file__, "mock_vault")
vs = load_lab_module(__file__, "vault_mcp_server")

PARTNER_KEY = "pk-live-4f9a7c2e1b"


class Clock:
    t = 5_000_000.0

    def __call__(self):
        return self.t


@contextlib.contextmanager
def env(secret_id="s3cr3t-id-1", uses=0):
    clock = Clock()
    vault = mv.MockVault(now=clock)
    vault.add_policy("mcp-reporting", read_kv=["partner"], db_roles=["reporting"])
    vault.add_policy("other", read_kv=["unrelated"])
    vault.add_approle("report-server", secret_id, ["mcp-reporting"], token_ttl=300, secret_id_uses=uses)
    vault.add_approle("nosy", "nosy-secret", ["other"])
    vault.put_kv("partner", {"api_key": PARTNER_KEY})
    vault.put_kv("unrelated", {"x": "y"})
    addr = vault.start()
    redact = vs.Redactor()
    client = vs.VaultClient(addr, "report-server", secret_id, redact, now=clock)
    server = vs.SecretsServer(client, vault.db_login_ok, lambda k: vault.partner_key_ok("partner", k), now=clock)
    try:
        yield clock, vault, client, server, addr
    finally:
        vault.stop()


def call(server, name, **args):
    return server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}})


def text(resp):
    return resp["result"]["content"][0]["text"]


def test_approle_login_gives_a_scoped_short_lived_token():
    with env() as (clock, vault, client, server, addr):
        client.login()
        assert client.token.startswith("hvs.")
        assert vault.tokens[client.token]["policies"] == ["mcp-reporting"]
        assert vault.tokens[client.token]["expires"] - clock.t == 300


def test_wrong_secret_id_is_refused_and_the_error_has_no_details():
    with env() as (_, _, _, _, addr):
        bad = vs.VaultClient(addr, "report-server", "wrong", vs.Redactor())
        with pytest.raises(vs.VaultError) as e:
            bad.login()
        assert str(e.value) == "vault returned 403"


def test_one_time_secret_id_cannot_be_replayed():
    with env(secret_id="once-only-1234", uses=1) as (_, _, client, _, addr):
        client.login()
        replay = vs.VaultClient(addr, "report-server", "once-only-1234", vs.Redactor())
        with pytest.raises(vs.VaultError):
            replay.login()
        assert client._secret_id is None          # the client dropped its bootstrap secret


def test_policies_limit_what_a_token_can_read():
    with env() as (_, _, _, _, addr):
        nosy = vs.VaultClient(addr, "nosy", "nosy-secret", vs.Redactor())
        assert nosy.kv("unrelated") == {"x": "y"}
        with pytest.raises(vs.VaultError):
            nosy.kv("partner")
        with pytest.raises(vs.VaultError):
            nosy.db_creds("reporting")


def test_tools_list_contains_no_secret_and_environment_is_clean():
    with env() as (_, _, client, server, _):
        call(server, "sync_partner")
        call(server, "run_report", month="2026-10")
        listing = json.dumps(server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
        for secret in (PARTNER_KEY, client.token):
            assert secret not in listing
        assert all(PARTNER_KEY not in v for v in os.environ.values())
        assert all(client.token not in v for v in os.environ.values())


def test_tools_work_with_dynamic_credentials_and_static_key():
    with env() as (_, _, _, server, _):
        assert "generated as v-" in text(call(server, "run_report", month="2026-10"))
        assert text(call(server, "sync_partner")) == "catalogue synchronised"


def test_logs_never_contain_secret_values():
    with env() as (_, vault, client, server, _):
        call(server, "sync_partner")
        call(server, "run_report", month="2026-10")
        server._log(f"debug: using key {PARTNER_KEY} and token {client.token} password=hunter2hunter2")
        joined = "\n".join(server.log)
        assert PARTNER_KEY not in joined and client.token not in joined and "hunter2" not in joined
        pw = server._creds["password"]
        server._log(f"connecting with {pw}")
        assert pw not in "\n".join(server.log)
        assert "[REDACTED]" in joined


def test_credentials_are_cached_until_shortly_before_the_lease_ends_then_replaced():
    with env() as (clock, vault, _, server, _):
        call(server, "run_report", month="a")
        call(server, "run_report", month="b")
        assert server.fetches == 1                       # cached
        clock.t += 100                                   # 120s lease * 0.8 = 96s: time to renew early
        call(server, "run_report", month="c")
        assert server.fetches == 2


def test_expired_lease_means_the_database_rejects_old_credentials():
    with env() as (clock, vault, _, server, _):
        call(server, "run_report", month="a")
        old = dict(server._creds)
        clock.t += 130
        assert not vault.db_login_ok(old["username"], old["password"])


def test_revoked_lease_is_detected_and_the_server_recovers_with_new_credentials():
    with env() as (_, vault, client, server, _):
        call(server, "run_report", month="a")
        first_user = server._creds["username"]
        lease_id = next(iter(vault.leases))
        client.revoke(lease_id)                           # operator revokes after an incident
        out = text(call(server, "run_report", month="b"))
        assert first_user not in out and "generated as v-" in out
        assert server.fetches == 2


def test_static_secret_rotation_takes_effect_on_the_next_call_and_old_key_dies():
    with env() as (_, vault, _, server, _):
        assert text(call(server, "sync_partner")) == "catalogue synchronised"
        vault.rotate_kv("partner", {"api_key": "pk-live-NEW-9d8c7b6a"})
        assert not vault.partner_key_ok("partner", PARTNER_KEY)
        assert text(call(server, "sync_partner")) == "catalogue synchronised"      # server re-read the vault
        assert vault.kv_version["partner"] == 2


def test_token_expiry_triggers_relogin_only_if_a_secret_id_is_available():
    with env() as (clock, _, client, server, _):
        call(server, "sync_partner")
        clock.t += 400                                    # the vault token expired; the secret ID was dropped
        out = call(server, "sync_partner")
        assert out["result"]["isError"] is True
        assert text(out) == "Secret backend unavailable. Try again later."
        # In production use a renewable token or a re-fetchable (wrapped) secret ID, or a platform identity (OIDC).


def test_vault_down_fails_closed_without_leaking_anything():
    with env() as (_, vault, client, server, _):
        call(server, "sync_partner")
        vault.stop()
        out = call(server, "sync_partner")
        assert out["result"]["isError"] is True
        assert PARTNER_KEY not in json.dumps(out) and client.token not in json.dumps(out)
        assert any("vault unreachable" in line for line in server.log)


def test_unexpected_exception_text_is_not_returned_to_the_model():
    with env() as (_, _, _, server, _):
        server.partner_api = lambda k: (_ for _ in ()).throw(RuntimeError(f"boom with key {k}"))
        out = call(server, "sync_partner")
        assert text(out) == "Internal error."
        assert PARTNER_KEY not in "\n".join(server.log)


def test_redactor_patterns():
    r = vs.Redactor()
    assert r("api_key=abc123") == "api_key=[REDACTED]"
    assert "hvs.abcdefghij" not in r("token hvs.abcdefghij")
    r.register("topsecretvalue")
    assert r("x topsecretvalue y") == "x [REDACTED] y"
