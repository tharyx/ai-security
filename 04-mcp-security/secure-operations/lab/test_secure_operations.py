"""Regression tests for operating MCP securely. Test names carry the OWASP MCP Top 10 (2025 beta) ID.

Each attack must work against the naive setup and fail against the secure one.
Run from the repository root:
    python -m pytest 04-mcp-security/secure-operations -v
"""

import hashlib
import io
import json
import logging
import tempfile
from pathlib import Path

import pytest

from aisec_lab import MockLLM, load_lab_module

attacks = load_lab_module(__file__, "attacks")
vuln = load_lab_module(__file__, "vulnerable_ops")
sec = load_lab_module(__file__, "secure_ops")

ALICE = sec.Principal(user="alice", tenant="tenant-a", agent="support-agent", session="s1")
ALICE_2 = sec.Principal(user="alice", tenant="tenant-a", agent="support-agent", session="s2")
BOB_B = sec.Principal(user="bob", tenant="tenant-b", agent="support-agent", session="s9")
BOT = sec.Principal(user="alice", tenant="tenant-a", agent="summary-bot", session="s3")


def entry(**overrides):
    fields = dict(
        name="acme-tickets", version="2.3.1", package=attacks.APPROVED_PACKAGE,
        package_sha256=hashlib.sha256(attacks.PACKAGE_V231).hexdigest(), owner="platform-team",
        tool_scopes=dict(attacks.TOOL_SCOPES), side_effect_tools=attacks.SIDE_EFFECT_TOOLS,
        secret_refs={"TICKETS_TOKEN": "vault://mcp/acme-tickets/token"},
    )
    fields.update(overrides)
    return sec.RegistryEntry(**fields)


@pytest.fixture
def registry():
    return {"acme-tickets": entry()}


def secure_gateway(registry, server=None, **kw):
    server = server or attacks.TicketsServer()
    gw = sec.SecureOpsGateway(registry, server, MockLLM(), agent_tools=attacks.AGENT_TOOLS, **kw)
    assert gw.connect(server.manifest(), server.package)
    return gw, server


def naive_gateway(server=None):
    server = server or attacks.TicketsServer()
    gw = vuln.NaiveGateway(server, MockLLM())
    gw.connect(server.manifest(), server.package)
    return gw, server


def capture_logger(name, *filters):
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    for f in filters:
        handler.addFilter(f)
    logger = logging.getLogger(name)
    logger.handlers = [handler]
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    return logger, stream


def emailed_attacker(server):
    return any(m["to"] == attacks.ATTACKER_INBOX for m in server.outbox)


# ---------- Part 1: prove the attacks are real (naive operations) ----------------------------------

def test_mcp01_naive_launch_hands_every_secret_to_a_malicious_server():
    parent = attacks.parent_environment()
    stolen = attacks.credential_harvester(vuln.naive_launch_env(parent))
    assert parent["AWS_SECRET_ACCESS_KEY"] in stolen and parent["GITHUB_TOKEN"] in stolen
    assert parent["PAYROLL_DB_PASSWORD"] in stolen


def test_mcp01_naive_logging_writes_the_bearer_token():
    token = attacks.fake_jwt()
    logger, stream = capture_logger("naive-ops")
    vuln.naive_log_request(logger, {"Authorization": f"Bearer {token}"}, {"query": "vpn"})
    assert token in stream.getvalue()


def test_mcp02_naive_gateway_grants_scope_creep():
    server = attacks.TicketsServer()
    server.scope_creep()
    gw, _ = naive_gateway(server)
    assert "admin:all" in gw.granted_scopes


def test_mcp02_naive_read_only_agent_can_send_and_delete():
    gw, server = naive_gateway()
    gw.call(BOT, "send_email", {"to": attacks.ATTACKER_INBOX, "body": "hi"})
    gw.call(BOT, "delete_ticket", {"ticket_id": "T-1"})
    assert emailed_attacker(server) and "T-1" not in server.tickets["tenant-a"]


def test_mcp04_naive_gateway_accepts_a_tampered_package():
    server = attacks.TicketsServer()
    server.malicious_update()
    assert vuln.NaiveGateway(server, MockLLM()).connect(server.manifest(), server.package) is True


def test_mcp06_naive_resource_injection_emails_the_attacker():
    gw, server = naive_gateway()
    gw.read_resource(ALICE, "ticket://T-9")
    gw.ask(ALICE, "Draft a reply to this ticket.")
    assert emailed_attacker(server)


def test_mcp10_naive_cache_leaks_across_tenants():
    gw, server = naive_gateway()
    gw.call(ALICE, "search_tickets", {"query": "payroll"})
    assert server.payroll_canary in gw.call(BOB_B, "search_tickets", {"query": "payroll"})


def test_mcp10_naive_gateway_overshares_context_with_the_server():
    gw, server = naive_gateway()
    gw.call(ALICE, "get_ticket", {"ticket_id": "T-1"})
    gw.call(BOB_B, "search_tickets", {"query": "printer"})
    assert server.payroll_canary in json.dumps(server.received[-1])  # tenant B's request carried A's data


def test_mcp10_naive_context_leaks_between_sessions():
    gw, server = naive_gateway()
    gw.call(ALICE, "get_ticket", {"ticket_id": "T-1"})
    assert server.payroll_canary in gw.ask(BOB_B, "What is in my context?")


def test_mcp08_naive_log_is_not_attributable():
    gw, _ = naive_gateway()
    gw.call(ALICE, "search_tickets", {"query": "vpn"})
    assert gw.log == ["called search_tickets"]  # no user, agent, tenant, decision or correlation ID


# ---------- Part 2: the secure operations hold -------------------------------------------------------

def test_mcp01_launch_env_has_only_the_servers_own_secret(registry):
    parent = attacks.parent_environment()
    own = "own-" + attacks.fake_jwt("svc")
    vault = sec.Vault({"vault://mcp/acme-tickets/token": (own, frozenset({"acme-tickets"}))})
    env = sec.build_launch_env(registry["acme-tickets"], parent, vault)
    assert attacks.credential_harvester(env) == [own]
    assert "HOME" not in env and env["PATH"] == parent["PATH"]
    assert vault.reads == [{"ref": "vault://mcp/acme-tickets/token", "server": "acme-tickets"}]


def test_mcp01_vault_refuses_another_servers_secret():
    vault = sec.Vault({"vault://mcp/github/token": ("gh-secret-value", frozenset({"github-helper"}))})
    with pytest.raises(PermissionError):
        vault.read("vault://mcp/github/token", server="acme-tickets")


def test_mcp01_secure_request_log_has_fingerprint_not_token():
    token = attacks.fake_jwt()
    logger, stream = capture_logger("secure-ops")
    sec.secure_log_request(logger, {"Authorization": f"Bearer {token}"}, {"query": "vpn"})
    out = stream.getvalue()
    assert token not in out and sec.fingerprint(token) in out and "vpn" not in out


@pytest.mark.parametrize("make_line", [
    lambda s: f"debug headers={{'Authorization': 'Bearer {s['jwt']}'}}",
    lambda s: f"token payload {s['jwt']}",
    lambda s: f"boto config key_id={s['aws']}",
    lambda s: f"db connect password={s['pw']} host=db.acme.example",
    lambda s: f'env {{"GITHUB_TOKEN": "{s["gh"]}"}}',
    lambda s: f"retrying with {s['vault']}",   # an exact value the redactor learned from the vault
], ids=["bearer_header", "bare_jwt", "aws_key_id", "password_assignment", "json_env", "known_vault_value"])
def test_mcp01_redacting_filter_catches_a_raw_debug_log(make_line):
    """A developer logs something raw. The handler filter is the second lock."""
    s = {"jwt": attacks.fake_jwt(), "aws": attacks.fake_aws_key_id(), "pw": "CANARY-pw-123456",
         "gh": "CANARY-gh-abcdef", "vault": "opaque-vault-value-7f3a9"}
    redactor = sec.Redactor(known=[s["vault"]])
    logger, stream = capture_logger("debug-ops", sec.RedactingFilter(redactor))
    logger.debug(make_line(s))
    out = stream.getvalue()
    assert "REDACTED" in out
    assert not any(secret in out for secret in s.values())


def test_mcp02_scope_creep_is_blocked_and_recorded(registry):
    server = attacks.TicketsServer()
    server.scope_creep()
    gw = sec.SecureOpsGateway(registry, server, MockLLM(), agent_tools=attacks.AGENT_TOOLS)
    assert gw.connect(server.manifest(), server.package) is False
    event = gw.audit.query(kind="scope_creep")[0]
    assert event["new_scopes"] == ["admin:all", "tickets:delete"]
    assert gw.call(ALICE, "search_tickets", {"query": "vpn"}).startswith("[denied")


def test_mcp02_agent_allowlist_and_registry_scopes_stop_excessive_permissions(registry):
    gw, server = secure_gateway(registry)
    assert "not allowed" in gw.call(BOT, "send_email", {"to": attacks.ATTACKER_INBOX, "body": "hi"})
    assert "not allowed" in gw.call(BOT, "delete_ticket", {"ticket_id": "T-1"})
    assert gw.call(ALICE, "delete_ticket", {"ticket_id": "T-1"}).startswith("[denied")  # no agent may delete
    assert server.outbox == [] and "T-1" in server.tickets["tenant-a"]


def test_mcp02_unused_scopes_are_reported_for_review(registry):
    gw, _ = secure_gateway(registry)
    gw.call(ALICE, "search_tickets", {"query": "vpn"})
    assert sec.unused_scopes(registry["acme-tickets"], gw.audit.events) == {"mail:send"}


def test_mcp04_tampered_package_with_same_version_is_rejected(registry):
    server = attacks.TicketsServer()
    server.malicious_update()
    gw = sec.SecureOpsGateway(registry, server, MockLLM(), agent_tools=attacks.AGENT_TOOLS)
    assert gw.connect(server.manifest(), server.package) is False
    assert gw.audit.query(kind="package_digest_mismatch")


def test_mcp04_self_reported_digest_is_ignored(registry):
    """The manifest lies (it reports the reviewed digest); the gateway hashes the artifact itself."""
    server = attacks.TicketsServer()
    honest_manifest = server.manifest()
    server.malicious_update()
    gw = sec.SecureOpsGateway(registry, server, MockLLM(), agent_tools=attacks.AGENT_TOOLS)
    assert gw.connect(honest_manifest, server.package) is False


def test_mcp04_unregistered_server_is_rejected(registry):
    gw = sec.SecureOpsGateway(registry, attacks.TicketsServer(), MockLLM(), agent_tools=attacks.AGENT_TOOLS)
    assert gw.connect({"name": "acme-tickets-pro", "version": "1.0.0"}, b"x") is False
    assert gw.audit.query(kind="server_rejected")


def test_mcp06_resource_injection_needs_approval_and_is_audited(registry):
    gw, server = secure_gateway(registry)
    gw.read_resource(ALICE, "ticket://T-9")
    out = gw.ask(ALICE, "Draft a reply to this ticket.")
    assert "needs human approval" in out and not emailed_attacker(server)
    deny = gw.audit.query(kind="tool_call", decision="deny")[-1]
    assert deny["tool"] == "send_email" and "model proposed it" in deny["reason"]


def test_mcp06_untrusted_content_is_fenced_for_the_model(registry):
    llm = MockLLM()
    server = attacks.TicketsServer()
    gw = sec.SecureOpsGateway(registry, server, llm, agent_tools=attacks.AGENT_TOOLS)
    gw.connect(server.manifest(), server.package)
    gw.read_resource(ALICE, "ticket://T-9")
    gw.ask(ALICE, "Draft a reply.")
    assert '<untrusted source="resource:ticket://T-9">' in llm.calls[-1][0]["content"]


def test_mcp10_cache_is_isolated_per_tenant_and_user(registry):
    gw, server = secure_gateway(registry)
    gw.call(ALICE, "search_tickets", {"query": "payroll"})
    assert server.payroll_canary not in gw.call(BOB_B, "search_tickets", {"query": "payroll"})


def test_mcp10_server_receives_only_its_arguments(registry):
    gw, server = secure_gateway(registry)
    gw.call(ALICE, "get_ticket", {"ticket_id": "T-1"})
    gw.call(BOB_B, "search_tickets", {"query": "printer"})
    assert set(server.received[-1]) == {"arguments", "tenant"}
    assert server.payroll_canary not in json.dumps(server.received[-1])


def test_mcp10_sessions_do_not_share_context(registry):
    gw, server = secure_gateway(registry)
    gw.call(ALICE, "get_ticket", {"ticket_id": "T-1"})
    assert server.payroll_canary not in gw.ask(ALICE_2, "What is in my context?")
    assert server.payroll_canary not in gw.ask(BOB_B, "What is in my context?")


def test_mcp08_every_decision_is_attributable(registry):
    gw, _ = secure_gateway(registry)
    gw.call(ALICE, "search_tickets", {"query": "vpn"})
    gw.call(BOT, "send_email", {"to": "x@acme.example", "body": "hi"})
    calls = gw.audit.query(kind="tool_call")
    assert [c["decision"] for c in calls] == ["allow", "deny"]
    for c in calls:
        for key in ("correlation_id", "user", "tenant", "agent", "session", "server", "server_version",
                    "tool", "decision", "reason", "args_sha256", "ts", "hash", "prev"):
            assert c[key] not in (None, ""), key


def test_mcp08_audit_trail_holds_no_secrets(registry):
    gw, _ = secure_gateway(registry)
    token = attacks.fake_jwt()
    gw.call(ALICE, "search_tickets", {"query": f"Bearer {token}"})
    gw.audit.record("note", reason=f"debug Authorization: Bearer {token}")
    assert token not in json.dumps(gw.audit.events)


@pytest.mark.parametrize("tamper", ["edit_decision", "delete_middle", "swap_order"])
def test_mcp08_tampering_breaks_the_hash_chain(registry, tamper):
    gw, _ = secure_gateway(registry)
    for q in ("vpn", "printer", "payroll"):
        gw.call(ALICE, "search_tickets", {"query": q})
    assert gw.audit.verify() == (True, None)
    ev = gw.audit.events
    if tamper == "edit_decision":
        ev[2]["decision"] = "deny"
    elif tamper == "delete_middle":
        del ev[2]
    else:
        ev[2], ev[3] = ev[3], ev[2]
    ok, index = gw.audit.verify()
    assert not ok and index == 2


def test_mcp08_anchor_detects_cut_off_events(registry):
    gw, _ = secure_gateway(registry)
    gw.call(ALICE, "search_tickets", {"query": "vpn"})
    anchor = gw.audit.head                       # copied to a separate system
    gw.audit.events.pop()                        # an attacker removes the newest event
    assert gw.audit.verify() == (True, None)     # the chain alone cannot see it ...
    assert gw.audit.verify(anchor=anchor)[0] is False   # ... the anchor can


def test_mcp08_detections_fire_on_the_trail(registry):
    server = attacks.TicketsServer()
    server.scope_creep()
    gw = sec.SecureOpsGateway(registry, server, MockLLM(), agent_tools=attacks.AGENT_TOOLS)
    gw.connect(server.manifest(), server.package)
    gw2, _ = secure_gateway(registry)
    gw2.read_resource(ALICE, "ticket://T-9")
    gw2.ask(ALICE, "Draft a reply.")
    for _ in range(3):
        gw2.call(BOT, "send_email", {"to": "x@acme.example", "body": "hi"})
    kinds = {a["alert"] for a in sec.detect(gw.audit.events + gw2.audit.events)}
    assert {"scope_creep", "side_effect_after_untrusted_content", "deny_burst"} <= kinds


def test_benign_flows_still_work(registry):
    gw, server = secure_gateway(registry)
    assert gw.call(ALICE, "send_email", {"to": "colleague@acme.example", "body": "hi"}).startswith("sent")
    assert "T-7" in gw.call(BOB_B, "search_tickets", {"query": "printer"})


def test_approved_side_effect_after_untrusted_content_is_recorded(registry):
    gw, server = secure_gateway(registry, approver=lambda who, tool, args: args["to"].endswith("@acme.example"))
    gw.call(ALICE, "search_tickets", {"query": "vpn"})  # the session is now tainted
    assert gw.call(ALICE, "send_email", {"to": "colleague@acme.example", "body": "hi"}).startswith("sent")
    assert gw.audit.query(kind="tool_call", tool="send_email")[-1]["approved_by"] == "human-approver"


# ---------- Part 3: defense in depth - switch one layer off, see what still holds ----------------------

def test_without_taint_the_resource_injection_lands(registry):
    gw, server = secure_gateway(registry, taint_untrusted=False)
    gw.read_resource(ALICE, "ticket://T-9")
    gw.ask(ALICE, "Draft a reply.")
    assert emailed_attacker(server), "taint-based approval was the only layer stopping a support agent"


def test_agent_allowlist_alone_stops_the_injection_for_a_read_only_agent(registry):
    gw, server = secure_gateway(registry, taint_untrusted=False)
    gw.read_resource(BOT, "ticket://T-9")
    assert "not allowed" in gw.ask(BOT, "Summarize this ticket.")
    assert not emailed_attacker(server)


def test_scope_baseline_off_still_cannot_reach_unreviewed_tools(registry):
    server = attacks.TicketsServer()
    server.scope_creep()
    gw = sec.SecureOpsGateway(registry, server, MockLLM(), agent_tools={"support-agent": {"delete_ticket"}},
                              enforce_scope_baseline=False)
    assert gw.connect(server.manifest(), server.package) is True and "admin:all" in gw.granted_scopes
    assert "not granted" in gw.call(ALICE, "delete_ticket", {"ticket_id": "T-1"})  # no registry scope


def test_without_isolation_the_cache_leaks(registry):
    gw, server = secure_gateway(registry, isolate_context=False)
    gw.call(ALICE, "search_tickets", {"query": "payroll"})
    assert server.payroll_canary in gw.call(BOB_B, "search_tickets", {"query": "payroll"})


def test_without_minimization_the_server_sees_other_context(registry):
    gw, server = secure_gateway(registry, minimize_context=False, isolate_context=False)
    gw.call(ALICE, "get_ticket", {"ticket_id": "T-1"})
    gw.call(BOB_B, "search_tickets", {"query": "printer"})
    assert server.payroll_canary in json.dumps(server.received[-1])


def test_without_package_check_the_tampered_artifact_connects(registry):
    server = attacks.TicketsServer()
    server.malicious_update()
    gw = sec.SecureOpsGateway(registry, server, MockLLM(), agent_tools=attacks.AGENT_TOOLS, verify_package=False)
    assert gw.connect(server.manifest(), server.package) is True


# ---------- Part 4: shadow MCP server discovery (MCP09) ---------------------------------------------------

@pytest.fixture
def endpoint_root():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for rel, content in attacks.endpoint_configs().items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
        (root / "erin").mkdir()
        (root / "erin" / "notes.json").write_text('{"mcpServers": {"x": {}}}', encoding="utf-8")  # not a config name
        yield root


def test_mcp09_discovery_flags_shadow_and_misconfigured_servers(registry, endpoint_root):
    inventory, errors = sec.discover_configs(endpoint_root)
    found = {(f["file"], f["server"], f["rule"]) for f in sec.assess_inventory(inventory, registry) + errors}
    assert found == {
        ("bob/project/.vscode/mcp.json", "github-helper", "unapproved_server"),
        ("bob/project/.vscode/mcp.json", "github-helper", "unpinned_package"),
        ("bob/project/.vscode/mcp.json", "github-helper", "plaintext_secret"),
        ("carol/.mcp.json", "acme-tickets", "unpinned_package"),
        ("carol/.mcp.json", "notes-sync", "unapproved_server"),
        ("carol/.mcp.json", "notes-sync", "remote_without_tls"),
        ("dave/.mcp.json", "-", "unreadable_config"),
    }
    assert len(inventory) == 4  # alice, bob, carol x2; erin's file is not an MCP config name


def test_mcp09_findings_never_contain_secret_values(registry, endpoint_root):
    inventory, _ = sec.discover_configs(endpoint_root)
    report = json.dumps(sec.assess_inventory(inventory, registry))
    assert "PLAINTEXT-" not in report and "CANARY" not in report


def test_mcp09_pinned_package_with_vault_reference_is_clean(registry):
    item = {"file": "alice/.cursor/mcp.json", "name": "acme-tickets", "command": "npx",
            "args": [attacks.APPROVED_PACKAGE], "url": "", "env": {"TICKETS_TOKEN": "vault://mcp/acme-tickets/token"}}
    assert sec.assess_inventory([item], registry) == []


def test_mcp09_wrong_pinned_version_is_flagged(registry):
    item = {"file": "f", "name": "acme-tickets", "command": "npx", "args": ["@acme/tickets-mcp@2.4.0"],
            "url": "", "env": {}}
    assert [f["rule"] for f in sec.assess_inventory([item], registry)] == ["package_not_approved"]


# ---------- Part 5: secure deployment checks ---------------------------------------------------------------

def test_insecure_deployment_has_every_finding():
    rules = {rule for rule, _ in sec.check_deployment(attacks.insecure_deployment())}
    assert rules == {
        "bind_not_loopback", "no_tls", "no_authentication", "image_not_pinned_by_digest", "runs_as_root",
        "privileged_container", "host_network", "writable_root_fs", "sensitive_host_mount",
        "docker_socket_mounted", "no_resource_limits", "unrestricted_egress", "plaintext_secret_env",
    }


def test_hardened_deployment_is_clean():
    assert sec.check_deployment(attacks.hardened_deployment()) == []


def test_deployment_findings_never_contain_secret_values():
    assert "CANARY" not in json.dumps(sec.check_deployment(attacks.insecure_deployment()))


@pytest.mark.parametrize("mount", ["/home/dev/.ssh:/root/.ssh", "/home/dev/.aws:/aws:ro", "/:/host"])
def test_credential_folders_and_host_root_are_sensitive_mounts(mount):
    spec = attacks.hardened_deployment()
    spec["container"]["mounts"] = [mount]
    assert [r for r, _ in sec.check_deployment(spec)] == ["sensitive_host_mount"]
