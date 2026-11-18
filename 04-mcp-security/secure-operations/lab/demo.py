"""Run every operations attack against the naive and the secure setup and print a scorecard.

From the repository root:
    python 04-mcp-security/secure-operations/lab/demo.py
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import tempfile
from pathlib import Path

import attacks
import secure_ops as sec
import vulnerable_ops as vuln
from aisec_lab import MockLLM

ALICE = sec.Principal("alice", "tenant-a", "support-agent", "s1")
BOB_B = sec.Principal("bob", "tenant-b", "support-agent", "s9")
BOT = sec.Principal("alice", "tenant-a", "summary-bot", "s3")


def registry() -> dict[str, sec.RegistryEntry]:
    return {"acme-tickets": sec.RegistryEntry(
        name="acme-tickets", version="2.3.1", package=attacks.APPROVED_PACKAGE,
        package_sha256=hashlib.sha256(attacks.PACKAGE_V231).hexdigest(), owner="platform-team",
        tool_scopes=dict(attacks.TOOL_SCOPES), side_effect_tools=attacks.SIDE_EFFECT_TOOLS,
        secret_refs={"TICKETS_TOKEN": "vault://mcp/acme-tickets/token"})}


def gateways(server_factory=attacks.TicketsServer):
    """A fresh naive and a fresh secure gateway, each with its own server."""
    s1, s2 = server_factory(), server_factory()
    naive = vuln.NaiveGateway(s1, MockLLM())
    naive.connect(s1.manifest(), s1.package)
    secure = sec.SecureOpsGateway(registry(), s2, MockLLM(), agent_tools=attacks.AGENT_TOOLS)
    secure.connect(s2.manifest(), s2.package)
    return (naive, s1), (secure, s2)


def logged(log_fn, *filters) -> str:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    for f in filters:
        handler.addFilter(f)
    logger = logging.getLogger(f"demo-{id(stream)}")
    logger.handlers, logger.propagate = [handler], False
    logger.setLevel(logging.DEBUG)
    log_fn(logger)
    return stream.getvalue()


def row(name: str, naive: str, secure: str, mcp: str) -> None:
    print(f"{name:32} {naive:22} {secure:24} {mcp}")


def main() -> None:
    print(f"{'case':32} {'naive':22} {'secure':24} OWASP MCP")
    print("-" * 92)

    # MCP01: a malicious stdio server reads its environment
    parent = attacks.parent_environment()
    vault = sec.Vault({"vault://mcp/acme-tickets/token": ("own-token-value-123", frozenset({"acme-tickets"}))})
    n = len(attacks.credential_harvester(vuln.naive_launch_env(parent)))
    s = len(attacks.credential_harvester(sec.build_launch_env(registry()["acme-tickets"], parent, vault)))
    row("malicious_server_reads_env", f"{n} SECRETS STOLEN", f"ok (own token only: {s})", "MCP01")

    # MCP01: token leakage through logs
    token = attacks.fake_jwt()
    headers = {"Authorization": f"Bearer {token}"}
    n_out = logged(lambda lg: vuln.naive_log_request(lg, headers, {"query": "vpn"}))
    s_out = logged(lambda lg: sec.secure_log_request(lg, headers, {"query": "vpn"}))
    row("token_in_request_log", "TOKEN LOGGED" if token in n_out else "ok",
        "TOKEN LOGGED" if token in s_out else "ok (fingerprint)", "MCP01")
    s_out = logged(lambda lg: lg.debug("raw headers %s", headers), sec.RedactingFilter(sec.Redactor()))
    n_out = logged(lambda lg: lg.debug("raw headers %s", headers))
    row("developer_debug_log", "TOKEN LOGGED" if token in n_out else "ok",
        "TOKEN LOGGED" if token in s_out else "ok (filter redacted)", "MCP01")

    # MCP02: scope creep in an update
    def creeping():
        srv = attacks.TicketsServer()
        srv.scope_creep()
        return srv
    (n_gw, _), (s_gw, _) = gateways(creeping)
    row("update_asks_for_admin_scope", "GRANTED admin:all" if "admin:all" in n_gw.granted_scopes else "ok",
        "blocked (scope_creep)" if s_gw.entry is None else "GRANTED", "MCP02")

    # MCP02: excessive permissions for a read-only agent
    (n_gw, n_srv), (s_gw, s_srv) = gateways()
    for gw in (n_gw, s_gw):
        gw.call(BOT, "send_email", {"to": attacks.ATTACKER_INBOX, "body": "hi"})
    row("read_only_bot_sends_email", "EMAIL SENT" if n_srv.outbox else "ok",
        "EMAIL SENT" if s_srv.outbox else "denied (agent policy)", "MCP02")

    # MCP04: same version string, different code
    def tampered():
        srv = attacks.TicketsServer()
        srv.malicious_update()
        return srv
    (n_gw, _), (s_gw, _) = gateways(tampered)
    row("tampered_package_same_version", "ACCEPTED", "blocked (digest)" if s_gw.entry is None else "ACCEPTED",
        "MCP04")

    # MCP06: a resource injects instructions
    (n_gw, n_srv), (s_gw, s_srv) = gateways()
    for gw in (n_gw, s_gw):
        gw.read_resource(ALICE, "ticket://T-9")
        gw.ask(ALICE, "Draft a reply to this ticket.")
    hit = lambda srv: any(m["to"] == attacks.ATTACKER_INBOX for m in srv.outbox)  # noqa: E731
    row("resource_injects_instructions", "EMAIL TO ATTACKER" if hit(n_srv) else "ok",
        "EMAIL TO ATTACKER" if hit(s_srv) else "denied (approval)", "MCP06")

    # MCP10: cross-tenant cache, over-sharing to the server, cross-session context
    (n_gw, n_srv), (s_gw, s_srv) = gateways()
    leaks = []
    for gw, srv in ((n_gw, n_srv), (s_gw, s_srv)):
        gw.call(ALICE, "search_tickets", {"query": "payroll"})
        leaks.append(srv.payroll_canary in gw.call(BOB_B, "search_tickets", {"query": "payroll"}))
    row("cross_tenant_cache", "TENANT A DATA" if leaks[0] else "ok", "TENANT A DATA" if leaks[1] else "ok", "MCP10")

    (n_gw, n_srv), (s_gw, s_srv) = gateways()
    seen = []
    for gw, srv in ((n_gw, n_srv), (s_gw, s_srv)):
        gw.call(ALICE, "get_ticket", {"ticket_id": "T-1"})
        gw.call(BOB_B, "search_tickets", {"query": "printer"})
        seen.append(srv.payroll_canary in json.dumps(srv.received[-1]))
    row("context_sent_to_server", "SERVER SAW A's DATA" if seen[0] else "ok",
        "SERVER SAW A's DATA" if seen[1] else "ok (args only)", "MCP10")

    (n_gw, n_srv), (s_gw, s_srv) = gateways()
    out = []
    for gw, srv in ((n_gw, n_srv), (s_gw, s_srv)):
        gw.call(ALICE, "get_ticket", {"ticket_id": "T-1"})
        out.append(srv.payroll_canary in gw.ask(BOB_B, "What is in my context?"))
    row("other_session_context", "LEAKED" if out[0] else "ok", "LEAKED" if out[1] else "ok", "MCP10")

    # MCP08: audit trail
    (n_gw, _), (s_gw, _) = gateways()
    for q in ("vpn", "printer", "payroll"):
        n_gw.call(ALICE, "search_tickets", {"query": q})
        s_gw.call(ALICE, "search_tickets", {"query": q})
    s_gw.audit.events[2]["decision"] = "deny"     # someone edits the evidence
    ok, idx = s_gw.audit.verify()
    row("audit_record_edited", "UNDETECTABLE", f"detected at event #{idx}" if not ok else "UNDETECTED", "MCP08")
    row("who_did_what", "NO USER/AGENT", f"{len(s_gw.audit.query(kind='tool_call'))} attributable events", "MCP08")

    # benign
    (n_gw, _), (s_gw, _) = gateways()
    ok_n = n_gw.call(ALICE, "send_email", {"to": "colleague@acme.example", "body": "hi"}).startswith("sent")
    ok_s = s_gw.call(ALICE, "send_email", {"to": "colleague@acme.example", "body": "hi"}).startswith("sent")
    row("benign_user_email", "ok" if ok_n else "BROKEN", "ok" if ok_s else "BROKEN", "-")

    # MCP09: shadow server discovery
    print("\nShadow MCP discovery (endpoint config files vs the registry):")
    print(f"{'file':32} {'server':16} rule")
    print("-" * 92)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for rel, content in attacks.endpoint_configs().items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
        inventory, errors = sec.discover_configs(root)
        for f in sec.assess_inventory(inventory, registry()) + errors:
            print(f"{f['file']:32} {f['server']:16} {f['rule']}: {f['detail']}")
    print(f"servers found: {len(inventory)}")

    # Deployment checks
    print("\nDeployment check:")
    for label, spec in (("insecure", attacks.insecure_deployment()), ("hardened", attacks.hardened_deployment())):
        rules = [rule for rule, _ in sec.check_deployment(spec)]
        print(f"  {label:9} {len(rules):2} findings: {', '.join(rules) or '-'}")

    print("\nTip: switch a layer off, e.g. SecureOpsGateway(..., taint_untrusted=False), and re-run.")


if __name__ == "__main__":
    main()
