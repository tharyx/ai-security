"""Cross-server privilege escalation and lateral movement through chained tool calls.

Run from the repository root:
    .venv/Scripts/python -m pytest cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/05-cross-server-privesc -v
"""

from aisec_lab import load_lab_module

p = load_lab_module(__file__, "privesc")
FIRST = ("fetch_page", {"url": "https://blog.example/post"})


def exfiltrated(servers):
    return p.CANARY in servers["tickets"].store[p.EXFIL_BOARD]


def test_flat_trust_lets_a_web_page_reach_the_vault_in_three_hops():
    s = p.build_servers()
    h = p.Host(s)
    h.run(FIRST)
    assert [t["server"] for t in h.trace] == ["web-reader", "tickets", "vault", "tickets"]
    assert exfiltrated(s)


def test_the_attacker_never_called_the_vault_directly():
    s = p.build_servers()
    p.Host(s).run(FIRST)
    assert [c["tool"] for c in s["vault"].calls] == ["get_secret"]  # reached only through chained tool calls


def test_audit_trace_shows_where_trust_was_escalated():
    h = p.Host(p.build_servers())
    h.run(FIRST)
    alerts = p.detect_escalation(h.trace)
    assert any("web-reader" in a and "tickets.read_ticket" in a for a in alerts)
    assert any("tickets" in a and "vault.get_secret" in a for a in alerts)


def test_no_read_up_stops_the_chain_at_the_first_hop():
    s = p.build_servers()
    h = p.Host(s, flow_policy=True)
    h.run(FIRST)
    assert [t["server"] for t in h.trace] == ["web-reader"]
    assert not exfiltrated(s) and any("no read-up" in b for b in h.blocked)


def test_no_write_down_blocks_sending_vault_data_to_a_lower_trust_sink():
    s = p.build_servers()
    h = p.Host(s, flow_policy=True)
    h._execute("get_secret", {"name": "deploy-key"}, None)  # the user legitimately reads a secret
    out = h._execute("create_ticket", {"id": p.EXFIL_BOARD, "text": "x"}, "vault")
    assert out.startswith("BLOCKED") and any("no write-down" in b for b in h.blocked)
    off = p.Host(p.build_servers())
    off._execute("get_secret", {"name": "deploy-key"}, None)
    assert off._execute("create_ticket", {"id": p.EXFIL_BOARD, "text": "x"}, "vault") == "updated T-1"


def test_a_direct_vault_request_by_the_user_still_works_with_the_policy_on():
    s = p.build_servers()
    h = p.Host(s, flow_policy=True)
    h.run(("get_secret", {"name": "deploy-key"}))
    assert [t["server"] for t in h.trace] == ["vault"] and not h.blocked


def test_benign_page_has_no_effect():
    s = p.build_servers()
    s["web-reader"].tools["fetch_page"].handler = lambda url: "A nice, ordinary article."
    h = p.Host(s)
    h.run(FIRST)
    assert [t["server"] for t in h.trace] == ["web-reader"] and p.detect_escalation(h.trace) == []
