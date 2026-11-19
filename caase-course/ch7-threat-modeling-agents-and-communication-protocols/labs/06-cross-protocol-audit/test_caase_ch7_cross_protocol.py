from __future__ import annotations

import pytest

from aisec_lab import load_lab_module

br = load_lab_module(__file__, "bridge")

FIXES = ("keep_trust", "namespace_identity", "strict_schema", "global_replay")


def hardened(**off):
    flags = {k: True for k in FIXES}
    flags.update({k: False for k in off})
    return lambda: br.Bridge(**flags)


def test_vulnerable_bridge_has_exactly_the_four_confusion_bugs():
    ids = {f["id"] for f in br.audit(lambda: br.Bridge())}
    assert ids == {"XP-1", "XP-2", "XP-3", "XP-4"}


def test_hardened_bridge_has_no_findings_and_keeps_benign_traffic_working():
    assert br.audit(hardened()) == []


@pytest.mark.parametrize("fix,finding", [("keep_trust", "XP-1"), ("namespace_identity", "XP-2"),
                                         ("strict_schema", "XP-3"), ("global_replay", "XP-4")])
def test_with_one_fix_missing_only_that_bug_remains(fix, finding):
    only_this_off = {k: (k != fix) for k in FIXES}
    ids = {f["id"] for f in br.audit(lambda: br.Bridge(**only_this_off))}
    assert ids == {finding}  # the other three fixes still hold


def test_vulnerable_external_agent_runs_a_tool_but_hardened_refuses():
    msg = br.a2a_msg("scout-agent", "partner", "lookup_order", {"order": "O-1"}, "n1")
    assert br.Bridge().handle("a2a", msg).startswith("order")
    with pytest.raises(br.Denied, match="external"):
        br.Bridge(keep_trust=True).handle("a2a", msg)


def test_sandbox_agent_cannot_borrow_the_prod_identity_when_namespaced():
    msg = br.a2a_msg("billing-agent", "acme-sandbox", "issue_refund", {"order": "O-2", "amount": 10}, "n2")
    b = br.Bridge(namespace_identity=True)
    with pytest.raises(br.Denied, match="identity"):
        b.handle("a2a", msg)
    assert b.backend.ledger == []


def test_schema_attack_moves_money_over_the_limit_only_on_the_vulnerable_bridge():
    attack = br.mcp_msg("billing-agent", "issue_refund", {"order": "O-3", "amount": "1e3", "override_limit": True}, "n3")
    v = br.Bridge()
    v.handle("mcp", attack)
    assert v.backend.ledger[-1]["amount"] == 1000
    s = br.Bridge(strict_schema=True)
    with pytest.raises(br.Denied, match="schema"):
        s.handle("mcp", attack)
    assert s.backend.ledger == []


def test_strict_schema_still_enforces_the_limit_for_well_typed_amounts():
    s = br.Bridge(strict_schema=True)
    with pytest.raises(br.Denied, match="limit"):
        s.handle("mcp", br.mcp_msg("billing-agent", "issue_refund", {"order": "O", "amount": 501}, "n4"))
    with pytest.raises(br.Denied, match="schema"):
        s.handle("mcp", br.mcp_msg("billing-agent", "issue_refund", {"order": "O", "amount": True}, "n5"))


def test_replay_is_blocked_within_one_protocol_even_when_vulnerable():
    b = br.Bridge()
    m = br.mcp_msg("billing-agent", "issue_refund", {"order": "O", "amount": 5}, "same")
    b.handle("mcp", m)
    with pytest.raises(br.Denied, match="replay"):
        b.handle("mcp", m)


def test_cross_protocol_replay_double_spends_only_when_stores_are_per_protocol():
    v = br.Bridge(namespace_identity=False)
    v.handle("mcp", br.mcp_msg("billing-agent", "issue_refund", {"order": "O", "amount": 5}, "x"))
    v.handle("ucp", br.ucp_msg("billing-agent", "acme", "issue_refund", {"order": "O", "amount": 5}, "x"))
    assert len(v.backend.ledger) == 2
    g = br.Bridge(global_replay=True)
    g.handle("mcp", br.mcp_msg("billing-agent", "issue_refund", {"order": "O", "amount": 5}, "x"))
    with pytest.raises(br.Denied, match="replay"):
        g.handle("ucp", br.ucp_msg("billing-agent", "acme", "issue_refund", {"order": "O", "amount": 5}, "x"))
