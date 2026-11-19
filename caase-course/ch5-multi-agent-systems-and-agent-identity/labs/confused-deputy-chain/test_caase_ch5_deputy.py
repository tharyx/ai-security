import pytest
from aisec_lab import load_lab_module

m = load_lab_module(__file__, "deputy_chain")


def test_vulnerable_deputy_lets_low_privilege_user_move_money():
    asst, ledger = m.build(secure=False)
    ctx = asst.start("alice", {"read_docs"})
    asst.read_document(ctx, m.INJECTED_DOC)
    assert ledger.entries == [("acct-FAKE-EVIL", 5000, "alice")]  # alice cannot transfer, the deputy did


def test_secure_deputy_denies_same_chain():
    asst, ledger = m.build(secure=True)
    ctx = asst.start("alice", {"read_docs"})
    with pytest.raises(m.Denied):
        asst.read_document(ctx, m.INJECTED_DOC)
    assert ledger.entries == []


def test_legitimate_user_request_works():
    asst, ledger = m.build(secure=True)
    ctx = asst.start("bob", {"read_docs", "transfer"})
    assert asst.explicit_request(ctx, "transfer", {"to": "acct-A", "amount": 50}) == "transferred"
    assert ledger.entries == [("acct-A", 50, "bob")]


def test_even_authorized_principal_blocked_when_injection_drives_high_value_action():
    asst, ledger = m.build(secure=True)
    ctx = asst.start("bob", {"read_docs", "transfer"})
    with pytest.raises(m.Denied, match="human approval"):
        asst.read_document(ctx, m.INJECTED_DOC)
    assert ledger.entries == []


def test_downscoping_on_a_hop_removes_authority_bob_has():
    asst, ledger = m.build(secure=True)
    ctx = asst.start("bob", {"read_docs", "transfer"})
    with pytest.raises(m.Denied, match="delegated scopes"):
        asst.read_document(ctx, m.INJECTED_DOC, narrow_to={"read_docs"})
    assert ledger.entries == []


def test_human_approval_flag_allows_tainted_action():
    deputy = m.FinanceAgent(m.Ledger(), secure=True)
    ctx = m.Ctx("bob", frozenset({"transfer"}), ("assistant",), tainted=True, approved=True)
    assert deputy.handle("transfer", {"to": "acct-A", "amount": 5000}, ctx) == "transferred"


def test_scopes_only_shrink():
    ctx = m.Ctx("bob", frozenset({"read_docs"}))
    assert ctx.hop("x", {"read_docs", "transfer"}).scopes == frozenset({"read_docs"})


def test_chain_depth_limit():
    deputy = m.FinanceAgent(m.Ledger(), secure=True)
    ctx = m.Ctx("bob", frozenset({"transfer"}), tuple(f"a{i}" for i in range(m.MAX_CHAIN + 1)))
    with pytest.raises(m.Denied, match="too deep"):
        deputy.handle("transfer", {"to": "a", "amount": 1}, ctx)


def test_deputy_own_permissions_still_checked():
    deputy = m.FinanceAgent(m.Ledger(), secure=True, perms={"read_docs"})
    ctx = m.Ctx("bob", frozenset({"transfer"}), ("assistant",))
    with pytest.raises(m.Denied, match="deputy lacks"):
        deputy.handle("transfer", {"to": "a", "amount": 1}, ctx)
