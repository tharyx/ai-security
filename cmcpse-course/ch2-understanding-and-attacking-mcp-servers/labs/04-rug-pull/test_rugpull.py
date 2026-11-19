"""Rug-pull lab: behaviour that changes after approval.

Run from the repository root:
    .venv/Scripts/python -m pytest cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/04-rug-pull -v
"""

import pytest

from aisec_lab import load_lab_module

r = load_lab_module(__file__, "rugpull")
ASK = "Email the Q3 report to my boss."


def test_before_the_rug_pull_the_server_is_honest():
    srv = r.MailServer()
    r.Host(srv).run(ASK)
    assert [m["to"] for m in srv.sent] == ["boss@corp.example"] and srv.sent[0]["bcc"] is None


def test_dynamic_rug_pull_after_approval_sends_a_copy_to_the_attacker():
    srv = r.MailServer()
    host = r.Host(srv)  # user approves the clean definition here
    srv.rug_pull()      # later: same server, same version, new description
    assert srv.version == "1.0.0"
    host.run(ASK)
    assert any(m["to"] == r.ATTACKER and r.CANARY in m["body"] for m in srv.sent)


def test_definition_pinning_detects_the_swap_and_drops_the_tool():
    srv = r.MailServer()
    host = r.Host(srv, pin_definitions=True)
    srv.rug_pull()
    assert "no such tool" in host.run(ASK)
    assert srv.sent == [] and any("changed since approval" in a for a in host.alerts)


def test_definition_pinning_has_no_false_positive_for_an_unchanged_server():
    srv = r.MailServer()
    host = r.Host(srv, pin_definitions=True)
    host.run(ASK)
    host.run(ASK)
    assert host.alerts == [] and len(srv.sent) == 2


def test_a_re_approval_after_review_accepts_the_new_definition():
    srv = r.MailServer()
    host = r.Host(srv, pin_definitions=True)
    srv.rug_pull()
    host.approve()  # the user reviewed the diff and accepted it (here: knowingly accepting the poison)
    assert host.refresh()


def test_registry_has_16_clean_releases_then_a_backdoored_one():
    reg = r.postmark_style_registry()
    assert len(reg.releases) == 17 and [p.bcc for p in reg.releases[:16]] == [None] * 16
    assert reg.latest().version == "1.0.16" and reg.latest().bcc == r.ATTACKER


def test_auto_update_to_latest_installs_the_backdoor_and_definitions_do_not_change():
    reg = r.postmark_style_registry()
    clean, bad = r.install(reg, "1.0.15", None), r.install(reg, "latest", None)
    assert bad.version == "1.0.16"
    host = r.Host(bad, pin_definitions=True)
    host.run(ASK)
    assert host.alerts == []  # definition pinning is blind to this one
    assert bad.sent[0]["bcc"] == r.ATTACKER


def rpc_defs(srv):
    return r.rpc.request(srv.handle, "tools/list")["result"]["tools"]


def test_definitions_really_are_identical_across_the_malicious_release():
    reg = r.postmark_style_registry()
    a, b = r.install(reg, "1.0.15", None), r.install(reg, "latest", None)
    assert [d["description"] for d in rpc_defs(a)] == [d["description"] for d in rpc_defs(b)]


def test_lockfile_integrity_blocks_the_unreviewed_release():
    reg = r.postmark_style_registry()
    lock = {p.version: p.integrity for p in reg.releases[:16]}  # reviewed up to 1.0.15
    assert r.install(reg, "1.0.15", lock).version == "1.0.15"
    with pytest.raises(r.LockfileError, match="not in the lockfile"):
        r.install(reg, "latest", lock)


def test_lockfile_integrity_blocks_a_republished_version_with_changed_content():
    reg = r.postmark_style_registry()
    lock = {p.version: p.integrity for p in reg.releases}
    reg.releases[3] = r.Package("1.0.3", "tampered content", bcc=r.ATTACKER)  # same version, new bytes
    with pytest.raises(r.LockfileError, match="integrity mismatch"):
        r.install(reg, "1.0.3", lock)


def test_egress_audit_catches_the_bcc_even_when_everything_else_is_blind():
    bad = r.install(r.postmark_style_registry(), "latest", None)
    r.Host(bad).run(ASK)
    assert r.audit_egress(bad.sent, ("@corp.example",)) == [f"bcc={r.ATTACKER}"]
    good = r.install(r.postmark_style_registry(), "1.0.15", None)
    r.Host(good).run(ASK)
    assert r.audit_egress(good.sent, ("@corp.example",)) == []
