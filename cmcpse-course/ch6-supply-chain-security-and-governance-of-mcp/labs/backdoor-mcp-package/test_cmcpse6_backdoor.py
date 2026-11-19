"""Backdoor lab tests: a harmless postmark-style backdoor, and four defences that each catch it.

Run from the repository root:
    python -m pytest cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/labs/backdoor-mcp-package -v
"""

import sys
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

HERE = Path(__file__).resolve().parent
d = load_lab_module(__file__, "defenses")
OLD, NEW = HERE / "packages" / "mailer_1_0_15", HERE / "packages" / "mailer_1_0_16"
SINK = "collector@attacker.example"
CALL = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "send_email", "arguments": {"to": "bob@customer.example", "subject": "invoice", "body": "BODY-CANARY"}}}


def run(package, transport):
    return d.load_package_server(package).handle(CALL, transport)


# ------------------------------------------------------------------ the attack
def test_old_version_sends_only_to_the_requested_recipient():
    t = d.RecordingTransport()
    run(OLD, t)
    assert t.recipients() == ["bob@customer.example"]


def test_new_version_silently_copies_every_message_to_the_attacker_sink():
    t = d.RecordingTransport()
    response = run(NEW, t)
    assert SINK in t.recipients()
    assert t.sent[0]["body"] == "BODY-CANARY"           # the canary data reaches the sink
    assert response["result"]["content"][0]["text"] == "sent to bob@customer.example"  # and the user sees nothing odd


def test_tool_description_and_schema_are_identical_in_both_versions():
    old, new = d.load_package_server(OLD), d.load_package_server(NEW)
    assert old.TOOL == new.TOOL  # a description pin alone would NOT catch this backdoor


def test_backdoor_package_never_touches_the_network():
    source = (NEW / "server.py").read_text()
    for forbidden in ("socket", "urllib", "requests", "smtplib", "subprocess", "os."):
        assert forbidden not in source.replace("# ", "")


# ------------------------------------------------------------------ defence 1: diff review
def test_diff_review_flags_the_backdoor_with_specific_reasons():
    findings = d.review_diff((OLD / "server.py").read_text(), (NEW / "server.py").read_text())
    text = " | ".join(r for _, r in findings)
    assert "new import of 'base64'" in text
    assert "base64-looking string literal" in text
    assert "'bcc' now has content" in text
    assert any(sev == "high" for sev, _ in findings)


def test_diff_review_is_quiet_for_identical_and_for_comment_only_changes():
    src = (OLD / "server.py").read_text()
    assert d.review_diff(src, src) == []
    assert d.review_diff(src, src + "\n# a harmless comment\n") == []


def test_diff_review_catches_other_common_additions():
    base = "def f():\n    return 1\n"
    assert d.review_diff(base, base + "import socket\n")
    assert d.review_diff(base, base + "URL = 'https://collect.example/x'\n")
    assert d.review_diff(base, base + "exec(payload)\n")


# ------------------------------------------------------------------ defence 2: behavior tests
def test_behavior_check_passes_old_and_fails_new():
    assert d.behavior_check(d.load_package_server(OLD)) == []
    problems = d.behavior_check(d.load_package_server(NEW))
    assert problems and "recipients are" in problems[0]


# ------------------------------------------------------------------ defence 3: egress allowlist
def test_egress_guard_lets_old_version_work():
    guard = d.EgressGuard(d.RecordingTransport(), {"customer.example"})
    run(OLD, guard)
    assert len(guard.inner.sent) == 1 and guard.blocked == []


def test_egress_guard_blocks_the_new_version_and_nothing_is_delivered():
    guard = d.EgressGuard(d.RecordingTransport(), {"customer.example"})
    with pytest.raises(d.EgressBlocked):
        run(NEW, guard)
    assert guard.inner.sent == [] and guard.blocked == [SINK]


def test_egress_guard_checks_cc_and_bcc_not_only_to():
    guard = d.EgressGuard(d.RecordingTransport(), {"customer.example"})
    msg = {"to": ["a@customer.example"], "cc": [], "bcc": ["x@evil.example"], "subject": "", "body": ""}
    with pytest.raises(d.EgressBlocked):
        guard.send(msg)


# ------------------------------------------------------------------ defence 4: pinning
def test_pin_accepts_the_pinned_version_and_rejects_the_update():
    lock = d.make_lock(OLD)
    assert d.verify_pin(OLD, lock) == []
    problems = d.verify_pin(NEW, lock)
    assert any("version 1.0.16 is not the pinned 1.0.15" in p for p in problems)
    assert any("content hash differs" in p for p in problems)


def test_pin_detects_content_change_even_when_version_label_is_unchanged():
    lock = d.make_lock(OLD)
    tampered = Path(__import__("tempfile").mkdtemp()) / "pkg"
    tampered.mkdir()
    (tampered / "metadata.json").write_text((OLD / "metadata.json").read_text())
    (tampered / "server.py").write_text((NEW / "server.py").read_text())  # new code, old label
    problems = d.verify_pin(tampered, lock)
    assert problems == ["package content hash differs from the lock file"]


def test_tree_hash_is_stable_and_order_independent():
    assert d.tree_hash(OLD) == d.tree_hash(OLD)
    assert d.tree_hash(OLD) != d.tree_hash(NEW)


@pytest.mark.parametrize(
    "command,args,expect_problem",
    [
        ("npx", ["-y", "mailer-mcp@latest"], True),
        ("npx", ["mailer-mcp"], True),
        ("npx", ["mailer-mcp@^1.0.0"], True),
        ("npx", ["mailer-mcp@1.0.15"], False),
        ("npx", ["@scope/mailer-mcp@1.0.15"], False),
        ("uvx", ["mailer-mcp"], True),
        ("uvx", ["mailer-mcp==1.0.15"], False),
        ("python", ["-m", "mailer"], False),
    ],
)
def test_host_config_pinning_rules(command, args, expect_problem):
    config = {"mcpServers": {"mail": {"command": command, "args": args}}}
    assert bool(d.check_host_config(config)) is expect_problem


def test_dash_y_is_flagged_even_when_version_is_pinned():
    config = {"mcpServers": {"mail": {"command": "npx", "args": ["-y", "mailer-mcp@1.0.15"]}}}
    assert any("'-y'" in p for p in d.check_host_config(config))
