"""Tests for invocation_log.py. Run: python -m pytest cmcpse-course/ch4-defending-and-hardening-mcp-servers"""

from __future__ import annotations

import copy
import json

import pytest

from aisec_lab import load_lab_module

il = load_lab_module(__file__, "invocation_log")
KEY = b"audit-key-audit-key-audit-key-32"
T0 = 1_760_000_000.0 - (1_760_000_000 % 86400) + 10 * 3600     # 10:00 UTC on some day


class Clock:
    t = T0

    def __call__(self):
        return self.t

    def tick(self, s=1.0):
        self.t += s


def make():
    clock = Clock()
    chain = il.AuditChain(KEY)
    logger = il.InvocationLogger(chain, clock)
    return clock, chain, logger


def rec(logger, user="alice", tool="notes_read", decision="allow", result="ok", args=None, server="notes"):
    return logger.record(session_id="s1", user=user, client_id="ide", server=server, tool=tool, args=args or {"id": "n1"},
                         result=result, latency_ms=3.2, decision=decision)


def test_record_has_full_context_and_hashes_the_raw_arguments():
    _, _, logger = make()
    r = rec(logger, args={"query": "q", "api_key": "sk-ABCDEFGHIJKL1234"}, result="x" * 50)
    for field in ("ts", "event_id", "session_id", "user", "client_id", "server", "tool", "args_hash", "args_redacted",
                  "result_size", "latency_ms", "decision", "prev_hash", "hash", "sig", "seq"):
        assert field in r
    assert r["args_redacted"]["api_key"] == "[REDACTED]"
    assert r["result_size"] == 50
    assert r["args_hash"] == il.sha256(il.canonical({"query": "q", "api_key": "sk-ABCDEFGHIJKL1234"}))
    assert "sk-ABCDEFGHIJKL1234" not in logger.sink[0]          # the raw secret never reaches the log line


def test_redaction_finds_nested_secrets_and_truncates_long_values():
    out = il.redact({"a": {"headers": {"Authorization": "Bearer x"}}, "b": ["token hvs.abcdefghijkl"], "c": "z" * 500})
    assert out["a"]["headers"]["Authorization"] == "[REDACTED]"
    assert "hvs." not in out["b"][0]
    assert out["c"].endswith("[truncated]")


def test_chain_verifies_when_untouched():
    _, chain, logger = make()
    for i in range(5):
        rec(logger, tool=f"t{i}")
    assert il.verify(chain.records, KEY) == []


def test_editing_a_record_is_detected():
    _, chain, logger = make()
    for i in range(4):
        rec(logger, decision="deny" if i == 2 else "allow")
    forged = copy.deepcopy(chain.records)
    forged[2]["decision"] = "allow"
    problems = il.verify(forged, KEY)
    assert any("record 3" in p and "hash mismatch" in p for p in problems)


def test_deleting_a_middle_record_is_detected():
    _, chain, logger = make()
    for _ in range(5):
        rec(logger)
    cut = chain.records[:2] + chain.records[3:]
    problems = il.verify(cut, KEY)
    assert any("sequence" in p for p in problems) and any("prev_hash" in p for p in problems)


def test_reordering_is_detected():
    _, chain, logger = make()
    for i in range(4):
        rec(logger, tool=f"t{i}")
    swapped = list(chain.records)
    swapped[1], swapped[2] = swapped[2], swapped[1]
    assert il.verify(swapped, KEY)


def test_attacker_who_recomputes_hashes_without_the_key_is_caught_by_the_signature():
    _, chain, logger = make()
    for _ in range(3):
        rec(logger, decision="deny")
    forged = copy.deepcopy(chain.records)
    prev = il.GENESIS
    for r in forged:                       # rewrite history and fix every hash
        r["decision"] = "allow"
        r["prev_hash"] = prev
        body = {k: v for k, v in r.items() if k not in ("hash", "sig")}
        r["hash"] = il.sha256(prev + il.canonical(body))
        prev = r["hash"]
    problems = il.verify(forged, KEY)
    assert problems and all("signature invalid" in p for p in problems)


def test_truncating_the_tail_needs_an_anchor_to_be_detected():
    _, chain, logger = make()
    for _ in range(5):
        rec(logger)
    anchor = chain.anchor()
    cut = chain.records[:3]
    assert il.verify(cut, KEY) == []                       # chain alone cannot see a cut tail
    assert any("anchor" in p for p in il.verify(cut, KEY, anchor))
    assert il.verify(chain.records, KEY, anchor) == []


def test_logged_caller_logs_allow_deny_and_error_with_latency():
    clock, chain, logger = make()
    ticks = iter([0.0, 0.0125, 1.0, 1.0, 2.0, 2.5])
    who = il.Identity("alice", "ide", "s9")

    def backend(server, tool, args):
        if tool == "boom":
            raise RuntimeError("db password=hunter2hunter2")
        return "result-text"

    caller = il.LoggedCaller(backend, logger, allow=lambda w, s, t: "tool not in role" if t == "admin_op" else None, timer=lambda: next(ticks))
    assert caller(who, "notes", "notes_read", {"id": "n1"}) == "result-text"
    with pytest.raises(PermissionError):
        caller(who, "notes", "admin_op", {})
    with pytest.raises(RuntimeError):
        caller(who, "notes", "boom", {})
    d = [(r["tool"], r["decision"], r["reason"]) for r in chain.records]
    assert d == [("notes_read", "allow", ""), ("admin_op", "deny", "tool not in role"), ("boom", "error", "RuntimeError")]
    assert chain.records[0]["latency_ms"] == 12.5
    assert "hunter2" not in "\n".join(logger.sink)          # exception text is not logged


def test_detect_burst():
    clock, chain, logger = make()
    for _ in range(25):
        rec(logger); clock.tick(0.2)
    alerts = il.detect(chain.records)
    assert [a["rule"] for a in alerts] == ["burst"]


def test_detect_repeated_denials_is_high_severity():
    clock, chain, logger = make()
    for t in ("a", "b", "c"):
        rec(logger, tool=t, decision="deny"); clock.tick(5)
    a = il.detect(chain.records)
    assert a and a[0]["rule"] == "repeated_denials" and a[0]["severity"] == "high"


def test_detect_read_then_egress_but_not_egress_alone_or_late():
    clock, chain, logger = make()
    rec(logger, tool="read_customers"); clock.tick(5)
    rec(logger, tool="send_email")
    assert [a["rule"] for a in il.detect(chain.records)] == ["read_then_egress"]
    clock2, chain2, logger2 = make()
    rec(logger2, tool="send_email")
    rec(logger2, tool="read_customers"); clock2.tick(300)
    rec(logger2, tool="send_email")
    assert il.detect(chain2.records) == []


def test_detect_new_tool_large_result_and_secret_in_args():
    clock, chain, logger = make()
    rec(logger, tool="notes_read")
    rec(logger, tool="shell_exec", result="x" * 200_000, args={"cmd": "echo sk-ABCDEFGHIJKL1234"})
    cfg = il.DetectionConfig(baseline_tools={"alice": {"notes_read"}})
    rules = sorted(a["rule"] for a in il.detect(chain.records, cfg))
    assert rules == ["large_result", "new_tool", "secret_in_args"]


def test_detect_off_hours():
    clock, chain, logger = make()
    clock.t = T0 - 8 * 3600 + 3600        # 03:00 UTC
    rec(logger)
    assert [a["rule"] for a in il.detect(chain.records)] == ["off_hours"]


def test_quiet_normal_use_raises_no_alerts():
    clock, chain, logger = make()
    for i in range(6):
        rec(logger, tool=["notes_read", "notes_search"][i % 2]); clock.tick(30)
    assert il.detect(chain.records) == []


def test_sink_lines_are_valid_json_and_match_chain():
    _, chain, logger = make()
    rec(logger); rec(logger)
    parsed = [json.loads(line) for line in logger.sink]
    assert parsed == chain.records
