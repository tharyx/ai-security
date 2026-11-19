"""Long-term memory poisoning across sessions, and provenance-tagged memory as the defence."""

import json
import tempfile
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

m = load_lab_module(__file__, "memory")
POISON_URL = "https://blog.example/post"


@pytest.fixture
def path():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d) / "memory.json"


def sessions(store_cls, path, **kw):
    s1 = m.Agent(store_cls(path, **kw), "s1")
    s2 = m.Agent(store_cls(path, **kw), "s2")
    return s1, s2


def test_vulnerable_memory_persists_poison_into_a_later_session(path):
    s1, s2 = sessions(m.VulnerableStore, path)
    s1.say(f"Summarize {POISON_URL}")
    assert "payment_account" in path.read_text()
    assert m.ATTACKER_ACCOUNT in s2.say("pay invoice 42")
    assert s2.payments[0]["account"] == m.ATTACKER_ACCOUNT


def test_provenance_store_quarantines_the_poison(path):
    s1, s2 = sessions(m.ProvenanceStore, path)
    s1.say(f"Summarize {POISON_URL}")
    q = s1.store.quarantined()
    assert len(q) == 1 and q[0].source == "tool:fetch_page" and not q[0].trusted
    assert s2.say("pay invoice 42") == "FINAL: Which account should I pay?"
    assert s2.payments == []


def test_user_stated_memory_is_trusted_and_used(path):
    s1, s2 = sessions(m.ProvenanceStore, path)
    s1.say(f"remember that payment_account is {m.USER_ACCOUNT}")
    assert m.USER_ACCOUNT in s2.say("pay invoice 42")


def test_poison_cannot_override_a_trusted_value(path):
    s1, s2 = sessions(m.ProvenanceStore, path)
    s1.say(f"remember that payment_account is {m.USER_ACCOUNT}")
    s2.say(f"Summarize {POISON_URL}")
    s3 = m.Agent(m.ProvenanceStore(path), "s3")
    assert m.USER_ACCOUNT in s3.say("pay invoice 7")


def test_human_approval_promotes_a_quarantined_entry(path):
    s1, s2 = sessions(m.ProvenanceStore, path)
    s1.say("Summarize https://blog.example/post")
    assert s1.store.approve("payment_account", "tool:fetch_page") == 1  # a human decided (not recommended here!)
    assert s1.store.quarantined() == []
    assert s2.store.facts()["payment_account"] == m.ATTACKER_ACCOUNT  # approval is a real decision: show provenance


def test_tampered_file_is_rejected_by_the_mac(path):
    s1, _ = sessions(m.ProvenanceStore, path)
    s1.say(f"remember that payment_account is {m.USER_ACCOUNT}")
    data = json.loads(path.read_text())
    data[0]["value"] = m.ATTACKER_ACCOUNT  # attacker edits the file on disk
    path.write_text(json.dumps(data))
    store = m.ProvenanceStore(path)
    assert "payment_account" not in store.facts() and store.rejected == ["tampered:payment_account"]


def test_entries_expire():
    with tempfile.TemporaryDirectory() as d:
        now = [1000.0]
        store = m.ProvenanceStore(Path(d) / "m.json", ttl_seconds=100, clock=lambda: now[0])
        store.add("city", "Berlin", "user", "s1")
        assert store.facts() == {"city": "Berlin"}
        now[0] += 101
        assert store.facts() == {}


def test_purge_by_source_removes_everything_a_bad_source_wrote(path):
    s1, _ = sessions(m.ProvenanceStore, path)
    s1.say(f"Summarize {POISON_URL}")
    s1.say(f"remember that city is Berlin")
    assert s1.store.purge_source("tool:fetch_page") == 1
    assert s1.store.facts() == {"city": "Berlin"} and s1.store.quarantined() == []


def test_benign_page_writes_nothing(path):
    s1, _ = sessions(m.ProvenanceStore, path)
    s1.say("Summarize https://news.example/x")
    assert not path.exists() or json.loads(path.read_text()) == []


def test_global_cache_bleeds_one_users_context_to_another():
    c = m.GlobalCache()
    c.put("alice", "salary-review", "Alice asked about her raise: FAKE-AMOUNT-90k")
    assert "FAKE-AMOUNT-90k" in c.get("bob", "salary-review")


def test_scoped_cache_isolates_users():
    c = m.ScopedCache()
    c.put("alice", "salary-review", "Alice asked about her raise: FAKE-AMOUNT-90k")
    assert c.get("bob", "salary-review") is None
    assert "FAKE-AMOUNT-90k" in c.get("alice", "salary-review")
