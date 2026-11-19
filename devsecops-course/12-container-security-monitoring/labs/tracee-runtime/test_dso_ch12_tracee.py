import json
from pathlib import Path

from aisec_lab import load_lab_module

t = load_lab_module(__file__, "tracee_lite")
EVENTS = [json.loads(l) for l in (Path(__file__).parent / "events.jsonl").read_text().splitlines() if l.strip()]
ALERTS = t.run(EVENTS)


def by(sig):
    return [a for a in ALERTS if a["id"] == sig]


def test_dropped_executable_requires_write_then_exec():
    d = by("DSO-TRC-001")
    assert [a["ts"] for a in d] == [1002, 1008]
    assert t.run([EVENTS[2]]) == []  # exec without a prior write: nothing


def test_anti_debugging():
    assert [a["ts"] for a in by("DSO-TRC-002")] == [1003]


def test_container_escape_three_variants():
    assert [a["ts"] for a in by("DSO-TRC-003")] == [1004, 1005, 1006]


def test_container_filter_on_escape_signature():
    ev = dict(EVENTS[3])
    ev.pop("containerId")
    assert t.ContainerEscape().on_event(ev) is None


def test_benign_events_quiet():
    assert not [a for a in ALERTS if a["ts"] in (1000, 1009)]


def test_each_signature_has_metadata():
    for s in t.default_signatures():
        assert {"id", "name", "severity"} <= set(s.meta)
