import json
from pathlib import Path

from aisec_lab import load_lab_module

w = load_lab_module(__file__, "wazuh_lite")
HERE = Path(__file__).parent
RULES = w.load_rules((HERE / "local_rules.xml").read_text())
EVENTS = [json.loads(l) for l in (HERE / "events.jsonl").read_text().splitlines() if l.strip()]
ALERTS = w.run(RULES, EVENTS, min_level=1)


def ids_at(ts):
    return {a["rule"] for a in ALERTS if a["ts"] == ts}


def test_flatten_dotted_paths():
    f = w.flatten(EVENTS[0])
    assert f["docker.Actor.Attributes.name"] == "web" and f["integration"] == "docker"


def test_container_start_and_shell():
    assert 100201 in ids_at(1000)
    assert 100202 in ids_at(1010)


def test_unapproved_registry_pull_only():
    assert 100205 in ids_at(1020) and 100205 not in ids_at(1021)


def test_oom_and_exit_137():
    assert 100204 in ids_at(1030) and 100203 in ids_at(1031)


def test_restart_loop_fires_on_fifth_death_within_window():
    loop = [a for a in ALERTS if a["rule"] == 100206]
    assert len(loop) == 1 and loop[0]["ts"] == 1058 and loop[0]["level"] == 10


def test_non_docker_event_ignored():
    assert ids_at(1500) == set()


def test_frequency_window_expires():
    slow = [{"ts": 1000 + i * 100, "integration": "docker", "docker": {"Type": "container", "Action": "die",
            "Actor": {"ID": "x", "Attributes": {"exitCode": "1"}}}} for i in range(6)]
    assert not [a for a in w.run(RULES, slow, 1) if a["rule"] == 100206]


def test_min_level_filters_noise():
    assert all(a["level"] >= 7 for a in w.run(RULES, EVENTS, 7))
