from pathlib import Path

from aisec_lab import load_lab_module

bp = load_lab_module(__file__, "bestpractice")
FIX = Path(__file__).parent / "fixtures"
BAD = (FIX / "bad.Dockerfile").read_text()
GOOD = (FIX / "good.Dockerfile").read_text()
CTX = {"app.py": 20, "requirements.txt": 2}


def rules(text):
    return {f.rule for f in bp.lint(text)}


def test_bad_dockerfile_hits_the_big_rules():
    r = rules(BAD)
    assert {"DF-001", "DF-003", "DF-004", "DF-005", "DF-009", "DF-011"} <= r


def test_secret_in_env_is_critical_and_sorted_first():
    fs = bp.lint(BAD)
    assert fs[0].severity == "CRITICAL" and fs[0].rule == "DF-003"


def test_good_dockerfile_is_clean():
    assert bp.lint(GOOD) == []
    assert bp.score(bp.lint(GOOD)) == 0


def test_digest_pin_beats_tag_pin():
    assert "DF-002" in rules("FROM python:3.12\nUSER 1000\nHEALTHCHECK CMD true\n")
    assert "DF-002" not in rules(GOOD)


def test_root_user_flagged():
    assert "DF-009" in rules("FROM alpine:3.20\nUSER root\n")
    assert "DF-009" in rules("FROM alpine:3.20\n")


def test_cache_friendly_order_rebuilds_less():
    bad = bp.rebuild_cost(BAD, CTX, "app.py")
    good = bp.rebuild_cost(GOOD, CTX, "app.py")
    assert good["rebuilt_kb"] < bad["rebuilt_kb"]
    assert good["rebuilt"] < bad["rebuilt"]


def test_multistage_last_stage_is_judged():
    text = "FROM golang:1.23 AS b\nRUN go build\nFROM alpine:3.20\nUSER 1000\nHEALTHCHECK CMD true\n"
    assert "DF-009" not in rules(text)
