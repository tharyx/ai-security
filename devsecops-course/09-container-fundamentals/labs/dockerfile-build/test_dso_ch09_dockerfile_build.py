from pathlib import Path

import pytest
from aisec_lab import load_lab_module

df = load_lab_module(__file__, "dockerfile")
FIX = Path(__file__).parent / "fixtures"
SINGLE = (FIX / "single-stage.Dockerfile").read_text()
MULTI = (FIX / "multi-stage.Dockerfile").read_text()
CTX = {"app.py": 20, "requirements.txt": 2}


def test_parse_handles_continuation_and_comments():
    ins = df.parse(SINGLE)
    cmds = [i.cmd for i in ins]
    assert cmds[0] == "FROM" and "RUN" in cmds
    run = [i for i in ins if i.cmd == "RUN"][0]
    assert "gcc" in run.args and "\\" not in run.args


def test_unknown_instruction_rejected():
    with pytest.raises(ValueError):
        df.parse("FROM alpine\nFOO bar")


def test_only_run_copy_add_make_layers():
    b = df.build(SINGLE, CTX)
    # base + COPY + 2 RUN
    assert len(b["layers"]) == 4
    assert b["meta"]["USER"] == "root"


def test_cache_hit_on_identical_rebuild():
    cache = set()
    df.build(SINGLE, CTX, cache)
    b2 = df.build(SINGLE, CTX, cache)
    assert b2["misses"] == 0 and b2["hits"] == 3


def test_change_invalidates_all_following_layers():
    cache = set()
    b1 = df.build(SINGLE, CTX, cache)
    b2 = df.build(SINGLE, dict(CTX, **{"app.py": 99}), cache)
    assert b2["misses"] == 3                          # COPY and both RUNs after it rebuilt
    lines = df.explain_cache(b1, b2)
    assert lines[0].startswith("cached") and lines[1].startswith("REBUILT")
    assert "parent changed" in lines[2]


def test_multistage_ships_only_last_stage():
    b = df.build(MULTI, {"go.mod": 1, "go.sum": 1, "main.go": 5})
    assert b["discarded_stages"] == ["build"]
    assert all(l.stage != "build" for l in b["layers"])
    assert b["meta"]["USER"] == "65532"
    assert b["size_kb"] < 20_000


def test_multistage_much_smaller_than_single():
    single = df.build(SINGLE, CTX)["size_kb"]
    multi = df.build(MULTI, {"main.go": 5})["size_kb"]
    assert multi * 20 < single


def test_stage_names_and_copy_from():
    sts = df.stages(df.parse(MULTI))
    assert [s.name for s in sts] == ["build", "1"]
    assert any("--from=build" in i.args for i in sts[1].instructions)
