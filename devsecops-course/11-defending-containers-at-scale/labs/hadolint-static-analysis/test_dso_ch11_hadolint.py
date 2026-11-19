from pathlib import Path

from aisec_lab import load_lab_module

h = load_lab_module(__file__, "hadolint_lite")
FIX = Path(__file__).parent / "fixtures"
BAD = h.lint((FIX / "Dockerfile.bad").read_text())
GOOD = h.lint((FIX / "Dockerfile.good").read_text())


def rules(fs):
    return {x.rule for x in fs}


def test_bad_dockerfile_hits_core_rules():
    assert {"DL3006", "DL3008", "DL3020", "DL3025", "DL3002", "DL3003", "DSO-001", "DSO-002"} <= rules(BAD)


def test_good_dockerfile_has_no_errors_or_warnings():
    assert [x for x in GOOD if x.level in ("error", "warning")] == []
    assert h.gate(GOOD)


def test_gate_fails_on_bad():
    assert not h.gate(BAD)
    assert h.gate([x for x in BAD if x.level == "info"], "error")


def test_continuation_lines_joined():
    ins = h.parse("RUN a \\\n  && b\nCMD x\n")
    assert ins[0][0] == 1 and "&& b" in ins[0][2] and ins[1][1] == "CMD"


def test_sarif_shape():
    s = h.to_sarif(BAD, "Dockerfile.bad")
    assert s["version"] == "2.1.0"
    r = s["runs"][0]["results"]
    assert len(r) == len(BAD)
    assert r[0]["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
    assert {x["level"] for x in r} <= {"error", "warning", "note"}


def test_pinned_digest_and_scratch_not_flagged():
    assert "DL3006" not in rules(h.lint("FROM scratch\nUSER 1000\n"))
    assert "DL3007" in rules(h.lint("FROM nginx:latest\nUSER 1000\n"))
