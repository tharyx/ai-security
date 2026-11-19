import copy
import json
import pathlib
import tempfile

from aisec_lab import load_lab_module

sp = load_lab_module(__file__, "slsa_provenance")
FX = pathlib.Path(__file__).parent / "fixtures"
ART = b"fake wheel bytes"


def make(**over):
    kw = dict(repo_uri="https://github.com/example/app", ref="refs/tags/v1.0.0", commit="a" * 40,
              entry_point=".github/workflows/release.yml", artifact_name="app.whl",
              artifact_bytes=ART, builder_id="https://example.invalid/builder")
    kw.update(over)
    return sp.simulate_pipeline(**kw)


def test_statement_shape():
    s = make()
    assert s["_type"] == sp.STATEMENT_TYPE
    assert s["predicateType"] == sp.PREDICATE_TYPE
    assert s["subject"][0]["digest"]["sha256"] == sp.sha256_hex(ART)


def test_good_provenance_passes_l1():
    assert sp.check_l1(make(), ART, "app.whl").passed


def test_digest_mismatch_fails():
    res = sp.check_l1(make(), b"other", "app.whl")
    assert not res.passed
    assert any("digest matches" in c.requirement for c in res.failures())


def test_name_mismatch_fails():
    assert not sp.check_l1(make(), ART, "other.whl").passed


def test_missing_builder_fails():
    s = make()
    del s["predicate"]["runDetails"]["builder"]
    assert not sp.check_l1(s, ART).passed


def test_missing_source_commit_fails():
    s = make()
    s["predicate"]["buildDefinition"]["externalParameters"]["source"]["digest"] = {}
    assert not sp.check_l1(s, ART).passed


def test_wrong_predicate_type_fails():
    s = make()
    s["predicateType"] = "https://slsa.dev/provenance/v0.2"
    assert not sp.check_l1(s, ART).passed


def test_bad_digest_format_fails():
    s = make()
    s["subject"][0]["digest"] = {"sha256": "xyz"}
    assert not sp.check_l1(s).passed


def test_non_object_fails():
    assert not sp.check_l1("nope").passed  # type: ignore[arg-type]


def test_empty_subjects_fail():
    s = make()
    s["subject"] = []
    assert not sp.check_l1(s).passed


def test_l1_does_not_need_a_signature():
    # L1 is a completeness check: an unsigned file passes. That is exactly its weakness.
    s = make()
    assert "signatures" not in s
    assert sp.check_l1(s, ART).passed


def test_forged_but_complete_provenance_passes_l1():
    # Anyone can write this by hand; L1 cannot tell. L2 adds signatures to fix that.
    forged = make(builder_id="https://attacker.example/not-a-builder")
    assert sp.check_l1(forged, ART).passed


def test_round_trip_file():
    s = make()
    with tempfile.TemporaryDirectory() as d:
        p = str(pathlib.Path(d) / "a.intoto.jsonl")
        sp.write_provenance(p, s)
        assert sp.read_provenance(p) == s
        assert len(pathlib.Path(p).read_text().splitlines()) == 1


def test_inputs_not_mutated():
    s = make()
    before = copy.deepcopy(s)
    sp.check_l1(s, ART)
    assert s == before


def test_github_fixture_produces_provenance():
    r = sp.analyze_pipeline_yaml((FX / "github-actions-slsa.yml").read_text())
    assert r["platform"] == "github-actions" and r["produces_provenance"]
    assert "slsa-github-generator" in r["mechanism"]


def test_gitlab_fixture_produces_provenance():
    r = sp.analyze_pipeline_yaml((FX / "gitlab-ci-provenance.yml").read_text())
    assert r["platform"] == "gitlab-ci" and r["produces_provenance"]


def test_plain_pipeline_has_no_provenance_and_unpinned_action():
    r = sp.analyze_pipeline_yaml((FX / "unpinned-no-provenance.yml").read_text())
    assert not r["produces_provenance"]
    assert "actions/checkout@v4" in r["unpinned_actions"]


def test_statement_is_json_serialisable():
    json.dumps(make())
