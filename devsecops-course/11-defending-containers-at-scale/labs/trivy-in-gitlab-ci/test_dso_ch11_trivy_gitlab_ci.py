from pathlib import Path

from aisec_lab import load_lab_module

v = load_lab_module(__file__, "ci_validate")
FIX = Path(__file__).parent / "fixtures"
GOOD = (FIX / "gitlab-ci.good.yml").read_text()
BAD = (FIX / "gitlab-ci.bad.yml").read_text()


def test_good_pipeline_clean():
    assert v.validate(GOOD) == []


def test_bad_pipeline_problems():
    p = " | ".join(v.validate(BAD))
    for frag in ("not pinned", "--exit-code", "--severity", "|| true", "allow_failure", "no artifacts", "not declared"):
        assert frag in p


def test_no_trivy_job():
    assert v.validate("stages: [a]\nj:\n  stage: a\n  script: [echo hi]\n") == ["no job runs trivy"]


def test_variable_image_is_resolved():
    txt = GOOD.replace('"aquasec/trivy:0.58.0"', '"aquasec/trivy:latest"')
    assert any("not pinned" in x for x in v.validate(txt))


def test_artifacts_when_always_required():
    txt = GOOD.replace("when: always", "when: on_success")
    assert any("artifacts.when" in x for x in v.validate(txt))


def test_release_must_need_scan():
    txt = GOOD.replace("needs: [trivy-scan]", "needs: [build]")
    assert any("release job does not need" in x for x in v.validate(txt))
