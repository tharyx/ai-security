import importlib.util
import sys
from pathlib import Path

from aisec_lab import load_lab_module

cp = load_lab_module(__file__, "compare")
HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location("csse3_lint06_mini", HERE.parents[3] / "06-ai-devsecops/docker/lab/dockerfile_lint.py")
lint06 = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = lint06
spec.loader.exec_module(lint06)
VARIANTS = cp.load(HERE / "fixtures/images.json")


def lint(name):
    return lint06.lint((HERE / "examples" / name).read_text())


def test_ranking_goes_from_full_to_scratch():
    names = [r["name"] for r in cp.table(VARIANTS)]
    assert names[0] == "python:3.12 (full)" and names[-1] == "scratch + static Go binary"


def test_scratch_is_smallest_and_has_no_packages_or_shell():
    s = VARIANTS[-1]
    assert s["size_mb"] == min(v["size_mb"] for v in VARIANTS) and s["packages"] == 0 and not s["has_shell"]


def test_distroless_has_no_shell_or_package_manager():
    d = next(v for v in VARIANTS if "distroless" in v["name"])
    assert not d["has_shell"] and not d["has_pkg_manager"] and d["runs_as"] == "nonroot"


def test_score_is_monotonic_for_each_extra_tool():
    v = dict(VARIANTS[-1])
    base = cp.score(v)
    assert cp.score({**v, "has_shell": True}) > base and cp.score({**v, "runs_as": "root"}) > base


def test_size_reduction_percentages():
    rows = {r["name"]: r for r in cp.table(VARIANTS)}
    assert rows["python:3.12 (full)"]["size_vs_full"] == "100%" and rows["scratch + static Go binary"]["size_vs_full"] == "1%"


def test_bloated_example_trips_many_rules():
    assert {"DF-002", "DF-003", "DF-008", "DF-009", "DF-012"} <= {f.rule_id for f in lint("Dockerfile.bloated")}


def test_multistage_examples_lint_clean():
    assert lint("Dockerfile.go-scratch") == []
    assert lint("Dockerfile.python-distroless") == []


def test_multistage_examples_have_two_stages_and_copy_from():
    for name in ("Dockerfile.go-scratch", "Dockerfile.python-distroless"):
        text = (HERE / "examples" / name).read_text()
        assert text.count("FROM ") == 2 and "COPY --from=build" in text


def test_tradeoffs_mention_debugging():
    assert "ephemeral" in cp.tradeoffs()["debugging"]
