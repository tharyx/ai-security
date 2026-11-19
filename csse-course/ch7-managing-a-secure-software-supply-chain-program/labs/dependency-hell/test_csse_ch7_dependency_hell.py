import copy
import json
import pathlib

import pytest

from aisec_lab import load_lab_module

r = load_lab_module(__file__, "resolver")
DATA = json.loads((pathlib.Path(__file__).parent / "fixtures" / "registry.json").read_text())
ROOT = {"web-framework": "^2.0.0", "report-gen": "~1.3.0"}


@pytest.fixture
def reg():
    return r.Registry(copy.deepcopy(DATA))


@pytest.mark.parametrize("v,spec,expected", [
    ("1.2.3", "^1.2.0", True), ("2.0.0", "^1.2.0", False), ("0.2.5", "^0.2.0", True),
    ("0.3.0", "^0.2.0", False), ("1.3.9", "~1.3.0", True), ("1.4.0", "~1.3.0", False),
    ("1.0.0", "*", True), ("1.5.0", ">=1.0,<2.0", True), ("2.0.0", ">=1.0,<2.0", False),
    ("2.1.0", "^1.4.0 || ^2.0.0", True), ("3.0.0", "^1.4.0 || ^2.0.0", False),
    ("1.9.0", "==1.9.0", True), ("1.9.1", "==1.9.0", False), ("1.9.0", "1.9.0", True),
    ("0.0.3", "^0.0.3", True), ("0.0.4", "^0.0.3", False),
])
def test_satisfies(v, spec, expected):
    assert r.satisfies(v, spec) is expected


def test_diamond_conflict_is_detected_and_explained(reg):
    res = r.resolve_flat(reg, ROOT)
    assert not res.ok
    c = res.conflicts[0]
    assert c.package == "json-lib"
    text = c.explain()
    assert "^1.0.0" in text and "^2.0.0" in text


def test_flat_resolve_picks_highest_when_no_conflict(reg):
    res = r.resolve_flat(reg, {"web-framework": "^2.0.0"})
    assert res.ok and res.versions["web-framework"] == "2.1.0" and res.versions["json-lib"] == "2.2.0"


def test_relaxing_the_frozen_dependency_solves_it(reg):
    res = r.resolve_flat(reg, {"web-framework": "^2.0.0", "report-gen": "^1.0.0"})
    assert res.ok and res.versions["report-gen"] == "1.5.0" and res.versions["json-lib"] == "2.2.0"
    assert res.violated == []


def test_nested_install_succeeds_with_duplicates(reg):
    res = r.resolve_nested(reg, ROOT)
    assert res.ok
    assert res.duplicates() == {"json-lib": ["1.9.0", "2.2.0"]}


def test_nested_install_ships_a_vulnerable_copy(reg):
    vulns = r.audit(reg, r.resolve_nested(reg, ROOT))
    assert [(v["package"], v["version"]) for v in vulns] == [("json-lib", "1.9.0")]


def test_pin_alone_cannot_break_the_conflict(reg):
    assert not r.resolve_flat(reg, ROOT, pins={"json-lib": "1.9.0"}).ok
    assert not r.resolve_flat(reg, ROOT, pins={"json-lib": "2.2.0"}).ok


def test_override_to_old_version_resolves_but_stays_vulnerable_and_breaks_a_range(reg):
    res = r.resolve_flat(reg, ROOT, overrides={"json-lib": "==1.9.0"})
    assert res.ok and res.versions["json-lib"] == "1.9.0"
    assert len(r.audit(reg, res)) == 1
    assert any(v[0].startswith("web-framework") for v in res.violated)


def test_override_to_new_version_is_secure_but_runs_outside_declared_range(reg):
    res = r.resolve_flat(reg, ROOT, overrides={"json-lib": "^2.0.0"})
    assert res.ok and res.versions["json-lib"] == "2.2.0"
    assert r.audit(reg, res) == []
    assert any(v[0].startswith("report-gen") and v[1] == "json-lib" for v in res.violated)


def test_suggest_upgrades_finds_the_clean_fix(reg):
    assert r.suggest_upgrades(reg, ROOT, "report-gen") == ["1.5.0"]


def test_compare_strategies_table(reg):
    rows = {x["strategy"]: x for x in r.compare_strategies(reg, ROOT, "json-lib", "1.9.0", "^2.0.0", "report-gen")}
    assert rows["plain flat resolve (pip-style)"]["ok"] is False
    assert rows["nested install (npm-style)"]["vulnerable"] == 1 and rows["nested install (npm-style)"]["duplicates"] == 1
    assert rows["override json-lib -> 1.9.0"]["vulnerable"] == 1
    assert rows["override json-lib -> ^2.0.0"]["violated_ranges"] >= 1
    best = rows["upgrade report-gen to 1.5.0"]
    assert best["ok"] and best["vulnerable"] == 0 and best["violated_ranges"] == 0 and best["duplicates"] == 0


def test_lockfile_freezes_versions_against_new_releases(reg):
    res = r.resolve_flat(reg, {"web-framework": "^2.0.0"})
    lock = r.make_lockfile(reg, res)
    reg.packages["json-lib"]["versions"]["2.3.0"] = {"deps": {}}
    assert dict(r.install_from_lockfile(reg, lock).pairs())["json-lib"] == "2.2.0"
    assert r.resolve_flat(reg, {"web-framework": "^2.0.0"}).versions["json-lib"] == "2.3.0"


def test_lockfile_detects_changed_artifact(reg):
    lock = r.make_lockfile(reg, r.resolve_flat(reg, {"web-framework": "^2.0.0"}))
    reg.packages["json-lib"]["versions"]["2.2.0"]["integrity"] = "sha256-republished"
    with pytest.raises(r.LockfileError, match="integrity"):
        r.install_from_lockfile(reg, lock)


def test_lockfile_missing_version_fails(reg):
    lock = r.make_lockfile(reg, r.resolve_flat(reg, {"web-framework": "^2.0.0"}))
    del reg.packages["json-lib"]["versions"]["2.2.0"]
    with pytest.raises(r.LockfileError, match="not in the registry"):
        r.install_from_lockfile(reg, lock)


def test_lock_drift_detection(reg):
    lock = r.make_lockfile(reg, r.resolve_flat(reg, {"web-framework": "^2.0.0"}))
    assert r.lock_satisfies({"web-framework": "^2.0.0"}, lock) == []
    assert r.lock_satisfies({"web-framework": "^3.0.0"}, lock) == ["web-framework"]


def test_a_lockfile_pins_a_vulnerable_version_until_someone_updates_it(reg):
    reg.packages["json-lib"]["versions"].pop("2.2.0")
    reg.packages["json-lib"]["versions"].pop("2.1.0")
    lock = r.make_lockfile(reg, r.resolve_flat(reg, {"web-framework": "^2.0.0"}))
    assert r.audit(reg, r.install_from_lockfile(reg, lock))  # vulnerable 2.0.0, frozen


def test_vendoring_goes_stale(reg):
    vend = r.vendor(r.resolve_flat(reg, {"web-framework": "^2.0.0"}))
    reg.packages["http-core"]["versions"]["1.2.0"] = {"deps": {}}
    stale = r.vendored_staleness(reg, vend)
    assert any(s.startswith("http-core") for s in stale)
    assert all(m["vendored"] for m in vend.values())


def test_unknown_package_reports_conflict(reg):
    res = r.resolve_flat(reg, {"ghost-package": "^1.0.0"})
    assert not res.ok and res.conflicts[0].package == "ghost-package"


def test_registry_not_mutated_by_resolution(reg):
    before = copy.deepcopy(reg.packages)
    r.resolve_flat(reg, ROOT)
    r.resolve_nested(reg, ROOT)
    assert reg.packages == before
