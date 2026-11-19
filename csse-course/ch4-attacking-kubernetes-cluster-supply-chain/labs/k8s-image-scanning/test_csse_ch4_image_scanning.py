from pathlib import Path

import yaml
from aisec_lab import load_lab_module

isc = load_lab_module(__file__, "image_scan")
FIX = Path(__file__).parent / "fixtures"
DOCS = [d for d in yaml.safe_load_all((FIX / "deploy.yaml").read_text()) if d]
DB = isc.load_db(FIX / "vulndb.json")
REPORTS = {r.ref: r for r in isc.scan_manifests(DOCS, DB)}
API = "registry.corp.example/shop/api:1.4"
WEB_TAG = "registry.corp.example/shop/web:1.4"


def test_extracts_images_from_init_containers_and_cronjobs():
    imgs = isc.extract_images(DOCS)
    assert API in imgs and "Deployment/web:migrate" in imgs[API]
    assert "CronJob/report:report" in imgs[WEB_TAG]
    assert len(imgs) == 5


def test_critical_and_high_thresholds():
    r = REPORTS[API]
    assert r.counts["CRITICAL"] == 1 and r.counts["HIGH"] == 3
    assert any("critical" in p for p in r.problems) and any("high" in p for p in r.problems)


def test_unpinned_tag_is_a_problem_even_if_clean():
    assert any("digest" in p for p in REPORTS[WEB_TAG].problems)


def test_digest_pinned_image_is_looked_up_by_digest():
    ref = next(k for k in REPORTS if "@sha256:" in k)
    assert REPORTS[ref].counts["MEDIUM"] == 1 and REPORTS[ref].problems == []


def test_unknown_registry_and_never_scanned():
    r = REPORTS["ghcr.io/someone/tools:latest"]
    assert any("not allowed" in p for p in r.problems) and any("never scanned" in p for p in r.problems)


def test_docker_hub_default_registry_is_resolved():
    assert isc.registry_of("nginx:1.27") == "docker.io" and isc.registry_of("localhost:5000/x") == "localhost:5000"


def test_gate_fails_overall_and_passes_for_clean_set():
    assert isc.gate(list(REPORTS.values())) is False
    only = {"kind": "Pod", "metadata": {"name": "p"}, "spec": {"containers": [{"name": "c", "image": "registry.corp.example/shop/web@sha256:" + "a" * 64}]}}
    assert isc.gate(isc.scan_manifests([only], DB))


def test_fixable_lists_only_fixed_versions():
    assert "parser-example -> None" not in isc.fixable(REPORTS[API]) and len(isc.fixable(REPORTS[API])) == 3


def test_relaxed_policy_changes_the_outcome():
    relaxed = isc.Policy(allowed_registries=("registry.corp.example", "docker.io", "ghcr.io"), max_critical=5, max_high=10, require_digest=False)
    reports = isc.scan_manifests(DOCS, DB, relaxed)
    assert [p for r in reports for p in r.problems] == ["never scanned: no entry in the vulnerability database"]
