"""Tests for sbom_gen.py"""

from __future__ import annotations

import copy
import json
from pathlib import Path

from aisec_lab import load_lab_module

sg = load_lab_module(__file__, "sbom_gen")
ENV = json.loads((Path(__file__).resolve().parent / "fixture_env.json").read_text(encoding="utf-8"))


def bom():
    return sg.build_bom(copy.deepcopy(ENV))


def components(b, kind):
    return [c for c in b["components"] if c["type"] == kind]


def test_generated_bom_passes_validation():
    assert sg.validate_bom(bom()) == []


def test_bom_is_deterministic_and_json_serializable():
    a, b = bom(), bom()
    assert a == b
    assert json.loads(json.dumps(a)) == a
    assert a["bomFormat"] == "CycloneDX" and a["serialNumber"].startswith("urn:uuid:")


def test_libraries_have_purl_hash_license():
    libs = components(bom(), "library")
    assert len(libs) == 5
    for c in libs:
        assert c["purl"].startswith("pkg:pypi/") and "@" in c["purl"]
        assert len(c["hashes"][0]["content"]) == 64
        assert c["licenses"]


def test_mlbom_entry_has_dataset_license_hash_and_card():
    models = components(bom(), "machine-learning-model")
    m = next(c for c in models if c["name"] == "tiny-support-classifier")
    assert m["hashes"][0]["alg"] == "SHA-256" and m["licenses"][0]["license"]["id"] == "Apache-2.0"
    card = m["modelCard"]
    assert len(card["modelParameters"]["datasets"]) == 2
    assert card["considerations"]["useCases"]
    data_names = {c["name"] for c in components(bom(), "data")}
    assert data_names == {"support-tickets-2024-redacted", "public-faq-crawl"}


def test_dependency_graph_links_app_to_model_and_libraries():
    b = bom()
    app_ref = b["metadata"]["component"]["bom-ref"]
    app_deps = next(d for d in b["dependencies"] if d["ref"] == app_ref)["dependsOn"]
    assert "pkg:pypi/requests@2.32.3" in app_deps and "model:tiny-support-classifier@0.3.0" in app_deps
    req = next(d for d in b["dependencies"] if d["ref"] == "pkg:pypi/requests@2.32.3")
    assert set(req["dependsOn"]) == {"pkg:pypi/urllib3@2.2.2", "pkg:pypi/certifi@2024.7.4"}


def test_non_spdx_license_uses_name_field():
    b = bom()
    ds = next(c for c in components(b, "data") if c["name"] == "support-tickets-2024-redacted")
    assert ds["licenses"] == [{"license": {"name": "proprietary"}}]


def test_validation_catches_missing_model_dataset():
    b = bom()
    m = next(c for c in b["components"] if c["name"] == "tiny-support-classifier")
    m["modelCard"]["modelParameters"]["datasets"] = []
    assert any("no training dataset" in p for p in sg.validate_bom(b))


def test_validation_catches_missing_model_hash_and_license():
    b = bom()
    m = next(c for c in b["components"] if c["name"] == "tiny-support-classifier")
    del m["hashes"], m["licenses"]
    problems = sg.validate_bom(b)
    assert any("model has no hash" in p for p in problems)
    assert any("model has no license" in p for p in problems)


def test_validation_catches_bad_hash_purl_and_dangling_refs():
    b = bom()
    b["components"][0]["hashes"][0]["content"] = "xyz"
    b["components"][1]["purl"] = "requests-2.0"
    b["dependencies"].append({"ref": "pkg:pypi/ghost@1", "dependsOn": []})
    b["dependencies"][0]["dependsOn"].append("pkg:pypi/other-ghost@1")
    problems = sg.validate_bom(b)
    assert any("bad hash" in p for p in problems)
    assert any("bad or missing purl" in p for p in problems)
    assert any("ghost@1 is not a component" in p for p in problems)
    assert any("other-ghost@1 is not a component" in p for p in problems)


def test_validation_catches_duplicate_refs():
    b = bom()
    b["components"].append(copy.deepcopy(b["components"][0]))
    assert any("duplicate bom-ref" in p for p in sg.validate_bom(b))


def test_cli_prints_json(capsys):
    assert sg.main([]) == 0
    assert json.loads(capsys.readouterr().out)["specVersion"] == "1.5"
