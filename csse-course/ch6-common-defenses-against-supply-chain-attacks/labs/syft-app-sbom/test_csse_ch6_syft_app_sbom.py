"""Tests for the lockfile -> CycloneDX generator."""

from aisec_lab import load_lab_module

s = load_lab_module(__file__, "app_sbom")


def test_requirements_parsed_and_unpinned_reported():
    comps, unpinned = s.parse_requirements(s.SAMPLE_REQUIREMENTS)
    assert {c["name"] for c in comps} == {"flask", "requests", "jinja2"}
    assert unpinned == ["urllib3>=2.0"]


def test_hash_captured_from_requirements():
    comps, _ = s.parse_requirements(s.SAMPLE_REQUIREMENTS)
    assert [c["hash"] for c in comps if c["name"] == "requests"] == ["sha256:aaaa1111"]


def test_npm_lock_direct_vs_transitive_and_dev_scope():
    comps = {c["name"]: c for c in s.parse_npm_lock(s.SAMPLE_NPM_LOCK)}
    assert comps["express"]["direct"] and not comps["qs"]["direct"]
    assert comps["@scope/util"]["scope"] == "optional"


def test_purl_scoped_npm_name_is_encoded():
    assert s.purl({"ecosystem": "npm", "name": "@scope/util", "version": "2.1.0"}) == "pkg:npm/%40scope/util@2.1.0"


def test_cyclonedx_document_is_valid_and_complete():
    doc = s.build("demo-app", s.SAMPLE_REQUIREMENTS, s.SAMPLE_NPM_LOCK)
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.5"
    assert s.validate(doc) == [] and len(doc["components"]) == 6


def test_hashes_and_licenses_emitted():
    doc = s.build("demo-app", s.SAMPLE_REQUIREMENTS, s.SAMPLE_NPM_LOCK)
    req = next(c for c in doc["components"] if c["name"] == "requests")
    assert req["hashes"][0]["alg"] == "SHA-256"
    exp = next(c for c in doc["components"] if c["name"] == "express")
    assert exp["licenses"][0]["license"]["id"] == "MIT"


def test_output_is_reproducible():
    a = s.build("demo-app", s.SAMPLE_REQUIREMENTS)
    b = s.build("demo-app", s.SAMPLE_REQUIREMENTS)
    assert s.sbom_digest(a) == s.sbom_digest(b)


def test_validator_catches_problems():
    doc = s.build("demo-app", s.SAMPLE_REQUIREMENTS)
    doc["components"].append(dict(doc["components"][0]))
    doc["serialNumber"] = "bad"
    errs = s.validate(doc)
    assert any("duplicate" in e for e in errs) and any("serialNumber" in e for e in errs)
