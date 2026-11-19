"""SBOM lab tests: generation, structure, and analysis (licenses, vulnerabilities, unpinned, transitive).

Run from the repository root:
    python -m pytest cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/labs/sbom-mcp-server -v
"""

import copy
import json
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

s = load_lab_module(__file__, "sbom")
HERE = Path(__file__).resolve().parent
FIX = HERE / "fixtures"
ADV = json.loads((FIX / "advisories.json").read_text())
POL = json.loads((FIX / "policy.json").read_text())
BOM = s.generate_sbom(FIX / "notes-mcp")
REPORT = s.analyze_sbom(BOM, ADV, POL)


# ------------------------------------------------------------------ generation
def test_sbom_has_cyclonedx_shape():
    assert BOM["bomFormat"] == "CycloneDX" and BOM["specVersion"] == "1.5" and BOM["serialNumber"].startswith("urn:uuid:")
    assert BOM["metadata"]["component"]["name"] == "notes-mcp"
    assert len(BOM["components"]) == 8


def test_components_have_purl_hash_and_license():
    comp = next(c for c in BOM["components"] if c["name"] == "yamlish")
    assert comp["purl"] == "pkg:pypi/yamlish@2.3.0"
    assert comp["hashes"][0]["alg"] == "SHA-256" and len(comp["hashes"][0]["content"]) == 64
    assert comp["licenses"][0]["license"]["id"] == "MIT"


def test_mcp_properties_describe_the_server():
    props = {(p["name"], p["value"]) for p in BOM["metadata"]["component"]["properties"]}
    assert ("lab:mcp:transport", "streamable-http") in props and ("lab:mcp:tool", "send_report") in props


def test_generation_is_reproducible():
    assert s.generate_sbom(FIX / "notes-mcp") == BOM


def test_serial_number_changes_when_the_lock_changes():
    other = Path(__import__("tempfile").mkdtemp())
    lock = json.loads((FIX / "notes-mcp" / "lock.json").read_text())
    lock["packages"][1]["version"] = "2.4.1"
    (other / "lock.json").write_text(json.dumps(lock))
    assert s.generate_sbom(other)["serialNumber"] != BOM["serialNumber"]


def test_dependency_graph_is_consistent():
    assert s.validate_sbom(BOM) == []
    root = BOM["dependencies"][0]
    assert root["ref"] == "notes-mcp@1.2.0" and len(root["dependsOn"]) == 4


def test_validator_catches_broken_graph_and_duplicate_refs():
    bad = copy.deepcopy(BOM)
    bad["dependencies"][1]["dependsOn"].append("pkg:pypi/ghost@1.0.0")
    bad["components"].append(copy.deepcopy(bad["components"][0]))
    problems = s.validate_sbom(bad)
    assert any("unknown component" in p for p in problems) and any("duplicate" in p for p in problems)


def test_sbom_is_json_serializable():
    assert json.loads(json.dumps(BOM)) == BOM


# ------------------------------------------------------------------ analysis
def test_counts_and_depth():
    assert REPORT["components"] == 8 and REPORT["direct"] == 4 and REPORT["transitive"] == 4
    assert REPORT["max_depth"] == 3  # notes-mcp -> mcp-sdk-lite -> httpx-lite -> h11-lite


def test_known_vulnerabilities_are_matched_by_version():
    assert set(REPORT["vulnerable"]) == {"yamlish", "h11-lite"}
    assert "pydantic-lite" not in REPORT["vulnerable"]  # advisory already fixed in the version used


def test_unpinned_denied_unknown_and_registry_findings():
    assert REPORT["unpinned"] == ["tinycrypto"]
    assert REPORT["denied_licenses"] == ["notesdb-client"]
    assert REPORT["unknown_licenses"] == ["pydantic-lite"]
    assert REPORT["bad_registry"] == ["internal-metrics"]


def test_ranking_puts_the_riskiest_first_and_verdict_needs_review():
    assert REPORT["rows"][0]["name"] == "yamlish"
    assert REPORT["acceptable"] is False


def test_a_clean_project_is_acceptable():
    clean = copy.deepcopy(BOM)
    clean["components"] = [c for c in clean["components"] if c["name"] in {"mcp-sdk-lite", "httpx-lite"}]
    clean["dependencies"] = [{"ref": "notes-mcp@1.2.0", "dependsOn": ["pkg:pypi/mcp-sdk-lite@1.4.0"]},
                             {"ref": "pkg:pypi/mcp-sdk-lite@1.4.0", "dependsOn": ["pkg:pypi/httpx-lite@0.27.0"]},
                             {"ref": "pkg:pypi/httpx-lite@0.27.0", "dependsOn": []}]
    report = s.analyze_sbom(clean, ADV, POL)
    assert report["vulnerable"] == [] and report["acceptable"] is True


def test_missing_hash_adds_a_small_risk():
    bom = copy.deepcopy(BOM)
    for c in bom["components"]:
        if c["name"] == "h11-lite":
            del c["hashes"]
    row = next(r for r in s.analyze_sbom(bom, [], POL)["rows"] if r["name"] == "h11-lite")
    assert "no hash" in row["reasons"]


def test_report_text_lists_the_findings():
    text = s.render_report(REPORT)
    assert "vulnerable: ['yamlish', 'h11-lite']" in text and "NEEDS REVIEW" in text


@pytest.mark.parametrize("a,b", [("2.3.0", "2.4.1"), ("0.14.0", "0.14.1"), ("1.9", "1.10")])
def test_version_compare_is_numeric_not_text(a, b):
    assert s._version_tuple(a) < s._version_tuple(b)
