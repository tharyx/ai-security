import copy
import json
import secrets
import shutil
import tempfile
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

pk = load_lab_module(__file__, "packer_lab")
FIX = Path(__file__).parent / "fixtures"
GOOD_TEXT = (FIX / "golden.pkr.hcl").read_text()
BAD_TEXT = (FIX / "golden_bad.pkr.hcl").read_text()


def ids(findings):
    return {f.rule_id for f in findings}


def test_parser_reads_blocks_labels_and_objects():
    blocks = pk.parse_hcl(GOOD_TEXT)
    build = [b for b in blocks if b.type == "build"][0]
    assert build.attrs["name"] == "golden"
    assert build.find("provisioner", "ansible")[0].attrs["playbook_file"] == "./ansible/harden.yml"
    packer = [b for b in blocks if b.type == "packer"][0]
    assert packer.find("required_plugins")[0].attrs["docker"]["version"] == "~> 1.1"


def test_parser_rejects_unbalanced_and_garbage():
    with pytest.raises(ValueError):
        pk.parse_hcl("build {\n")
    with pytest.raises(ValueError):
        pk.parse_hcl("}\n")
    with pytest.raises(ValueError):
        pk.parse_hcl("this is not hcl\n")


def test_comments_inside_strings_are_kept():
    blocks = pk.parse_hcl('variable "u" {\n  default = "http://x.example/#frag"  # trailing\n}\n')
    assert blocks[0].attrs["default"] == "http://x.example/#frag"


def test_good_template_is_clean():
    assert pk.validate(pk.parse_hcl(GOOD_TEXT)) == []


def test_bad_template_fires_all_rules():
    found = pk.validate(pk.parse_hcl(BAD_TEXT))
    assert {"PKR-001", "PKR-002", "PKR-003", "PKR-004", "PKR-005", "PKR-006", "PKR-007"} <= ids(found)


def test_tag_instead_of_digest_is_flagged():
    text = GOOD_TEXT.replace("debian@sha256:89abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567", "debian:12")
    assert "PKR-001" in ids(pk.validate(pk.parse_hcl(text)))


def test_secret_default_and_missing_sensitive_flagged():
    text = GOOD_TEXT.replace("  sensitive = true\n", "").replace("  # no default", '  default = "CANARY-pw"\n  # no default')
    found = pk.validate(pk.parse_hcl(text))
    assert {f.severity for f in found if f.rule_id == "PKR-002"} == {"CRITICAL", "MEDIUM"}


def test_missing_ansible_provisioner_and_manifest():
    text = GOOD_TEXT.replace('provisioner "ansible"', 'provisioner "file"').replace('post-processor "manifest"', 'post-processor "compress"')
    assert {"PKR-003", "PKR-004"} <= ids(pk.validate(pk.parse_hcl(text)))


def test_simulated_build_is_deterministic_and_input_sensitive():
    a = pk.simulate_build(FIX / "golden.pkr.hcl")
    b = pk.simulate_build(FIX / "golden.pkr.hcl")
    assert a == b
    assert a["builds"][0]["artifact_id"].startswith("sha256:") and len(a["builds"][0]["artifact_id"]) == 71
    tmp = Path(tempfile.mkdtemp())
    try:
        shutil.copytree(FIX, tmp / "f")
        play = tmp / "f" / "ansible" / "harden.yml"
        play.write_text(play.read_text() + "    - name: extra\n      ansible.builtin.debug: {msg: hi}\n")
        c = pk.simulate_build(tmp / "f" / "golden.pkr.hcl")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    assert c["builds"][0]["artifact_id"] != a["builds"][0]["artifact_id"]


def gate_inputs():
    manifest = pk.simulate_build(FIX / "golden.pkr.hcl")
    key = secrets.token_bytes(32)
    findings = pk.validate(pk.parse_hcl(GOOD_TEXT))
    comp = json.loads((FIX / "compliance_result.json").read_text())["score"]
    scan = json.loads((FIX / "scan_result.json").read_text())
    return manifest, key, findings, comp, scan


def test_gate_promotes_a_clean_image():
    m, key, f, comp, scan = gate_inputs()
    gate = pk.promotion_gate(m, f, comp, scan, pk.sign_manifest(m, key), key)
    assert gate.decision == "PROMOTE" and gate.reasons == []


def test_gate_blocks_low_compliance_and_vulns():
    m, key, f, comp, scan = gate_inputs()
    att = pk.sign_manifest(m, key)
    assert pk.promotion_gate(m, f, 80.0, scan, att, key).decision == "BLOCK"
    bad_scan = dict(scan, critical=1)
    assert pk.promotion_gate(m, f, comp, bad_scan, att, key).decision == "BLOCK"


def test_gate_blocks_tampered_manifest_and_wrong_key():
    m, key, f, comp, scan = gate_inputs()
    att = pk.sign_manifest(m, key)
    tampered = copy.deepcopy(m)
    tampered["builds"][0]["artifact_id"] = "sha256:" + "0" * 64
    gate = pk.promotion_gate(tampered, f, comp, scan, att, key)
    assert gate.decision == "BLOCK" and any("attestation" in r for r in gate.reasons)
    other = secrets.token_bytes(32)
    assert pk.promotion_gate(m, f, comp, scan, att, other).decision == "BLOCK"


def test_gate_blocks_on_bad_template_findings():
    m, key, _f, comp, scan = gate_inputs()
    bad = pk.validate(pk.parse_hcl(BAD_TEXT))
    assert pk.promotion_gate(m, bad, comp, scan, pk.sign_manifest(m, key), key).decision == "BLOCK"
