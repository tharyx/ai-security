import json
from pathlib import Path

from aisec_lab import load_lab_module

sn = load_lab_module(__file__, "sniff")
FIX = Path(__file__).parent / "fixtures"
FLOWS = sn.load(FIX / "capture.json")
MESH = json.loads((FIX / "peer-authentication.json").read_text())


def kinds(flows):
    return {e.kind for e in sn.find_exposures(flows)}


def test_plaintext_flows_expose_credentials():
    assert {"password-field", "bearer-token"} <= kinds(FLOWS)


def test_tls_flow_exposes_nothing():
    vault = [f for f in FLOWS if f["dst"] == "vault"]
    assert sn.find_exposures(vault) == []


def test_exposures_are_redacted():
    assert all("hunter2" not in e.redacted and "FAKE-hunter2" not in e.redacted for e in sn.find_exposures(FLOWS))


def test_strict_mtls_hides_meshed_flows():
    after = sn.apply_mesh(FLOWS, MESH)
    left = [(e.flow, e.kind) for e in sn.find_exposures(after)]
    assert left == [("web -> cache:6379", "redis-auth")]  # the cache is not in the mesh, so it stays readable


def test_permissive_mode_does_not_force_encryption():
    permissive = {**MESH, "spec": {"mtls": {"mode": "PERMISSIVE"}}}
    assert len(sn.find_exposures(sn.apply_mesh(FLOWS, permissive))) == len(sn.find_exposures(FLOWS))


def test_unmeshed_workload_stays_plaintext():
    assert sn.mtls_gaps(FLOWS, MESH) == ["web -> cache:6379"]


def test_metadata_leaks_even_with_encryption():
    after = sn.apply_mesh(FLOWS, MESH)
    assert len(sn.metadata_visible(after)) == len(FLOWS)


def test_can_sniff_depends_on_net_raw():
    pod = {"spec": {"containers": [{"name": "a", "image": "x"}]}}
    assert sn.can_sniff(pod)[0]
    pod["spec"]["containers"][0]["securityContext"] = {"capabilities": {"drop": ["NET_RAW"]}}
    assert not sn.can_sniff(pod)[0]


def test_host_network_widens_scope():
    pod = {"spec": {"hostNetwork": True, "containers": [{"name": "a", "image": "x"}]}}
    assert "whole node network" in sn.can_sniff(pod)[1]
