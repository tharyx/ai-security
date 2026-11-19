import copy
import json
from pathlib import Path

from aisec_lab import load_lab_module

pe = load_lab_module(__file__, "privesc")
FIX = Path(__file__).parent / "fixtures"
HOST = json.loads((FIX / "host.json").read_text())
ROOTLESS = json.loads((FIX / "host-rootless.json").read_text())


def chains(host):
    return pe.analyze_host(host)


def test_docker_group_members_are_root_equivalent():
    c = {x.who: x for x in chains(HOST) if x.severity == "CRITICAL"}
    assert set(c) == {"alice", "deploy"}
    assert "root-equivalent on the host" in c["alice"].chain[-1]


def test_non_member_not_flagged():
    assert not any(x.who == "bob" for x in chains(HOST))


def test_userns_remap_lowers_severity():
    h = copy.deepcopy(HOST)
    h["daemon"]["userns_remap"] = True
    sev = {x.who: x.severity for x in chains(h) if x.who in ("alice", "deploy") and "docker" in x.chain[0]}
    assert sev == {"alice": "HIGH", "deploy": "HIGH"}


def test_rootless_docker_group_is_low():
    c = chains(ROOTLESS)
    assert [x.severity for x in c] == ["LOW"] and "ROOTLESS" in c[0].chain[0]


def test_passwordless_sudo_flagged():
    assert any(x.who == "deploy" and "sudo" in x.chain[0] for x in chains(HOST))


def test_world_writable_socket_critical():
    h = copy.deepcopy(HOST)
    h["socket"]["mode"] = "666"
    assert any(x.who == "any local user" and x.severity == "CRITICAL" for x in chains(h))


def test_container_misconfigs_found_for_uploader_only():
    who = {x.who for x in chains(HOST)}
    assert "uploader" in who and "static-web" not in who


def test_checklist():
    assert "rootful daemon with no user namespace remapping" in pe.misconfiguration_checklist(HOST)
    assert pe.misconfiguration_checklist(ROOTLESS) == []
