"""Tests for the EDR lab. Run from the repo root:
    .venv/Scripts/python -m pytest cybersecurity-track/07-edr-xdr-mdr
"""

import copy

import pytest

from aisec_lab import load_lab_module

az = load_lab_module(__file__, "edr_analyzer")
se = load_lab_module(__file__, "sample_events")


def rules_for(events, host):
    return {a.rule_id for a in az.run_rules(events) if a.host == host}


# ---- detections fire on the attack chain -------------------------------------------

def test_attack_chain_triggers_all_four_rules():
    assert rules_for(se.attack_chain(), "WS-ACCT-07") == {"EDR-001", "EDR-002", "EDR-003", "EDR-004"}


def test_encoded_command_is_decoded_in_evidence():
    alert = next(a for a in az.run_rules(se.attack_chain()) if a.rule_id == "EDR-001")
    assert "DownloadString" in alert.evidence


def test_three_lolbins_are_found():
    lol = [a for a in az.run_rules(se.attack_chain()) if a.rule_id == "EDR-002"]
    assert len(lol) == 3  # certutil, rundll32, mshta


# ---- benign admin activity must NOT alert ------------------------------------------

def test_benign_admin_raises_no_alerts():
    assert az.run_rules(se.benign_admin()) == []


def test_encoded_powershell_from_management_agent_is_not_rule_one():
    ev = [e for e in se.benign_admin() if e.get("guid") == "B-3"]
    assert az.encoded_command(ev[0]["command_line"])  # it IS encoded
    assert az.rule_office_encoded_powershell(ev) == []  # but the parent is not Office


def test_certutil_hashfile_is_not_a_download():
    assert az.rule_lolbin_abuse([e for e in se.benign_admin() if e.get("guid") == "B-4"]) == []


def test_rundll32_system32_applet_is_not_flagged():
    assert az.rule_lolbin_abuse([e for e in se.benign_admin() if e.get("guid") == "B-5"]) == []


def test_defender_reading_lsass_is_allowed():
    assert az.rule_lsass_access([e for e in se.benign_admin() if e.get("guid") == "B-6"]) == []


def test_lsass_access_without_memory_read_right_is_ignored():
    ev = [e for e in se.benign_admin() if e.get("guid") == "B-7"]
    assert az.rule_lsass_access(ev) == []


def test_vendor_service_in_program_files_is_not_flagged():
    assert az.rule_suspicious_service(se.benign_admin()) == []


# ---- evasion cases -----------------------------------------------------------------

def test_fake_svchost_in_public_folder_still_alerts():
    ev = copy.deepcopy([e for e in se.attack_chain() if e["event_id"] == 10])
    ev[0]["image"] = "C:\\Users\\Public\\svchost.exe"  # right name, wrong path
    assert len(az.rule_lsass_access(ev)) == 1


@pytest.mark.parametrize("flag", ["-e", "-ec", "-enc", "-EncodedCommand", "-ENCODEDCOMMAND"])
def test_flag_abbreviations_are_caught(flag):
    blob = se.ps_encode("Write-Output 'synthetic'")
    assert az.encoded_command(f"powershell.exe {flag} {blob}") == blob


def test_non_encoding_flags_are_not_matched():
    assert az.encoded_command("powershell.exe -ExecutionPolicy Bypass -File a.ps1") is None


# ---- trees -------------------------------------------------------------------------

def test_tree_links_office_to_powershell_to_children():
    roots = az.build_trees(se.attack_chain())["WS-ACCT-07"]
    word = roots[0].children[0]
    ps = word.children[0]
    assert az.base_name(word.image) == "winword.exe"
    assert az.base_name(ps.image) == "powershell.exe"
    assert {az.base_name(c.image) for c in ps.children} == {"certutil.exe", "rundll32.exe", "mshta.exe"}


def test_unknown_parent_becomes_root():
    roots = az.build_trees(se.benign_admin())["WS-IT-02"]
    assert any(az.base_name(r.image) == "powershell.exe" for r in roots)  # CcmExec parent not seen


# ---- recommendation and simulated response ----------------------------------------

def test_attack_host_gets_isolate_and_benign_hosts_get_nothing():
    responses = az.recommend(az.run_rules(se.all_events()))
    assert [r.host for r in responses] == ["WS-ACCT-07"]
    assert responses[0].action == "isolate_host"


def test_lsass_alone_means_investigate_not_isolate():
    ev = [e for e in se.attack_chain() if e["event_id"] == 10]
    [r] = az.recommend(az.run_rules(ev))
    assert r.action == "investigate"


def test_simulated_isolation_changes_state_only_in_memory():
    edr = az.SimulatedEDR()
    [r] = az.recommend(az.run_rules(se.attack_chain()))
    edr.execute(r)
    assert edr.isolated == {"WS-ACCT-07"}
    assert "already isolated" in edr.isolate_host("WS-ACCT-07")


def test_protected_host_needs_approval_to_isolate():
    edr = az.SimulatedEDR()
    r = az.Response("SRV-DC01", 100, "isolate_host", ["EDR-004"], requires_approval=True)
    assert "REFUSED" in edr.execute(r)
    assert edr.isolated == set()
    assert "ISOLATED" in edr.execute(r, approved=True)
    assert edr.isolated == {"SRV-DC01"}


def test_protected_flag_set_on_recommendation():
    ev = copy.deepcopy(se.attack_chain())
    for e in ev:
        e["host"] = "SRV-DC01"
    [r] = az.recommend(az.run_rules(ev), protected_hosts={"SRV-DC01"})
    assert r.requires_approval
