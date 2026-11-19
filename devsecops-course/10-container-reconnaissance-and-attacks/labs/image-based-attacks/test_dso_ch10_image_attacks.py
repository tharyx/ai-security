import copy

from aisec_lab import load_lab_module

ia = load_lab_module(__file__, "imgattack")
IMG = ia.sample_image()


def test_secrets_from_history_and_git_config():
    s = ia.extract_secrets(IMG)
    names = {x["name"] for x in s}
    assert "SERVICE_TOKEN" in names and "credentials in a URL" in names


def test_fixed_component_not_reported():
    ids = {p.vuln_id for p in ia.exploit_paths(IMG)}
    assert "FIXTURE-A3" not in ids and {"FIXTURE-A1", "FIXTURE-A2", "FIXTURE-A4"} <= ids


def test_network_facing_rce_is_fix_now_with_host_pivot():
    p = {x.vuln_id: x for x in ia.exploit_paths(IMG)}["FIXTURE-A1"]
    assert p.reachable and p.priority == "FIX NOW"
    assert any("docker.sock" in s for s in p.steps) and p.steps[-1] == "impact: host compromise"


def test_local_only_flaw_is_backlog_not_entry_point():
    p = {x.vuln_id: x for x in ia.exploit_paths(IMG)}["FIXTURE-A4"]
    assert not p.reachable and p.priority.startswith("BACKLOG")


def test_user_upload_parsing_is_reachable():
    p = {x.vuln_id: x for x in ia.exploit_paths(IMG)}["FIXTURE-A2"]
    assert p.reachable and "user input" in p.why


def test_hardening_changes_impact():
    img = copy.deepcopy(IMG)
    img["runtime"]["docker_sock"] = False
    img["user"] = "10001"
    p = {x.vuln_id: x for x in ia.exploit_paths(img)}["FIXTURE-A1"]
    assert p.steps[-1] == "impact: container compromise"
    assert not any("root" in s for s in p.steps)


def test_priority_sorting():
    ps = ia.exploit_paths(IMG)
    assert ps[0].priority == "FIX NOW" and ps[-1].priority.startswith("BACKLOG")


def test_closing_the_port_removes_network_reachability():
    img = copy.deepcopy(IMG)
    img["exposed_ports"] = []
    p = {x.vuln_id: x for x in ia.exploit_paths(img)}["FIXTURE-A1"]
    assert not p.reachable
