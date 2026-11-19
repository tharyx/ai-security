"""Recon lab: the scanner finds the sloppy fleet's problems and finds none in the hardened fleet.

Run from the repository root:
    .venv/Scripts/python -m pytest cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/01-recon-enumeration -v
"""

from aisec_lab import load_lab_module

fleet = load_lab_module(__file__, "fleet")
recon = load_lab_module(__file__, "recon")
http = load_lab_module(__file__, "http_transport")
rpc = load_lab_module(__file__, "rpc")


def network(servers):
    return {addr: s.handle for addr, s in servers.items()}


def ids(endpoint):
    return {f["id"] for f in endpoint["findings"]}


def by_addr(report, prefix):
    return next(e for e in report["endpoints"] if e["address"].startswith(prefix))


def test_vulnerable_fleet_enumeration_lists_tools_resources_and_prompts():
    files = by_addr(recon.scan(network(fleet.vulnerable_fleet())), "files")
    assert files["tools"] == ["read_file", "run_shell"]
    assert files["resources"] == ["file:///srv/app/.env"]
    assert files["prompts"] == ["explain_error"]
    assert files["server"] == "file-helper"


def test_flags_unauthenticated_overbroad_sensitive_and_verbose_endpoint():
    files = by_addr(recon.scan(network(fleet.vulnerable_fleet())), "files")
    assert {"RECON-01", "RECON-02", "RECON-03", "RECON-04", "RECON-05"} <= ids(files)
    assert files["findings"][0]["severity"] == "high"  # sorted worst first


def test_error_probe_really_leaks_the_canary_to_an_anonymous_caller():
    srv = fleet.vulnerable_fleet()["files.corp.example:8001"]
    r = rpc.request(srv.handle, "tools/call", {"name": "read_file", "arguments": {"path": "/definitely/missing/file"}})
    assert fleet.ENV_CANARY in r["error"]["message"]


def test_authenticated_crm_is_not_enumerated_anonymously():
    crm = by_addr(recon.scan(network(fleet.vulnerable_fleet())), "crm")
    assert crm["auth"] == "required" and crm["tools"] == [] and crm["findings"] == []


def test_a_valid_token_lets_the_scanner_see_the_crm_and_nothing_is_wrong_with_it():
    rep = recon.scan(network(fleet.vulnerable_fleet()), tokens={"crm.corp.example:8003": "crm-secret-token"})
    crm = by_addr(rep, "crm")
    assert crm["tools"] == ["get_customer"] and crm["auth"] == "accepted"
    assert "RECON-01" not in ids(crm) and "RECON-02" not in ids(crm) and "RECON-03" not in ids(crm)


def test_hardened_fleet_shows_no_anonymous_surface_at_all():
    rep = recon.scan(network(fleet.hardened_fleet()))
    assert all(e["auth"] == "required" for e in rep["endpoints"])
    assert rep["counts"] == {}


def test_hardened_fleet_has_no_high_findings_even_with_credentials():
    tokens = {"files.corp.example:8001": "files-secret-token", "notes.corp.example:8002": "notes-secret-token",
              "crm.corp.example:8003": "crm-secret-token"}
    rep = recon.scan(network(fleet.hardened_fleet()), tokens=tokens)
    assert rep["counts"].get("high", 0) == 0
    assert "RECON-02" not in ids(by_addr(rep, "files"))  # generic errors


def test_report_renders_findings_and_owasp_mapping():
    text = recon.render_report(recon.scan(network(fleet.vulnerable_fleet())))
    assert "RECON-01" in text and "MCP07" in text and "auth=required" in text


def test_same_scan_works_over_real_localhost_http_and_the_server_is_stopped_afterwards():
    srv = fleet.vulnerable_fleet()["notes.corp.example:8002"]
    with http.serve(srv) as url:
        assert url.startswith("http://127.0.0.1:")
        ep = recon.scan_endpoint(url, http.http_transport(url))
        assert ep["tools"] == ["add_note"] and "RECON-01" in ids(ep)
    try:
        http.http_transport(url)(rpc.json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
        stopped = False
    except OSError:
        stopped = True
    assert stopped


def test_http_401_maps_to_auth_required():
    crm = fleet.vulnerable_fleet()["crm.corp.example:8003"]
    with http.serve(crm) as url:
        assert recon.scan_endpoint(url, http.http_transport(url))["auth"] == "required"


def test_serve_refuses_to_bind_to_all_interfaces():
    try:
        with http.serve(fleet.vulnerable_fleet()["notes.corp.example:8002"], host="0.0.0.0"):
            pass
        refused = False
    except ValueError:
        refused = True
    assert refused
