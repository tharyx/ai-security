from aisec_lab import load_lab_module

oc = load_lab_module(__file__, "owasp_containers")
DIRECT = f"http://{oc.METADATA_IP}{oc.ROLE_PATH}"
DECIMAL = f"http://2852039166{oc.ROLE_PATH}"


def test_top10_has_ten_unique_codes_and_labs():
    assert [t[0] for t in oc.TOP10] == [f"A{i:02d}" for i in range(1, 11)]
    assert all(t[2] and t[3] for t in oc.TOP10)


def test_ssrf_leaks_role_credentials_on_imdsv1_without_filter():
    status, body = oc.VulnerableApp(oc.MetadataService(1), "none").fetch(DIRECT)
    assert status == 200 and body["SecretAccessKey"].startswith("canary-")


def test_naive_blocklist_is_bypassed_by_decimal_ip():
    app = oc.VulnerableApp(oc.MetadataService(1), "naive-blocklist")
    assert app.fetch(DIRECT)[0] == 403
    assert app.fetch(DECIMAL)[0] == 200          # same address, different spelling


def test_canonical_host_normalises_spellings():
    assert oc.canonical_host("2852039166") == "169.254.169.254"
    assert oc.canonical_host("0xA9FEA9FE") == "169.254.169.254"
    assert oc.canonical_host("example.com") == "example.com"


def test_strict_filter_blocks_both_and_allows_allowlisted_host():
    app = oc.VulnerableApp(oc.MetadataService(1), "strict")
    assert app.fetch(DIRECT)[0] == 403 and app.fetch(DECIMAL)[0] == 403
    assert app.fetch("https://images.example.net/logo.png")[0] == 200
    assert app.fetch("http://evil.example/x")[0] == 403


def test_imdsv2_stops_plain_get_ssrf_even_without_a_filter():
    app = oc.VulnerableApp(oc.MetadataService(2), "none")
    assert app.fetch(DIRECT)[0] == 401


def test_hop_limit_one_blocks_container_token_request():
    md = oc.MetadataService(2, hop_limit=1)
    assert md.put_token(from_container=False)
    assert md.put_token(from_container=True) is None
    assert oc.MetadataService(2, hop_limit=2).put_token(from_container=True)


def test_credentials_are_canaries_not_real_formats():
    creds = oc.role_credentials()
    assert not creds["AccessKeyId"].startswith("AKIA") and "canary" in creds["SecretAccessKey"]


def test_matrix_shape():
    rows = oc.ssrf_matrix()
    assert len(rows) == 12
    assert [s for n, _, s in rows if n.startswith("IMDSv1, no filter")] == [200, 200, 200]
