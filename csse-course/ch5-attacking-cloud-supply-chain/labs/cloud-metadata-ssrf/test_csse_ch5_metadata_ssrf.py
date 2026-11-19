"""Tests for the simulated IMDS and SSRF defenses (no network)."""

from aisec_lab import load_lab_module

m = load_lab_module(__file__, "imds")
V1 = "http://169.254.169.254/latest/meta-data/iam/security-credentials/web-role"
TOK = "http://169.254.169.254/latest/api/token"
TTL = {"X-aws-ec2-metadata-token-ttl-seconds": "60"}


def test_imdsv1_leaks_credentials_via_ssrf():
    net = m.Network(aws=m.AwsIMDS(v2_required=False))
    code, body = m.vulnerable_preview(net, V1)
    assert code == 200 and "FAKE-SESSION-TOKEN" in body


def test_imdsv2_blocks_simple_get_ssrf():
    net = m.Network(aws=m.AwsIMDS(v2_required=True))
    assert m.vulnerable_preview(net, V1)[0] == 401


def test_imdsv2_token_flow_works_for_the_instance():
    net = m.Network(aws=m.AwsIMDS(v2_required=True))
    code, tok = net.request("PUT", TOK, TTL)
    assert code == 200
    code, body = net.request("GET", V1, {"X-aws-ec2-metadata-token": tok})
    assert code == 200 and "AccessKeyId" in body


def test_imdsv2_rejects_put_without_ttl_header():
    net = m.Network(aws=m.AwsIMDS(v2_required=True))
    assert net.request("PUT", TOK, {})[0] == 400


def test_hop_limit_blocks_container_token_request():
    net = m.Network(aws=m.AwsIMDS(v2_required=True, hop_limit=1))
    assert net.request("PUT", TOK, TTL, hops=2)[0] == 0
    net2 = m.Network(aws=m.AwsIMDS(v2_required=True, hop_limit=2))
    assert net2.request("PUT", TOK, TTL, hops=2)[0] == 200


def test_forwarded_header_rejected():
    net = m.Network(aws=m.AwsIMDS(v2_required=False))
    assert net.request("GET", V1, {"X-Forwarded-For": "203.0.113.5"})[0] == 403


def test_get_only_ssrf_cannot_obtain_a_token():
    net = m.Network(aws=m.AwsIMDS(v2_required=True))
    assert m.vulnerable_preview(net, TOK, attacker_method="GET")[0] in (401, 405)


def test_azure_requires_metadata_header():
    net = m.Network(azure=m.AzureIMDS())
    u = "http://169.254.169.254/metadata/identity/oauth2/token?resource=x"
    assert m.vulnerable_preview(net, u)[0] == 400
    assert m.vulnerable_preview(net, u, attacker_controls_headers=True)[0] == 200  # a header is not a full defense


def test_gcp_requires_metadata_flavor():
    net = m.Network(gcp=m.GcpMetadata())
    u = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
    assert m.vulnerable_preview(net, u)[0] == 403
    assert m.vulnerable_preview(net, u, attacker_controls_headers=True)[0] == 200


def test_imdsv2_holds_even_if_attacker_sets_headers_on_one_get():
    net = m.Network(aws=m.AwsIMDS(v2_required=True))
    assert m.vulnerable_preview(net, V1, attacker_controls_headers=True)[0] == 401


def test_is_blocked_obfuscated_forms():
    for u in ("http://169.254.169.254/", "http://2852039166/", "http://0xA9FEA9FE/", "http://metadata.google.internal/",
              "http://[::ffff:169.254.169.254]/", "http://127.0.0.1:8080/", "file:///etc/passwd", "http://10.0.0.5/"):
        assert m.is_blocked(u), u


def test_name_resolving_to_metadata_is_blocked():
    assert m.is_blocked("http://innocent.example/", {"innocent.example": ["169.254.169.254"]})
    assert not m.is_blocked("http://docs.example/", {"docs.example": ["93.184.216.34"]})


def test_unresolvable_host_fails_closed():
    assert m.is_blocked("http://nope.example/")


def test_safe_preview_checks_redirect_hops():
    net = m.Network(aws=m.AwsIMDS())
    res = {"docs.example": ["93.184.216.34"]}
    code, msg = m.safe_preview(net, "http://docs.example/", res, redirects=["http://169.254.169.254/latest/meta-data/"])
    assert code == 403 and "blocked" in msg
    assert m.safe_preview(net, "http://docs.example/", res)[0] == 200
