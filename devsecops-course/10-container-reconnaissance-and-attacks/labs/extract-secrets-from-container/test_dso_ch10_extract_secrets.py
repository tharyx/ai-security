from aisec_lab import load_lab_module

ex = load_lab_module(__file__, "extractor")
FX = ex.build_fixture()
FINDS = ex.investigate(FX)


def where(source):
    return {f["where"] for f in FINDS if f["source"] == source}


def test_env_secrets_found_and_file_reference_is_ok():
    env = {f["where"]: f for f in FINDS if f["source"] == "env"}
    assert env["API_TOKEN"]["is_leak"] and env["DB_PASSWORD"]["is_leak"]
    assert env["DB_PASSWORD_FILE"]["is_leak"] is False


def test_tls_key_found_certificate_is_low_risk():
    files = {f["where"]: f for f in FINDS if f["source"] == "file"}
    assert files["/etc/ssl/private/server.key"]["kind"] == "TLS/private key"
    assert files["/etc/ssl/certs/server.crt"]["is_leak"] is False


def test_config_credentials_found():
    assert any(w.startswith("/app/config.yml:password") for w in where("file"))
    assert any(w.startswith("/app/config.yml:service_token") for w in where("file"))


def test_image_history_secret_found():
    assert len(where("image history")) == 2        # echo TOKEN > .env  and curl -u user:pw


def test_proc_environ_found():
    assert "API_TOKEN" in where("/proc/1/environ")


def test_previews_are_redacted():
    for f in FINDS:
        assert ex.canary_token() not in f["preview"]
        assert "canary-db-pw-1" not in f["preview"]


def test_innocent_file_not_flagged():
    assert not any("readme" in f["where"] for f in FINDS)


def test_no_literal_key_markers_in_source():
    src = open(ex.__file__, encoding="utf-8").read()
    assert "-----BEGIN FAKE" not in src and "cn-token-9d41" not in src


def test_entropy_orders_random_above_words():
    assert ex.entropy("aZ3$kq9Lx0Pw7Rt2") > ex.entropy("passwordpassword")
