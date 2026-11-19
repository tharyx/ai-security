from aisec_lab import load_lab_module

a = load_lab_module(__file__, "authapi")


def _token(api):
    body = (f"grant_type=client_credentials&client_id={api.client_id}"
            f"&client_secret={api.client_secret}&scope=orders:read")
    status, headers, resp = api.handle("POST", "/oauth/token", body=body)
    assert status == 200 and headers["Cache-Control"] == "no-store"
    return resp["access_token"]


def test_public_endpoint_needs_no_credentials():
    assert a.AuthApi().handle("GET", "/public")[0] == 200


def test_basic_auth_accepts_right_credentials_only():
    api = a.AuthApi()
    assert api.handle("GET", "/basic", a.basic_header(api.basic_user, api.basic_pass))[0] == 200
    status, headers, _ = api.handle("GET", "/basic", a.basic_header(api.basic_user, "wrong"))
    assert status == 401 and headers["WWW-Authenticate"].startswith("Basic")
    assert api.handle("GET", "/basic")[0] == 401


def test_basic_auth_is_only_encoding_not_encryption():
    import base64
    hdr = a.basic_header("svc", "FAKE-pw")["Authorization"]
    assert base64.b64decode(hdr[6:]).decode() == "svc:FAKE-pw"  # anyone can decode it


def test_api_key_in_header_works_but_in_url_is_refused():
    api = a.AuthApi()
    assert api.handle("GET", "/apikey", {"X-API-Key": api.api_key})[0] == 200
    assert api.handle("GET", "/apikey", {"X-API-Key": "FAKE-KEY-wrong"})[0] == 401
    assert api.handle("GET", f"/apikey?api_key={api.api_key}")[0] == 400


def test_oauth_client_credentials_then_bearer_call():
    api = a.AuthApi()
    tok = _token(api)
    status, _, body = api.handle("GET", "/bearer", {"Authorization": f"Bearer {tok}"})
    assert status == 200 and "orders:read" in body["data"]


def test_bad_client_secret_and_wrong_grant_are_refused():
    api = a.AuthApi()
    assert api.handle("POST", "/oauth/token",
                      body=f"grant_type=client_credentials&client_id={api.client_id}&client_secret=x")[0] == 401
    assert api.handle("POST", "/oauth/token", body="grant_type=password&username=u&password=p")[0] == 400


def test_tampered_bearer_token_is_rejected():
    api = a.AuthApi()
    h, p, s = _token(api).split(".")
    assert api.handle("GET", "/bearer", {"Authorization": f"Bearer {h}.{p}.AAAA"})[0] == 401
    assert api.handle("GET", "/bearer", {"Authorization": f"Bearer {h}.{p}."})[0] == 401


def test_token_from_another_instance_is_rejected():
    tok = _token(a.AuthApi())  # different signing key
    assert a.AuthApi().handle("GET", "/bearer", {"Authorization": f"Bearer {tok}"})[0] == 401


def test_mtls_trusts_only_the_tls_layer_not_a_client_header():
    api = a.AuthApi()
    assert api.handle("GET", "/mtls", tls_client_fp=api.trusted_client_fp)[0] == 200
    spoof = {"X-Client-Cert": api.trusted_client_fp}
    assert api.handle("GET", "/mtls", spoof)[0] == 401
    assert api.handle("GET", "/mtls", tls_client_fp="00" * 32)[0] == 401
