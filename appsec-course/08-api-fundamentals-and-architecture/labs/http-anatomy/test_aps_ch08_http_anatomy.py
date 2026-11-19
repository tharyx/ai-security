from aisec_lab import load_lab_module

h = load_lab_module(__file__, "httpmsg")

RAW_REQUEST = (
    "GET /api/v1/orders/42 HTTP/1.1\r\n"
    "Host: shop.example\r\n"
    "Authorization: Bearer FAKE-abc123-DEMO\r\n"
    "Accept: application/json\r\n"
    "\r\n"
)

RAW_RESPONSE = (
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: 17\r\n"
    "\r\n"
    '{"id":42,"ok":1}\n'
)


def test_parse_request_splits_line_headers_and_body():
    req = h.parse_request(RAW_REQUEST)
    assert req.method == "GET"
    assert req.target == "/api/v1/orders/42"
    assert req.version == "HTTP/1.1"
    assert req.header("Host") == "shop.example"
    assert req.header("authorization") == "Bearer FAKE-abc123-DEMO"


def test_parse_response_reads_status_and_headers():
    resp = h.parse_response(RAW_RESPONSE)
    assert resp.status == 200
    assert resp.header("content-type") == "application/json"
    assert resp.body.startswith('{"id":42')


def test_malformed_request_line_is_rejected():
    for bad in ["", "GET\r\n\r\n", "GET /x HTTP/1.1 extra\r\n\r\n"]:
        try:
            h.parse_request(bad)
            raised = False
        except ValueError:
            raised = True
        assert raised, f"should reject {bad!r}"


def test_status_class_from_first_digit():
    assert h.status_class(200) == "Success"
    assert h.status_class(301) == "Redirection"
    assert h.status_class(404) == "Client error"
    assert h.status_class(503) == "Server error"


def test_build_response_adds_content_length():
    raw = h.build_response(201, {"Location": "/api/v1/orders/42"}, body="created")
    resp = h.parse_response(raw)
    assert resp.status == 201
    assert resp.header("content-length") == str(len("created"))
    assert resp.header("location") == "/api/v1/orders/42"


def test_stateless_api_needs_token_on_every_request_and_keeps_no_state():
    token = h.make_fake_token()
    api = h.StatelessApi({token})
    good = h.parse_request(f"GET /me HTTP/1.1\r\nAuthorization: Bearer {token}\r\n\r\n")
    bad = h.parse_request("GET /me HTTP/1.1\r\n\r\n")
    assert api.handle(good).status == 200
    assert api.handle(bad).status == 401
    # A second valid call still works, and the server never stored anything.
    assert api.handle(good).status == 200
    assert api.server_state_entries == 0


def test_stateful_api_tracks_a_server_side_session_by_cookie():
    api = h.StatefulApi()
    login = api.login("alice")
    assert api.server_state_entries == 1
    set_cookie = login.header("set-cookie")
    assert "HttpOnly" in set_cookie and "Secure" in set_cookie
    sid = set_cookie.split("session=", 1)[1].split(";", 1)[0]
    with_cookie = h.parse_request(f"GET /me HTTP/1.1\r\nCookie: session={sid}\r\n\r\n")
    without = h.parse_request("GET /me HTTP/1.1\r\n\r\n")
    assert api.handle(with_cookie).status == 200
    assert "alice" in api.handle(with_cookie).body
    assert api.handle(without).status == 401


def test_fake_token_is_labelled_and_not_a_real_format():
    tok = h.make_fake_token()
    assert tok.startswith("FAKE-") and tok.endswith("-DEMO")
