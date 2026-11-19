from aisec_lab import load_lab_module

t = load_lab_module(__file__, "toyapi")


def test_full_crud_cycle_changes_state():
    api = t.ToyApi()
    # Create
    r = api.handle("POST", "/api/v1/items", body={"name": "widget"})
    assert r.status == 201
    assert r.body["id"] == 1
    assert r.headers["Location"] == "/api/v1/items/1"
    # Read one
    assert api.handle("GET", "/api/v1/items/1").body["name"] == "widget"
    # Update
    u = api.handle("PUT", "/api/v1/items/1", body={"name": "gadget"})
    assert u.status == 200 and u.body["name"] == "gadget"
    # List
    assert len(api.handle("GET", "/api/v1/items").body) == 1
    # Delete
    assert api.handle("DELETE", "/api/v1/items/1").status == 204
    assert api.handle("GET", "/api/v1/items/1").status == 404


def test_verbs_map_to_the_right_operations():
    api = t.ToyApi()
    api.handle("POST", "/api/v1/items", body={"name": "a"})
    # wrong verb on a collection
    assert api.handle("DELETE", "/api/v1/items").status == 405
    # unknown path
    assert api.handle("GET", "/api/v1/other").status == 404


def test_create_requires_a_name():
    api = t.ToyApi()
    assert api.handle("POST", "/api/v1/items", body={}).status == 400


def test_parse_curl_reads_method_headers_and_data():
    cmd = "curl -X POST -H 'Content-Type: application/json' -d '{\"name\":\"x\"}' http://127.0.0.1/api/v1/items"
    req = t.parse_curl(cmd)
    assert req.method == "POST"
    assert req.headers["Content-Type"] == "application/json"
    assert req.data == '{"name":"x"}'
    assert req.url.endswith("/api/v1/items")


def test_parse_curl_defaults_method_from_presence_of_data():
    assert t.parse_curl("curl http://127.0.0.1/x").method == "GET"
    assert t.parse_curl("curl -d 'a=1' http://127.0.0.1/x").method == "POST"


def test_build_curl_round_trips():
    req = t.CurlRequest("PUT", "http://127.0.0.1/api/v1/items/1",
                        {"Authorization": "Bearer FAKE-x-DEMO"}, '{"name":"y"}')
    cmd = t.build_curl(req)
    back = t.parse_curl(cmd)
    assert back.method == "PUT"
    assert back.headers["Authorization"] == "Bearer FAKE-x-DEMO"
    assert back.data == '{"name":"y"}'


def test_call_with_curl_drives_the_api():
    api = t.ToyApi()
    created = t.call_with_curl(api, "curl -X POST -d '{\"name\":\"z\"}' http://127.0.0.1/api/v1/items")
    assert created.status == 201
    got = t.call_with_curl(api, "curl http://127.0.0.1/api/v1/items/1")
    assert got.status == 200 and got.body["name"] == "z"


def test_non_curl_command_is_rejected():
    for bad in ["wget http://x", "", "curl"]:
        try:
            t.parse_curl(bad)
            raised = False
        except ValueError:
            raised = True
        assert raised
