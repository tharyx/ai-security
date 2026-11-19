from aisec_lab import load_lab_module

g = load_lab_module(__file__, "graphql_lab")


def test_parser_handles_aliases_arguments_and_nesting():
    ast = g.parse('query Q { a: user(id: 2) { name friends { name } } me { id } }')
    assert ast[0]["alias"] == "a" and ast[0]["args"] == {"id": 2}
    assert g.depth(ast) == 3 and g.count_fields(ast) == 6


def test_introspection_leaks_hidden_admin_field_when_enabled():
    r = g.Server(False).execute("{ __schema }", 1)
    assert "adminResetAllPasswords" in r["data"]["__schema"]["Query"]
    assert g.Server(True).execute("{ __schema }", 1)["errors"] == ["introspection is disabled"]


def test_bola_in_resolver_leaks_other_users_ssn_only_when_vulnerable():
    q = "{ user(id: 3) { name ssn } }"
    assert g.Server(False).execute(q, 1)["data"]["user"]["ssn"] == "FAKE-SSN-333"
    assert g.Server(True).execute(q, 1)["data"]["user"] == {"error": "not authorized"}


def test_alias_batching_brute_forces_pin_in_one_http_request():
    s = g.Server(False)
    r = s.execute(g.alias_bruteforce_query("admin", [f"{i:02d}" for i in range(100)]), None)
    hits = [k for k, v in r["data"].items() if v["ok"]]
    assert hits == [f"p{g.PINS['admin']}"] and s.http_requests == 1


def test_hardened_server_rejects_multiple_login_aliases():
    r = g.Server(True).execute(g.alias_bruteforce_query("admin", ["00", "01"]), None)
    assert "errors" in r


def test_deep_query_explodes_resolver_calls_and_depth_limit_stops_it():
    v = g.Server(False)
    v.execute(g.deep_friends_query(12), 1)
    assert v.resolver_calls > 4000
    s = g.Server(True)
    r = s.execute(g.deep_friends_query(12), 1)
    assert "depth" in r["errors"][0] and s.resolver_calls == 0


def test_cost_limit_stops_wide_query_within_depth_limit():
    wide = "{ " + " ".join(f"u{i}: me {{ name }}" for i in range(30)) + " }"
    assert "cost" in g.Server(True, max_aliases=100).execute(wide, 1)["errors"][0]


def test_normal_query_still_works_on_hardened_server_and_hides_friend_ssn():
    r = g.Server(True).execute("{ me { name ssn friends { name ssn } } }", 1)
    assert r["data"]["me"]["ssn"] == "FAKE-SSN-111"
    assert all(f["ssn"] is None for f in r["data"]["me"]["friends"])
