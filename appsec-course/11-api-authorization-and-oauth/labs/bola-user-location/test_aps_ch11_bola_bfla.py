import json

from aisec_lab import load_lab_module

la = load_lab_module(__file__, "location_api")


def _as(api, uid):
    return {"Authorization": f"Bearer {api.login(uid)}"}


def test_bola_attacker_enumerates_every_users_location_on_vulnerable_api():
    api = la.LocationAPI(secure=False)
    found = la.enumerate_locations(api, api.login(101), [1, 101, 102, 103])
    assert set(found) == {1, 101, 102, 103}
    assert found[102].startswith("28.61")  # bob's home location leaked


def test_bola_secure_api_returns_only_own_location_and_404_for_others():
    api = la.LocationAPI(secure=True)
    tok = api.login(101)
    assert set(la.enumerate_locations(api, tok, [1, 101, 102, 103])) == {101}
    status, _, _ = api.handle("GET", "/api/v1/users/102/location", {"Authorization": f"Bearer {tok}"})
    assert status == 404  # same as "does not exist": no ID probing


def test_admin_can_still_read_any_location_on_secure_api():
    api = la.LocationAPI(secure=True)
    assert api.handle("GET", "/api/v1/users/102/location", _as(api, 1))[0] == 200


def test_horizontal_escalation_reads_other_riders_trip_only_when_vulnerable():
    v, s = la.LocationAPI(False), la.LocationAPI(True)
    assert v.handle("GET", "/api/v1/trips/T-5002", _as(v, 101))[2]["fare"] == 610
    assert s.handle("GET", "/api/v1/trips/T-5002", _as(s, 101))[0] == 404


def test_vertical_escalation_via_role_field_only_when_vulnerable():
    v, s = la.LocationAPI(False), la.LocationAPI(True)
    body = json.dumps({"role": "admin", "name": "alice"})
    assert v.handle("PUT", "/api/v1/users/101", _as(v, 101), body)[2]["role"] == "admin"
    assert s.handle("PUT", "/api/v1/users/101", _as(s, 101), body)[2]["role"] == "rider"


def test_bfla_rider_deletes_user_only_when_vulnerable():
    v, s = la.LocationAPI(False), la.LocationAPI(True)
    assert v.handle("DELETE", "/api/v1/admin/users/102", _as(v, 101))[0] == 204 and 102 not in v.users
    assert s.handle("DELETE", "/api/v1/admin/users/102", _as(s, 101))[0] == 403 and 102 in s.users
    assert s.handle("DELETE", "/api/v1/admin/users/102", _as(s, 1))[0] == 204


def test_misconfigured_public_admin_route_leaks_and_audit_finds_it():
    v, s = la.LocationAPI(False), la.LocationAPI(True)
    assert v.handle("GET", "/api/v1/admin/export")[0] == 200
    assert s.handle("GET", "/api/v1/admin/export")[0] == 401
    issues = la.find_misconfigured_routes(la.ROUTES_VULN)
    assert len(issues) == 1 and "admin_export" in issues[0]
    assert la.find_misconfigured_routes(la.ROUTES_SECURE) == []


def test_no_token_is_401_everywhere_on_secure_api():
    s = la.LocationAPI(True)
    for method, path in (("GET", "/api/v1/users/101/location"), ("GET", "/api/v1/trips/T-5001")):
        assert s.handle(method, path)[0] == 401
