import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import location_api as la  # noqa: E402

for secure in (False, True):
    api = la.LocationAPI(secure=secure)
    alice = api.login(101)
    h = {"Authorization": f"Bearer {alice}"}
    print(f"===== {'SECURE' if secure else 'VULNERABLE'} API, logged in as alice (id 101, rider) =====")
    print("1 BOLA  : enumerate /users/{id}/location for ids 1..103 ->",
          la.enumerate_locations(api, alice, [1, 101, 102, 103]))
    print("2 horiz : GET /trips/T-5002 (bob's trip) ->", api.handle("GET", "/api/v1/trips/T-5002", h)[0])
    s, _, b = api.handle("PUT", "/api/v1/users/101", h, json.dumps({"role": "admin"}))
    print("3 vert  : PUT /users/101 {role: admin} ->", s, b)
    print("4 BFLA  : DELETE /admin/users/102 ->", api.handle("DELETE", "/api/v1/admin/users/102", h)[0])
    print("5 misconf: GET /admin/export with NO token ->", api.handle("GET", "/api/v1/admin/export")[0])
    print("   route audit:", la.find_misconfigured_routes(api.routes) or "clean")
    print()
