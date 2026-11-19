"""A ride-hailing API with BOLA, BFLA, horizontal and vertical privilege escalation.

In-process only: handle(method, path, headers, body) -> (status, headers, body).
Session tokens are random values built at runtime and labelled FAKE.

DBA analogy: the vulnerable handlers run
    SELECT * FROM locations WHERE user_id = :id
and forget the second predicate
    AND (user_id = :me OR :me_is_admin = 1)
that a VPD policy would have added for you.
"""

from __future__ import annotations

import copy
import json
import re
import secrets

USERS_SEED = {
    1: {"id": 1, "name": "carol", "role": "admin", "location": "HQ, 12.9716,77.5946"},
    101: {"id": 101, "name": "alice", "role": "rider", "location": "12.9352,77.6245"},
    102: {"id": 102, "name": "bob", "role": "rider", "location": "28.6139,77.2090"},
    103: {"id": 103, "name": "dev", "role": "driver", "location": "19.0760,72.8777"},
}
TRIPS_SEED = {
    "T-5001": {"id": "T-5001", "rider_id": 101, "fare": 240},
    "T-5002": {"id": "T-5002", "rider_id": 102, "fare": 610},
}

# Route table: (method, regex, handler name, public?). A "misconfigured permission"
# is a route that is public, or protected by the wrong role, by mistake.
ROUTES_VULN = [
    ("GET", r"^/api/v1/users/(\d+)/location$", "get_location", False),
    ("GET", r"^/api/v1/trips/([\w-]+)$", "get_trip", False),
    ("PUT", r"^/api/v1/users/(\d+)$", "update_user", False),
    ("DELETE", r"^/api/v1/admin/users/(\d+)$", "admin_delete_user", False),
    ("GET", r"^/api/v1/admin/export$", "admin_export", True),  # copy-paste mistake: public
]
ROUTES_SECURE = [r[:3] + (False,) for r in ROUTES_VULN]
ADMIN_ONLY = {"admin_delete_user", "admin_export"}


def find_misconfigured_routes(routes) -> list[str]:
    """Audit: admin routes must never be public; every route must need a session."""
    issues = []
    for method, pattern, handler, public in routes:
        if public and (handler in ADMIN_ONLY or "/admin/" in pattern):
            issues.append(f"{method} {pattern} -> {handler} is PUBLIC but is an admin function")
        elif public:
            issues.append(f"{method} {pattern} -> {handler} is public; confirm this is intended")
    return issues


class LocationAPI:
    def __init__(self, secure: bool):
        self.secure = secure
        self.users = copy.deepcopy(USERS_SEED)
        self.trips = copy.deepcopy(TRIPS_SEED)
        self.sessions: dict[str, int] = {}
        self.routes = ROUTES_SECURE if secure else ROUTES_VULN

    # ---- helpers
    def login(self, user_id: int) -> str:
        token = "FAKE-session-" + secrets.token_hex(8)
        self.sessions[token] = user_id
        return token

    def _me(self, headers):
        auth = headers.get("Authorization", "")
        uid = self.sessions.get(auth.removeprefix("Bearer "))
        return self.users.get(uid) if uid else None

    def _deny(self, found: bool = True):
        # Secure version returns 404 for objects you may not see, so IDs cannot be probed.
        return (404, {}, {"error": "not found"}) if self.secure else (403, {}, {"error": "forbidden"})

    # ---- router
    def handle(self, method: str, path: str, headers: dict | None = None, body: str = ""):
        headers = headers or {}
        for m, pattern, name, public in self.routes:
            match = re.match(pattern, path)
            if m == method and match:
                me = self._me(headers)
                if me is None and not public:
                    return 401, {}, {"error": "login required"}
                if self.secure and name in ADMIN_ONLY and (me is None or me["role"] != "admin"):
                    return 403, {}, {"error": "admin only"}  # BFLA defence: function-level check
                data = json.loads(body) if body else {}
                return getattr(self, name)(me, match.group(1) if match.groups() else None, data)
        return 404, {}, {"error": "no route"}

    # ---- handlers
    def get_location(self, me, uid, _):
        user = self.users.get(int(uid))
        if user is None:
            return 404, {}, {"error": "not found"}
        if self.secure and not (user["id"] == me["id"] or me["role"] == "admin"):
            return self._deny()  # BOLA defence: object-level check
        return 200, {}, {"user_id": user["id"], "name": user["name"], "location": user["location"]}

    def get_trip(self, me, trip_id, _):
        trip = self.trips.get(trip_id)
        if trip is None:
            return 404, {}, {"error": "not found"}
        if self.secure and not (trip["rider_id"] == me["id"] or me["role"] == "admin"):
            return self._deny()
        return 200, {}, trip

    def update_user(self, me, uid, data):
        user = self.users.get(int(uid))
        if user is None:
            return 404, {}, {"error": "not found"}
        if self.secure:
            if user["id"] != me["id"]:
                return self._deny()
            allowed = {"name"}  # role can only change through an admin workflow
            data = {k: v for k, v in data.items() if k in allowed}
        user.update(data)
        return 200, {}, {"id": user["id"], "name": user["name"], "role": user["role"]}

    def admin_delete_user(self, me, uid, _):
        if self.users.pop(int(uid), None) is None:
            return 404, {}, {"error": "not found"}
        return 204, {}, {}

    def admin_export(self, me, _, __):
        return 200, {}, {"users": list(self.users.values())}


def enumerate_locations(api: LocationAPI, token: str, ids) -> dict[int, str]:
    """The attacker loop: walk predictable IDs and collect everyone's location."""
    found = {}
    for uid in ids:
        status, _, body = api.handle("GET", f"/api/v1/users/{uid}/location", {"Authorization": f"Bearer {token}"})
        if status == 200:
            found[uid] = body["location"]
    return found
