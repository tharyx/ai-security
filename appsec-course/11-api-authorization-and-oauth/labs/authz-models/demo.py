import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import authz_models as m  # noqa: E402

print("== No authorization ==")
print("mallory may delete doc:salaries?", m.no_authz("mallory", "delete", "doc:salaries"))

print("\n== RBAC (roles and a role hierarchy) ==")
for roles in ({"viewer"}, {"editor"}, {"admin"}):
    print(sorted(roles), "->", sorted(m.rbac_permissions(roles)))

print("\n== DAC (owner grants, like GRANT ... WITH GRANT OPTION) ==")
d = m.DacStore()
d.create("carol", "doc:salaries")
print("bob grants himself read:", d.grant("bob", "doc:salaries", "bob", "read"))
print("carol grants alice read WITH GRANT OPTION:", d.grant("carol", "doc:salaries", "alice", "read", True))
print("alice re-grants read to bob:", d.grant("alice", "doc:salaries", "bob", "read"))
print("bob can read now?", d.check("bob", "read", "doc:salaries"), "(DAC weakness: the owner lost control)")

print("\n== ABAC (subject, resource, action, environment attributes) ==")
alice = {"department": "eng", "clearance": 2, "roles": ["engineer"]}
doc = {"department": "eng", "classification": 1}
hr_doc = {"department": "hr", "classification": 1}
print("alice read eng doc 10:00 ->", m.abac_allows(alice, "read", doc, {"hour": 10}))
print("alice read hr doc ->", m.abac_allows(alice, "read", hr_doc, {"hour": 10}))
print("alice write eng doc 23:00 ->", m.abac_allows(alice, "write", doc, {"hour": 23}))

print("\n== ReBAC (relationship tuples) ==")
z = m.sample_rebac()
for user, obj in (("user:alice", "doc:q3-plan"), ("user:alice", "doc:salaries"), ("user:carol", "doc:salaries")):
    print(f"{user} viewer of {obj}?", z.check(obj, "viewer", user))
