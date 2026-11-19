from aisec_lab import load_lab_module

m = load_lab_module(__file__, "authz_models")


def test_no_authorization_lets_anyone_delete():
    assert m.no_authz("mallory", "delete", "doc:salaries") is True


def test_rbac_hierarchy_inherits_lower_role_permissions():
    assert m.rbac_allows({"admin"}, "doc:read")
    assert m.rbac_allows({"editor"}, "doc:write")
    assert not m.rbac_allows({"viewer"}, "doc:write")
    assert not m.rbac_allows({"editor"}, "user:manage")


def test_dac_only_owner_or_grant_option_can_grant():
    d = m.DacStore()
    d.create("carol", "doc:x")
    assert d.grant("bob", "doc:x", "bob", "read") is False
    assert not d.check("bob", "read", "doc:x")
    assert d.grant("carol", "doc:x", "alice", "read", with_grant_option=True)
    assert d.grant("alice", "doc:x", "bob", "read")  # privilege spreads: DAC weakness
    assert d.check("bob", "read", "doc:x")


def test_dac_non_owner_cannot_revoke():
    d = m.DacStore()
    d.create("carol", "doc:x")
    d.grant("carol", "doc:x", "bob", "read")
    assert d.revoke("bob", "doc:x", "bob", "read") is False
    assert d.revoke("carol", "doc:x", "bob", "read") and not d.check("bob", "read", "doc:x")


def test_abac_denies_cross_department_after_hours_and_low_clearance():
    eng = {"department": "eng", "clearance": 1, "roles": []}
    assert m.abac_allows(eng, "read", {"department": "eng", "classification": 1}, {"hour": 10})[0]
    assert m.abac_allows(eng, "read", {"department": "hr", "classification": 1}, {"hour": 10}) == (False, "different department")
    assert not m.abac_allows(eng, "write", {"department": "eng"}, {"hour": 22})[0]
    assert not m.abac_allows(eng, "read", {"department": "eng", "classification": 3}, {"hour": 10})[0]


def test_abac_auditor_role_crosses_departments_but_suspension_wins():
    aud = {"department": "audit", "clearance": 3, "roles": ["auditor"]}
    assert m.abac_allows(aud, "read", {"department": "hr", "classification": 2}, {"hour": 10})[0]
    aud["suspended"] = True
    assert not m.abac_allows(aud, "read", {"department": "hr"}, {"hour": 10})[0]


def test_rebac_group_and_parent_folder_inheritance():
    z = m.sample_rebac()
    assert z.check("doc:q3-plan", "viewer", "user:alice")  # eng member -> folder viewer -> doc viewer
    assert not z.check("doc:salaries", "viewer", "user:alice")
    assert z.check("doc:salaries", "viewer", "user:carol")  # owner implies editor implies viewer


def test_rebac_cycle_does_not_loop_forever():
    z = m.ReBAC()
    z.write("folder:a", "parent", "folder:b")
    z.write("folder:b", "parent", "folder:a")
    assert z.check("folder:a", "viewer", "user:x") is False
