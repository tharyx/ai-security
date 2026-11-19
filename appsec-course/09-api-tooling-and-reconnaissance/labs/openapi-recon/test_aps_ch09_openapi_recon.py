from pathlib import Path

from aisec_lab import load_lab_module

r = load_lab_module(__file__, "openapi_recon")
SPEC = Path(__file__).resolve().parent / "fixtures" / "openapi.json"


def test_load_spec_accepts_openapi_3_and_rejects_others(tmp_path=None):
    spec = r.load_spec(SPEC)
    assert spec["openapi"].startswith("3.")


def test_lists_all_endpoints_with_security():
    eps = r.endpoints(r.load_spec(SPEC))
    paths = {(e.method, e.path) for e in eps}
    assert ("POST", "/api/v1/login") in paths
    assert ("GET", "/api/v1/admin/users") in paths
    admin = next(e for e in eps if e.path == "/api/v1/admin/users")
    assert admin.secured and "bearerAuth" in admin.security_schemes


def test_reads_declared_auth_schemes():
    schemes = r.auth_schemes(r.load_spec(SPEC))
    assert schemes["bearerAuth"] == "http/bearer"
    assert schemes["apiKey"] == "apiKey"


def test_public_endpoints_are_flagged():
    pub = {e.path for e in r.unauthenticated_endpoints(r.load_spec(SPEC))}
    assert "/api/v1/login" in pub
    assert "/api/v1/products" in pub
    assert "/api/v1/admin/users" not in pub


def test_recon_finds_shadow_and_zombie_endpoints():
    spec = r.load_spec(SPEC)
    # Live inventory: /products and /login still served, /orders gone,
    # and an undocumented debug endpoint is live.
    live = [
        ("POST", "/api/v1/login"),
        ("GET", "/api/v1/products"),
        ("GET", "/api/v1/admin/users"),
        ("GET", "/api/v1/debug/env"),       # shadow: not in spec
    ]
    rec = r.recon(spec, live)
    assert ("GET", "/api/v1/debug/env") in rec["shadow"]
    assert ("GET", "/api/v1/orders/{orderId}") in rec["zombie"]
    assert ("POST", "/api/v1/login") in rec["documented"]


def test_versioned_paths_detected():
    versions = r.versioned_paths(r.load_spec(SPEC))
    assert "v1" in versions


def test_rejects_swagger_2():
    import json
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump({"swagger": "2.0", "paths": {}}, f)
        name = f.name
    try:
        r.load_spec(name)
        raised = False
    except ValueError:
        raised = True
    assert raised


def test_report_mentions_shadow_and_zombie():
    spec = r.load_spec(SPEC)
    live = [("GET", "/api/v1/products"), ("GET", "/api/v1/debug/env")]
    out = r.report(spec, live)
    assert "Shadow" in out and "Zombie" in out
    assert "debug/env" in out
