import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from aisec_lab import load_lab_module  # noqa: E402

here = Path(__file__).parent
app = load_lab_module(str(here.parent / "dast-local-app" / "x.py"), "vulnapp")
prober = load_lab_module(str(here.parent / "dast-local-app" / "x.py"), "prober")
zest = load_lab_module(__file__, "zest")

with app.running(False) as srv:
    print("== 1. Zest-like script: log in, keep token, assert logged in ==")
    script = json.loads((here / "fixtures" / "login.zest.json").read_text())
    res = zest.run_script(script, srv.base)
    for s in res.steps:
        print(f"  {'ok  ' if s.ok else 'FAIL'} {s.summary} {s.detail}")
    print("  variables:", {k: v for k, v in res.variables.items() if k in ("token", "notes_link")})

    print("\n== 2. Scan the authenticated page without and with the session ==")
    anon = prober.Prober(srv.base).scan(["/account/notes?q="])
    print("  anonymous  :", sorted({f.rule for f in anon if f.rule == "REFLECTED-XSS"}) or "no XSS seen (401 page)")
    hdr = {"Authorization": "Bearer " + res.variables["token"]}
    authed = prober.Prober(srv.base, hdr).scan(["/account/notes?q="])
    print("  with token :", sorted({f.rule for f in authed if f.rule == "REFLECTED-XSS"}))

    print("\n== 3. ZAP context files (form and header based) ==")
    env = {"APP_PASSWORD": "alice-demo-pass"}
    for name in ("context-form.yaml", "context-header.yaml"):
        ctx = zest.load_context(here / "fixtures" / name, srv.base)
        headers = zest.login_with_context(ctx, env)
        print(f"  {ctx['name']:9} method={ctx['authentication']['method']:5} logged in = {zest.is_logged_in(ctx, headers)}  header keys = {list(headers)}")
    bad = zest.load_context(here / "fixtures" / "context-form.yaml", srv.base)
    print("  wrong cookie is detected as logged out:", not zest.is_logged_in(bad, {"Cookie": "session=bogus"}))
