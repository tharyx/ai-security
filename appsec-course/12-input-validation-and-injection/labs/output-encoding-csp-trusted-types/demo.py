import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import xss_defenses as x  # noqa: E402

PAYLOADS = {"html": "<img src=x onerror=alert(1)>", "attribute": '" autofocus onfocus="alert(1)',
            "javascript": "';alert(1);//", "css": "red; background:url(//evil.example/x)"}

print("== Output encoding per context ==")
for ctx, p in PAYLOADS.items():
    raw, enc = x.render(ctx, p, False), x.render(ctx, p, True)
    print(f"[{ctx}] payload {p!r}")
    print(f"   raw     breaks out={x.breaks_out(ctx, raw)!s:<5} {raw}")
    print(f"   encoded breaks out={x.breaks_out(ctx, enc)!s:<5} {enc}")
print("[onclick handler] HTML-encoded value breaks out:", x.onclick_handler_breaks_out("');alert(1);//", x.html_encode),
      "| JS-encoded:", x.onclick_handler_breaks_out("');alert(1);//", x.js_string_encode))

print("\n== CSP evaluator ==")
weak = "default-src 'self'; script-src 'self' 'unsafe-inline' https://ajax.googleapis.com"
nonce = x.new_nonce()
strict = x.build_strict_csp(nonce)
for name, h in (("weak", weak), ("strict", strict)):
    print(f"{name}: {h}")
    for f in x.evaluate_csp(h) or ["no findings"]:
        print("   -", f)
injected = "<script>steal()</script>"
print("injected inline script runs under weak CSP?  ", x.browser_runs_inline_script(weak, injected))
print("injected inline script runs under strict CSP?", x.browser_runs_inline_script(strict, injected))
print("our own nonce'd script runs under strict CSP?", x.browser_runs_inline_script(strict, f'<script nonce="{nonce}">app()</script>'))

print("\n== Trusted Types (simulated DOM sink) ==")
evil = 'Hi <b>there</b><img src=x onerror="alert(1)">'
el = x.FakeElement(enforce_trusted_types=False)
el.innerHTML = evil
print("no TT: innerHTML =", el.innerHTML, "| script present:", x.element_has_script(el))
el = x.FakeElement(enforce_trusted_types=True)
try:
    el.innerHTML = evil
except TypeError as e:
    print("TT enforced, plain string ->", e)
policy = x.TrustedTypePolicy("sanitize", x.simple_sanitizer)
el.innerHTML = policy.createHTML(evil)
print("TT enforced, via policy ->", el.innerHTML, "| script present:", x.element_has_script(el))
