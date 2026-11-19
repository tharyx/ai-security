import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fakebrowser as fb  # noqa: E402

browser = fb.FakeBrowser()
for build in fb.CommentBoard.BUILDS:
    app = fb.CommentBoard(build)
    for p in fb.attacker_payloads():
        app.post(p)
    page, headers = app.render()
    res = browser.load(page, headers)
    print(f"== build={build}  CSP={headers or 'none'}")
    print(f"   executed: {res.executed}")
    print(f"   blocked : {len(res.blocked)} | reports sent: {len(res.reports)} | cookie stolen: {fb.stolen(res)}")

print("\nStatic nonce: the attacker read the nonce from an earlier page and reuses it")
app = fb.CommentBoard("static_nonce")
app.post('<script nonce="static123">steal(document.cookie)</script>')
page, headers = app.render()
print("   cookie stolen:", fb.stolen(browser.load(page, headers)))

print("\nHash-based CSP allows exactly one known inline script:")
h = fb.sha256_source(fb.APP_SCRIPT)
csp = {"Content-Security-Policy": f"script-src {h}; object-src 'none'; base-uri 'none'"}
page = f"<script>{fb.APP_SCRIPT}</script><script>steal(1)</script>"
r = browser.load(page, csp)
print("   policy:", csp["Content-Security-Policy"])
print("   executed:", r.executed, "| blocked:", r.blocked)
