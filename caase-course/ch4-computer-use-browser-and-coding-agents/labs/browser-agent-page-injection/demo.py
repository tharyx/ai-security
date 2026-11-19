"""Demo: the same agent on five pages, with and without defences (all simulated)."""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import browser_agent as b  # noqa: E402

DEFENDED = b.Defenses(visible_only=True, domain_allowlist=("blog.example",), no_autofill=True,
                      approval_actions=("grant-permissions", "download", "export"))
for name in ("benign", "hidden-text", "offscreen", "alt-text", "fake-allow-overlay"):
    html = (HERE / "fixtures" / f"{name}.html").read_text()
    for label, d in (("naive   ", b.Defenses()), ("defended", DEFENDED)):
        w = b.run(html, d)
        print(f"{name:20} {label} navigations={w.navigations} clicks={w.clicks} creds={len(w.credentials_sent)} grants={w.grants}")
