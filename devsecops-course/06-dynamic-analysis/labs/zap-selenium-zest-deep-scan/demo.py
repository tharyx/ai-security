import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from aisec_lab import load_lab_module  # noqa: E402

here = Path(__file__).parent
_APP = str(here.parent / "dast-local-app" / "x.py")
app = load_lab_module(_APP, "vulnapp")
prober = load_lab_module(_APP, "prober")
qa = load_lab_module(__file__, "qaproxy")
scenario = json.loads((here / "fixtures" / "qa_steps.json").read_text())

with app.running(False) as srv:
    # BEFORE: a spider alone
    p0 = prober.Prober(srv.base)
    urls0 = sorted(p0.spider())
    f0 = p0.scan()
    cov0 = prober.Prober.coverage(urls0)

    # QA automation plays through a recording proxy
    proxy = qa.RecordingProxy().start()
    browser = qa.ScriptedBrowser(srv.base, proxy.port)
    results = browser.play(scenario)
    proxy.stop()
    print("QA run through the proxy:")
    for action, path, status in results:
        print(f"  {action:11} {path:32} -> {status}")

    # AFTER: the URLs the proxy saw, scanned with the session the browser obtained
    urls1 = [u.replace(srv.base, "") for u in proxy.urls()]
    p1 = prober.Prober(srv.base, browser.cookie_header())
    f1 = p1.scan(urls1)
    cov1 = prober.Prober.coverage(urls1)

    print(f"\nBEFORE (spider only)  : {len(urls0)} pages, {len(cov0)} testable parameters, {len(f0)} findings, "
          f"{len([f for f in f0 if f.severity == 'High'])} High")
    print(f"AFTER  (QA + session) : {len(urls1)} URLs,  {len(cov1)} testable parameters, {len(f1)} findings, "
          f"{len([f for f in f1 if f.severity == 'High'])} High")
    print("parameters reached only through QA automation:", sorted(cov1 - cov0))
    print("new finding types:", sorted({f.rule for f in f1} - {f.rule for f in f0}))
    z = qa.recording_to_zest(proxy.log[:2])
    print("\nZest-like recording (first 2 requests):")
    print(qa.dump(z))
