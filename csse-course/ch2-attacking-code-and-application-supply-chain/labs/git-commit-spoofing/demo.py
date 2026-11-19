import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import spoof  # noqa: E402

if not spoof.git_available():
    sys.exit("git not found: install git to run this demo")
with spoof.make_workdir() as t:
    rows = spoof.run_scenario(Path(t))
print(f"{'subject':32} {'author':12} {'email':18} sig  trusted")
for r in rows:
    print(f"{r.subject:32} {r.author:12} {r.email:18} {r.sig_status:3}  {spoof.trusted(r)}")
print("sig: G=good, N=none, B=bad, U=valid signature, signer not trusted for this identity")
