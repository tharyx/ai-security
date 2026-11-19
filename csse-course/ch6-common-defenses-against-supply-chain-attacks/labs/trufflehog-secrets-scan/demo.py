"""Demo: history scan with verification."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import truffle_lite as t  # noqa: E402

prov = t.FakeProvider(live={t.LIVE_KEY})
fs = t.scan_history(t.HISTORY, prov)
for f in fs:
    print(f"{f.status:10} {f.detector:6} {f.secret_preview:10} commit {f.commit} {f.file}")
print("only-verified:", [(f.commit, f.file) for f in t.scan_history(t.HISTORY, prov, only_verified=True)])
print("latest checkout alone sees:", t.current_tree_secrets(t.HISTORY))
print({k: len(v) for k, v in t.triage(fs).items()})
