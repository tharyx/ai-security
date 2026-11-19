"""Demo: scan a bad and a good Deployment."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import manifest_scan as m  # noqa: E402

for label, text in (("BAD", m.BAD), ("GOOD", m.GOOD)):
    f = m.scan(text)
    print(f"== {label}: {len(f)} failed checks, compliance {m.compliance_score(f)}%")
    for cid, res, where in f:
        print(f"   {cid} {m.CONTROLS[cid][1]:8} {m.CONTROLS[cid][0]:44} {res} ({where})")
print("supply-chain framework only (BAD):", sorted({c for c, _, _ in m.scan(m.BAD, 'supply-chain')}))
